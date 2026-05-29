using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Ashlar.Auditing;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.OAuth;

/// <summary>
/// Maps ASP.NET Core external identities to Ashlar assertions.
/// </summary>
public sealed class AshlarExternalCredentialAuthenticationService
{
    private readonly IPrimaryAuthenticationRateLimiter _primaryRateLimiter;
    private readonly ISecurityEventSink? _securityEventSink;
    private readonly IOptionsMonitor<AshlarOAuthOptions> _options;
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Initializes a new instance of the external credential authentication service.
    /// </summary>
    /// <param name="primaryRateLimiter">The provider-neutral primary authentication rate limiter.</param>
    /// <param name="options">The OAuth options monitor.</param>
    /// <param name="securityEventSink">The optional security event sink.</param>
    /// <param name="timeProvider">The optional time provider.</param>
    public AshlarExternalCredentialAuthenticationService(
        IPrimaryAuthenticationRateLimiter primaryRateLimiter,
        IOptionsMonitor<AshlarOAuthOptions> options,
        ISecurityEventSink? securityEventSink = null,
        TimeProvider? timeProvider = null)
    {
        _primaryRateLimiter = primaryRateLimiter ?? throw new ArgumentNullException(nameof(primaryRateLimiter));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _securityEventSink = securityEventSink;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Completes callback handling only up to a mapped Ashlar external identity assertion.
    /// </summary>
    /// <param name="httpContext">The current HTTP context.</param>
    /// <param name="providerName">The configured Ashlar provider name.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The external assertion completion result.</returns>
    /// <remarks>
    /// Use this method when the host application must pass the mapped assertion through its own authentication
    /// orchestration before issuing a session, such as when MFA policy is applied by <see cref="IAuthenticationOrchestrator"/>.
    /// A successful result means the external credential was validated and mapped; it does not mean an application
    /// session may be issued.
    /// </remarks>
    public async Task<AshlarExternalAssertionResult> CompleteExternalAssertionAsync(
        HttpContext httpContext,
        string providerName,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        var provider = AshlarExternalProviderResolver.GetProvider(_options.CurrentValue, providerName);
        if (provider == null)
        {
            var unsupportedProviderKey = CreateUnsupportedProviderKey(providerName);
            await AshlarExternalTicket.TryClearAsync(httpContext, _options.CurrentValue.ExternalSignInScheme, CancellationToken.None);
            return await CreateFailureResultAsync(
                CreateAuthenticationContext(httpContext, null),
                unsupportedProviderKey,
                AshlarExternalAssertionStatus.UnsupportedProvider,
                cancellationToken);
        }

        var providerKey = CreateProviderKey(provider, providerName);
        var context = CreateAuthenticationContext(httpContext, null);
        var result = await AshlarExternalTicket.AuthenticateAndClearAsync(httpContext, _options.CurrentValue.ExternalSignInScheme, cancellationToken);

        if (!result.Succeeded || result.Principal == null)
        {
            return await CreateFailureResultAsync(context, providerKey, AshlarExternalAssertionStatus.AuthenticationFailed, cancellationToken);
        }

        if (!AshlarExternalProviderResolver.MatchesProvider(result, provider))
        {
            return await CreateFailureResultAsync(context, providerKey, AshlarExternalAssertionStatus.ProviderMismatch, cancellationToken);
        }

        try
        {
            var assertion = AshlarExternalProviderResolver.MapAssertion(provider, result.Principal);
            return new AshlarExternalAssertionResult(AshlarExternalAssertionStatus.Succeeded, assertion);
        }
        catch (InvalidOperationException)
        {
            return await CreateFailureResultAsync(context, providerKey, AshlarExternalAssertionStatus.InvalidPrincipal, cancellationToken);
        }
        catch (ArgumentException)
        {
            return await CreateFailureResultAsync(context, providerKey, AshlarExternalAssertionStatus.InvalidPrincipal, cancellationToken);
        }
    }

    private static AuthenticationContext CreateAuthenticationContext(HttpContext httpContext, Guid? tenantId)
    {
        return new AuthenticationContext(
            TenantId: tenantId,
            IpAddress: httpContext.Connection.RemoteIpAddress?.ToString(),
            UserAgent: httpContext.Request.Headers.UserAgent.ToString(),
            CorrelationId: httpContext.TraceIdentifier);
    }

    private async Task<bool> ConsumeExternalFailureRateLimitAsync(
        AuthenticationContext context,
        AuthenticationProviderKey providerKey,
        CancellationToken cancellationToken)
    {
        var assertion = new ExternalCompletionAssertion(providerKey);
        var decision = await _primaryRateLimiter.CheckAsync(context, assertion, providerKey, cancellationToken);
        if (decision.Status != RateLimitStatus.Blocked)
        {
            return false;
        }

        await RecordRateLimitedAsync(context, providerKey, cancellationToken);
        return true;
    }

    private async Task<AshlarExternalAssertionResult> CreateFailureResultAsync(
        AuthenticationContext context,
        AuthenticationProviderKey providerKey,
        AshlarExternalAssertionStatus status,
        CancellationToken cancellationToken)
    {
        return await ConsumeExternalFailureRateLimitAsync(context, providerKey, cancellationToken)
            ? new AshlarExternalAssertionResult(AshlarExternalAssertionStatus.RateLimited)
            : new AshlarExternalAssertionResult(status);
    }

    private async Task RecordRateLimitedAsync(
        AuthenticationContext context,
        AuthenticationProviderKey providerKey,
        CancellationToken cancellationToken)
    {
        if (_securityEventSink == null)
        {
            return;
        }

        await _securityEventSink.RecordAsync(new AshlarSecurityEvent
        {
            Id = Guid.NewGuid(),
            EventType = AshlarSecurityEventTypes.AuthenticationRateLimited,
            OccurredAt = _timeProvider.GetUtcNow(),
            TenantId = context.TenantId,
            ActorUserId = context.UserId,
            Provider = providerKey,
            IpAddress = context.IpAddress,
            UserAgent = context.UserAgent,
            CorrelationId = context.CorrelationId,
            Outcome = SecurityEventOutcomes.Failure,
            FailureReason = SecurityEventFailureReasons.RateLimited
        }, cancellationToken);
    }

    private static AuthenticationProviderKey CreateUnsupportedProviderKey(string providerName)
    {
        var normalizedProviderName = string.IsNullOrWhiteSpace(providerName) ? "UNKNOWN" : providerName.Trim();
        return new AuthenticationProviderKey((ProviderType)"EXTERNAL_UNSUPPORTED", normalizedProviderName);
    }

    private static AuthenticationProviderKey CreateProviderKey(AshlarExternalProvider provider, string requestedProviderName)
    {
        var normalizedProviderName = string.IsNullOrWhiteSpace(provider.ProviderName)
            ? requestedProviderName.Trim()
            : provider.ProviderName;
        return new AuthenticationProviderKey(provider.Type, normalizedProviderName);
    }

    private sealed class ExternalCompletionAssertion(AuthenticationProviderKey providerIdentity) : IAuthenticationAssertion
    {
        public AuthenticationProviderKey ProviderIdentity { get; } = providerIdentity;
    }
}
