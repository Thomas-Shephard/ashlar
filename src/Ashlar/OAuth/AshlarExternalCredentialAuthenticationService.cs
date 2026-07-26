using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Ashlar.Auditing;
using Ashlar.Identity.Providers.External;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.OAuth;

/// <summary>
/// Authenticates ASP.NET Core external identities through Ashlar.
/// </summary>
/// <param name="primaryRateLimiter">The provider-neutral primary authentication rate limiter.</param>
/// <param name="options">The OAuth options monitor.</param>
/// <param name="authenticationOrchestrator">The Ashlar authentication orchestrator.</param>
/// <param name="securityEventSink">The optional security event sink.</param>
/// <param name="timeProvider">The optional time provider.</param>
/// <remarks>
/// Initializes a new instance of the external credential authentication service.
/// </remarks>
public sealed class AshlarExternalCredentialAuthenticationService(
    IPrimaryAuthenticationRateLimiter primaryRateLimiter,
    IOptionsMonitor<AshlarOAuthOptions> options,
    IAuthenticationOrchestrator authenticationOrchestrator,
    ISecurityEventSink? securityEventSink = null,
    TimeProvider? timeProvider = null)
{
    private const string UnsupportedProviderNameFallback = "unsupported";
    private readonly IPrimaryAuthenticationRateLimiter _primaryRateLimiter = primaryRateLimiter ?? throw new ArgumentNullException(nameof(primaryRateLimiter));
    private readonly ISecurityEventSink? _securityEventSink = securityEventSink;
    private readonly IOptionsMonitor<AshlarOAuthOptions> _options = options ?? throw new ArgumentNullException(nameof(options));
    private readonly IAuthenticationOrchestrator _authenticationOrchestrator = authenticationOrchestrator ?? throw new ArgumentNullException(nameof(authenticationOrchestrator));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    /// <summary>
    /// Completes external callback authentication through Ashlar's MFA-aware orchestration.
    /// </summary>
    /// <param name="httpContext">The current HTTP context.</param>
    /// <param name="providerName">The configured Ashlar provider name.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The MFA-aware external authentication result, or a failure status when the ticket is absent, invalid, mismatched, or rate limited.</returns>
    /// <remarks>
    /// The ASP.NET Core external authentication middleware must have already validated the remote provider response
    /// and written the temporary external ticket. This method authenticates that ticket, verifies that it was issued
    /// for the configured Ashlar provider, clears it, maps only stable provider key data, and runs Ashlar's
    /// authentication orchestration. Issue an application session only when the nested MFA result is successful.
    /// </remarks>
    public async Task<AshlarExternalAuthenticationResult> CompleteExternalAuthenticationAsync(
        HttpContext httpContext,
        string providerName,
        CancellationToken cancellationToken = default)
    {
        var result = await CompleteExternalTicketAsync(httpContext, providerName, cancellationToken);
        if (result.Assertion is not { } assertion)
        {
            return new AshlarExternalAuthenticationResult(result.Status);
        }

        var authentication = await _authenticationOrchestrator.AuthenticateAsync(
            CreateAuthenticationContext(httpContext, null),
            assertion,
            cancellationToken: cancellationToken);
        var status = authentication.Status switch
        {
            MfaAuthenticationStatus.Succeeded or MfaAuthenticationStatus.MfaRequired => AshlarExternalAuthenticationStatus.Succeeded,
            MfaAuthenticationStatus.RateLimited => AshlarExternalAuthenticationStatus.RateLimited,
            _ => AshlarExternalAuthenticationStatus.AuthenticationFailed
        };
        return new AshlarExternalAuthenticationResult(status, authentication);
    }

    private async Task<ExternalTicketCompletion> CompleteExternalTicketAsync(
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
                AshlarExternalAuthenticationStatus.UnsupportedProvider,
                cancellationToken);
        }

        var providerKey = CreateProviderKey(provider, providerName);
        var context = CreateAuthenticationContext(httpContext, null);
        var result = await AshlarExternalTicket.AuthenticateAndClearAsync(httpContext, _options.CurrentValue.ExternalSignInScheme, cancellationToken);

        if (!result.Succeeded || result.Principal == null)
        {
            return await CreateFailureResultAsync(context, providerKey, AshlarExternalAuthenticationStatus.AuthenticationFailed, cancellationToken);
        }

        if (!AshlarExternalProviderResolver.MatchesProvider(result, provider))
        {
            return await CreateFailureResultAsync(context, providerKey, AshlarExternalAuthenticationStatus.ProviderMismatch, cancellationToken);
        }

        if (AshlarExternalProviderResolver.TryMapAssertion(provider, result.Principal, out var assertion))
        {
            return new ExternalTicketCompletion(AshlarExternalAuthenticationStatus.Succeeded, assertion);
        }

        return await CreateFailureResultAsync(context, providerKey, AshlarExternalAuthenticationStatus.InvalidPrincipal, cancellationToken);
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

    private async Task<ExternalTicketCompletion> CreateFailureResultAsync(
        AuthenticationContext context,
        AuthenticationProviderKey providerKey,
        AshlarExternalAuthenticationStatus status,
        CancellationToken cancellationToken)
    {
        return await ConsumeExternalFailureRateLimitAsync(context, providerKey, cancellationToken)
            ? new ExternalTicketCompletion(AshlarExternalAuthenticationStatus.RateLimited)
            : new ExternalTicketCompletion(status);
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
        var normalizedProviderName = string.IsNullOrWhiteSpace(providerName) ? UnsupportedProviderNameFallback : providerName.Trim();
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

    private sealed record ExternalTicketCompletion(
        AshlarExternalAuthenticationStatus Status,
        ExternalIdentityAssertion? Assertion = null);
}
