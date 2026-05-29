using Ashlar.Auditing;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Ashlar.Identity.Features.Authentication;

/// <summary>
/// Provides authentication pipeline behavior.
/// </summary>
/// <param name="providerRegistry">The provider registry value.</param>
/// <param name="credentialService">The credential service value.</param>
/// <param name="transactionProvider">The transaction provider value.</param>
/// <param name="primaryRateLimiter">The provider-neutral primary authentication rate limiter.</param>
/// <param name="factorRateLimiter">The provider-neutral secondary factor verification rate limiter.</param>
/// <param name="dependencies">Optional operational dependencies used by the pipeline.</param>
/// <remarks>
/// Pass both log members in <paramref name="dependencies" /> when constructing this pipeline manually and operational
/// logging is desired for both authentication lifecycle operations and security event sink failures.
/// </remarks>
public sealed class AuthenticationPipeline(
    IAuthenticationProviderRegistry providerRegistry,
    ICredentialService credentialService,
    IAshlarTransactionProvider transactionProvider,
    IPrimaryAuthenticationRateLimiter primaryRateLimiter,
    IAuthenticationFactorRateLimiter factorRateLimiter,
    AuthenticationPipelineDependencies? dependencies = null)
    : IAuthenticationPipeline, IAuthenticationFactorPipeline
{
    private static readonly Action<ILogger, Guid, Guid?, string, string, Exception?> CredentialLifecycleUpdateFailed =
        LoggerMessage.Define<Guid, Guid?, string, string>(
            LogLevel.Warning,
            new EventId(1000, nameof(CredentialLifecycleUpdateFailed)),
            "Non-critical credential lifecycle update failed during authentication. UserId={UserId} CredentialId={CredentialId} ProviderType={ProviderType} ProviderName={ProviderName}");

    private static readonly Action<ILogger, Guid, Guid, string, string, Exception?> CriticalCredentialLifecycleUpdateFailed =
        LoggerMessage.Define<Guid, Guid, string, string>(
            LogLevel.Error,
            new EventId(1001, nameof(CriticalCredentialLifecycleUpdateFailed)),
            "Critical credential lifecycle update failed during authentication. UserId={UserId} CredentialId={CredentialId} ProviderType={ProviderType} ProviderName={ProviderName}");

    private static readonly Action<ILogger, string, string, Exception?> RateLimiterCheckFailed =
        LoggerMessage.Define<string, string>(
            LogLevel.Error,
            new EventId(1002, nameof(RateLimiterCheckFailed)),
            "Authentication rate limiter check failed. Scope={Scope} Provider={Provider}");

    private readonly IAuthenticationProviderRegistry _providerRegistry = providerRegistry ?? throw new ArgumentNullException(nameof(providerRegistry));
    private readonly ICredentialService _credentialService = credentialService ?? throw new ArgumentNullException(nameof(credentialService));
    private readonly IAshlarTransactionProvider _transactionProvider = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
    private readonly IPrimaryAuthenticationRateLimiter _primaryRateLimiter = primaryRateLimiter ?? throw new ArgumentNullException(nameof(primaryRateLimiter));
    private readonly IAuthenticationFactorRateLimiter _factorRateLimiter = factorRateLimiter ?? throw new ArgumentNullException(nameof(factorRateLimiter));
    private readonly SecurityEventEmitter _securityEvents = new(dependencies?.SecurityEventSink, dependencies?.TimeProvider ?? TimeProvider.System, dependencies?.LoggerFactory);
    private readonly ILogger<AuthenticationPipeline> _logger = dependencies?.Logger ?? NullLogger<AuthenticationPipeline>.Instance;

    /// <summary>
    /// Performs primary sign-in authentication and returns the result.
    /// </summary>
    /// <param name="context">The context value.</param>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public Task<AuthenticationResponse> LoginAsync(
        AuthenticationContext context,
        IAuthenticationAssertion assertion,
        CancellationToken cancellationToken = default)
    {
        return ExecutePrimaryAsync(context, assertion, cancellationToken);
    }

    /// <summary>
    /// Verifies a secondary factor without applying primary sign-in throttles.
    /// </summary>
    /// <param name="context">The context value.</param>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public Task<AuthenticationResponse> VerifyFactorAsync(
        AuthenticationContext context,
        IAuthenticationAssertion assertion,
        CancellationToken cancellationToken = default)
    {
        return ExecuteFactorAsync(context, assertion, cancellationToken);
    }

    private async Task<AuthenticationResponse> ExecutePrimaryAsync(
        AuthenticationContext context,
        IAuthenticationAssertion assertion,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(assertion);

        if (!_providerRegistry.TryGetProvider(assertion, out var provider))
        {
            if (!await CheckPrimaryRateLimitAsync(context, assertion, assertion.ProviderIdentity, cancellationToken))
            {
                return await RecordRateLimitedAsync(context, assertion.ProviderIdentity, cancellationToken);
            }

            return await RecordFailureAsync(context, assertion.ProviderIdentity, null, SecurityEventFailureReasons.ProviderUnsupported, cancellationToken);
        }

        if (!await CheckPrimaryRateLimitAsync(context, assertion, provider.Key, cancellationToken))
        {
            return await RecordRateLimitedAsync(context, provider.Key, cancellationToken);
        }

        if (!AuthenticationProviderCapabilities.IsPrimary(provider))
        {
            return await RecordFailureAsync(context, provider.Key, null, SecurityEventFailureReasons.InvalidCredentials, cancellationToken);
        }

        return await ExecuteProviderAsync(context, assertion, provider, cancellationToken);
    }

    private async Task<AuthenticationResponse> ExecuteFactorAsync(
        AuthenticationContext context,
        IAuthenticationAssertion assertion,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(assertion);

        if (!context.UserId.HasValue)
        {
            return await RecordFailureAsync(context, assertion.ProviderIdentity, null, SecurityEventFailureReasons.InvalidCredentials, cancellationToken);
        }

        if (!_providerRegistry.TryGetProvider(assertion, out var provider))
        {
            if (!await CheckFactorRateLimitAsync(context, assertion.ProviderIdentity, cancellationToken))
            {
                return await RecordRateLimitedAsync(context, assertion.ProviderIdentity, cancellationToken);
            }

            return await RecordFailureAsync(context, assertion.ProviderIdentity, context.UserId, SecurityEventFailureReasons.ProviderUnsupported, cancellationToken);
        }

        if (!await CheckFactorRateLimitAsync(context, provider.Key, cancellationToken))
        {
            return await RecordRateLimitedAsync(context, provider.Key, cancellationToken);
        }

        if (provider is not ISecondaryAuthenticationFactorProvider)
        {
            return await RecordFailureAsync(context, provider.Key, context.UserId, SecurityEventFailureReasons.InvalidCredentials, cancellationToken);
        }

        return await ExecuteProviderAsync(context, assertion, provider, cancellationToken);
    }

    private async Task<AuthenticationResponse> ExecuteProviderAsync(
        AuthenticationContext context,
        IAuthenticationAssertion assertion,
        IAuthenticationProvider provider,
        CancellationToken cancellationToken)
    {
        var (user, credential, originalCredential, unprotectFailed) = await _credentialService.ResolveAsync(context, assertion, provider, cancellationToken);
        if (unprotectFailed)
        {
            return await RecordFailureAsync(context, provider.Key, user?.Id, SecurityEventFailureReasons.UnprotectFailed, cancellationToken);
        }

        var result = await provider.AuthenticateAsync(assertion, credential, cancellationToken);
        if (result.Status is not (AuthenticationResultStatus.Succeeded or AuthenticationResultStatus.SucceededWithCredentialUpdate or AuthenticationResultStatus.MfaRequired) || user == null)
        {
            return await RecordFailureAsync(context, provider.Key, user?.Id, SecurityEventFailureReasons.InvalidCredentials, cancellationToken);
        }

        if (!user.IsActive)
        {
            return await RecordFailureAsync(context, provider.Key, user.Id, SecurityEventFailureReasons.UserDisabled, cancellationToken, user, AuthenticationStatus.Disabled);
        }

        if (result.Status == AuthenticationResultStatus.MfaRequired)
        {
            return new AuthenticationResponse(false, user, AuthenticationStatus.MfaRequired, result.Claims);
        }

        var status = result.Status == AuthenticationResultStatus.SucceededWithCredentialUpdate ? AuthenticationStatus.SuccessWithCredentialUpdate : AuthenticationStatus.Success;

        return await ProcessCredentialLifecycleAsync(
            new CredentialLifecycleContext(user, credential, originalCredential, result, provider, context, status),
            cancellationToken);
    }

    private async Task<bool> CheckPrimaryRateLimitAsync(
        AuthenticationContext context,
        IAuthenticationAssertion assertion,
        AuthenticationProviderKey providerKey,
        CancellationToken cancellationToken)
    {
        try
        {
            var decision = await _primaryRateLimiter.CheckAsync(context, assertion, providerKey, cancellationToken);
            return decision.Status != RateLimitStatus.Blocked;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            RateLimiterCheckFailed(_logger, "primary", providerKey.ToString(), ex);
            return true;
        }
    }

    private async Task<bool> CheckFactorRateLimitAsync(
        AuthenticationContext context,
        AuthenticationProviderKey providerKey,
        CancellationToken cancellationToken)
    {
        try
        {
            var decision = await _factorRateLimiter.CheckAsync(context, providerKey, cancellationToken);
            return decision.Status != RateLimitStatus.Blocked;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            RateLimiterCheckFailed(_logger, "factor", providerKey.ToString(), ex);
            return true;
        }
    }

    private async Task<AuthenticationResponse> RecordRateLimitedAsync(
        AuthenticationContext context,
        AuthenticationProviderKey providerKey,
        CancellationToken cancellationToken)
    {
        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.AuthenticationRateLimited,
            Outcome = SecurityEventOutcomes.Failure,
            UserId = context.UserId,
            Provider = providerKey,
            Context = context,
            FailureReason = SecurityEventFailureReasons.RateLimited
        }, cancellationToken);

        return new AuthenticationResponse(false, Status: AuthenticationStatus.RateLimited);
    }

    private async Task<AuthenticationResponse> ProcessCredentialLifecycleAsync(
        CredentialLifecycleContext lifecycle,
        CancellationToken cancellationToken)
    {
        if (lifecycle.Credential == null)
        {
            if (lifecycle.Result.IsCredentialConsumed || lifecycle.Result.CredentialUpdateRequirement == CredentialUpdateRequirement.Required)
            {
                return await RecordFailureAsync(lifecycle.Context, lifecycle.Provider.Key, lifecycle.User.Id, SecurityEventFailureReasons.CredentialUpdateFailed, cancellationToken);
            }

            return await CompleteSuccessfulLoginAsync(lifecycle.User, lifecycle.Provider, lifecycle.Context, lifecycle.Status, lifecycle.Result.Claims, properties: null, cancellationToken);
        }

        var lifecycleUpdateFailed = false;
        try
        {
            var credentialUsageUpdated = await _credentialService.UpdateCredentialUsageAsync(
                lifecycle.Credential,
                lifecycle.OriginalCredential,
                lifecycle.Result,
                lifecycle.Provider,
                cancellationToken);
            if (!credentialUsageUpdated)
            {
                return await RecordFailureAsync(lifecycle.Context, lifecycle.Provider.Key, lifecycle.User.Id, SecurityEventFailureReasons.CredentialUpdateFailed, cancellationToken);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Fail authentication if a critical lifecycle operation (Consume or Required Update) threw an uncaught exception.
            if (lifecycle.Result.IsCredentialConsumed || lifecycle.Result.CredentialUpdateRequirement == CredentialUpdateRequirement.Required)
            {
                CriticalCredentialLifecycleUpdateFailed(
                    _logger,
                    lifecycle.User.Id,
                    lifecycle.Credential.Id,
                    lifecycle.Provider.Key.Type.ValueOrUnknown,
                    lifecycle.Provider.Key.Name,
                    ex);
                return await RecordFailureAsync(lifecycle.Context, lifecycle.Provider.Key, lifecycle.User.Id, SecurityEventFailureReasons.CredentialUpdateFailed, cancellationToken);
            }

            lifecycleUpdateFailed = true;
            CredentialLifecycleUpdateFailed(
                _logger,
                lifecycle.User.Id,
                lifecycle.Credential.Id,
                lifecycle.Provider.Key.Type.ValueOrUnknown,
                lifecycle.Provider.Key.Name,
                ex);
        }

        return await CompleteSuccessfulLoginAsync(
            lifecycle.User,
            lifecycle.Provider,
            lifecycle.Context,
            lifecycle.Status,
            lifecycle.Result.Claims,
            lifecycleUpdateFailed ? new Dictionary<string, string> { ["lifecycle_update_failed"] = "true" } : null,
            cancellationToken);
    }

    private async Task<AuthenticationResponse> RecordFailureAsync(
        AuthenticationContext context,
        AuthenticationProviderKey providerKey,
        Guid? userId,
        string reason,
        CancellationToken cancellationToken,
        IUser? returnedUser = null,
        AuthenticationStatus returnedStatus = AuthenticationStatus.Failed)
    {
        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.AuthenticationFailed,
            Outcome = SecurityEventOutcomes.Failure,
            UserId = userId,
            Provider = providerKey,
            Context = context,
            FailureReason = reason
        }, cancellationToken);

        return new AuthenticationResponse(false, returnedUser, returnedStatus);
    }

    private async Task<AuthenticationResponse> CompleteSuccessfulLoginAsync(
        IUser user,
        IAuthenticationProvider provider,
        AuthenticationContext context,
        AuthenticationStatus status,
        IReadOnlyDictionary<string, IReadOnlyList<string>>? claims,
        Dictionary<string, string>? properties,
        CancellationToken cancellationToken)
    {
        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);
        transaction.OnCommitted(ct => _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.AuthenticationSucceeded,
            Outcome = SecurityEventOutcomes.Success,
            UserId = user.Id,
            Provider = provider.Key,
            Context = context,
            Properties = properties
        }, ct));

        await transaction.CommitAsync(cancellationToken);
        return new AuthenticationResponse(true, user, status, claims);
    }

    private sealed record CredentialLifecycleContext(
        IUser User,
        UserCredential? Credential,
        UserCredential? OriginalCredential,
        AuthenticationResult Result,
        IAuthenticationProvider Provider,
        AuthenticationContext Context,
        AuthenticationStatus Status);
}

/// <summary>
/// Optional operational dependencies for <see cref="AuthenticationPipeline" />.
/// </summary>
/// <param name="SecurityEventSink">The optional security event sink.</param>
/// <param name="TimeProvider">The optional clock.</param>
/// <param name="Logger">The optional operational <paramref name="Logger" />.</param>
/// <param name="LoggerFactory">The optional <paramref name="LoggerFactory" /> used by the security event emitter.</param>
public sealed record AuthenticationPipelineDependencies(
    ISecurityEventSink? SecurityEventSink = null,
    TimeProvider? TimeProvider = null,
    ILogger<AuthenticationPipeline>? Logger = null,
    ILoggerFactory? LoggerFactory = null);
