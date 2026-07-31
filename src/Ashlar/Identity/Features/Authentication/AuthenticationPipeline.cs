using Ashlar.Auditing;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Ashlar.Identity.Features.Authentication;

internal sealed class AuthenticationPipeline(
    IAuthenticationProviderRegistry providerRegistry,
    ICredentialService credentialService,
    AshlarDurableTransactionProvider transactionProvider,
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

    private static readonly Action<ILogger, string, string, bool, Exception?> RateLimiterCheckFailed =
        LoggerMessage.Define<string, string, bool>(
            LogLevel.Error,
            new EventId(1002, nameof(RateLimiterCheckFailed)),
            "Authentication rate limiter backend failed. Scope={Scope} Provider={Provider} FailOpen={FailOpen}");

    private static readonly Action<ILogger, string, Guid, string, bool, Exception?> AccountLockoutOperationFailed =
        LoggerMessage.Define<string, Guid, string, bool>(
            LogLevel.Error,
            new EventId(1003, nameof(AccountLockoutOperationFailed)),
            "Account lockout backend failed during local password authentication. Operation={Operation} UserId={UserId} Provider={Provider} FailOpen={FailOpen}");

    private readonly IAuthenticationProviderRegistry _providerRegistry = providerRegistry ?? throw new ArgumentNullException(nameof(providerRegistry));
    private readonly ICredentialService _credentialService = credentialService ?? throw new ArgumentNullException(nameof(credentialService));
    private readonly AshlarDurableTransactionProvider _transactionProvider = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
    private readonly IPrimaryAuthenticationRateLimiter _primaryRateLimiter = primaryRateLimiter ?? throw new ArgumentNullException(nameof(primaryRateLimiter));
    private readonly IAuthenticationFactorRateLimiter _factorRateLimiter = factorRateLimiter ?? throw new ArgumentNullException(nameof(factorRateLimiter));
    private readonly IAccountLockoutService? _accountLockoutService = dependencies?.AccountLockoutService;
    private readonly bool _primaryRateLimiterFailOpen = dependencies?.PrimaryRateLimitOptions?.FailOpenOnBackendFailure ?? false;
    private readonly bool _factorRateLimiterFailOpen = dependencies?.FactorRateLimitOptions?.FailOpenOnBackendFailure ?? false;
    private readonly bool _accountLockoutFailOpen = dependencies?.AccountLockoutOptions?.FailOpenOnBackendFailure ?? false;
    private readonly SecurityEventEmitter _securityEvents = new(dependencies?.SecurityEventSink, dependencies?.TimeProvider ?? TimeProvider.System);
    private readonly ILogger<AuthenticationPipeline> _logger = dependencies?.Logger ?? NullLogger<AuthenticationPipeline>.Instance;
    private readonly TimeProvider _timeProvider = dependencies?.TimeProvider ?? TimeProvider.System;

    public Task<AuthenticationResponse> LoginAsync(
        AuthenticationContext context,
        IAuthenticationAssertion assertion,
        CancellationToken cancellationToken = default)
    {
        return ExecutePrimaryAsync(context, assertion, cancellationToken);
    }

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

        return await ExecuteProviderAsync(context, assertion, provider, isFactor: false, cancellationToken);
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

        // Assertions that opt into this contract require actual user verification for factor use.
        if (assertion is IUserVerifiedAuthenticationAssertion { UserVerified: false })
        {
            return await RecordFailureAsync(context, provider.Key, context.UserId, SecurityEventFailureReasons.InvalidCredentials, cancellationToken);
        }

        return await ExecuteProviderAsync(context, assertion, provider, isFactor: true, cancellationToken);
    }

    private async Task<AuthenticationResponse> ExecuteProviderAsync(
        AuthenticationContext context,
        IAuthenticationAssertion assertion,
        IAuthenticationProvider provider,
        bool isFactor,
        CancellationToken cancellationToken)
    {
        var (user, credential, originalCredential, unprotectFailed) = await _credentialService.ResolveAsync(context, assertion, provider, cancellationToken);
        if (unprotectFailed)
        {
            return await RecordFailureAsync(context, provider.Key, user?.Id, SecurityEventFailureReasons.UnprotectFailed, cancellationToken);
        }

        var shouldApplyAccountLockout = ShouldApplyAccountLockout(provider, user);
        var lockoutResponse = await BlockIfAccountLockoutAppliesAsync(shouldApplyAccountLockout, user, provider.Key, context, cancellationToken);
        if (lockoutResponse != null)
        {
            return lockoutResponse;
        }

        var result = await provider.AuthenticateAsync(assertion, credential, cancellationToken);
        if (result.Status is not (AuthenticationResultStatus.Succeeded or AuthenticationResultStatus.SucceededWithCredentialUpdate or AuthenticationResultStatus.MfaRequired) || user == null)
        {
            return await RecordProviderFailureAsync(shouldApplyAccountLockout, user, provider.Key, context, cancellationToken);
        }

        if (!user.CanSignIn())
        {
            return await RecordFailureAsync(context, provider.Key, user.Id, user.AccountState.ToSecurityFailureReason(), cancellationToken, user, AuthenticationStatus.Disabled);
        }

        if (result.Status == AuthenticationResultStatus.MfaRequired)
        {
            await ResetAccountLockoutIfApplicableAsync(shouldApplyAccountLockout, user, provider.Key, context, cancellationToken);

            return new AuthenticationResponse(user, AuthenticationStatus.MfaRequired, result.Claims);
        }

        var status = result.Status == AuthenticationResultStatus.SucceededWithCredentialUpdate ? AuthenticationStatus.SuccessWithCredentialUpdate : AuthenticationStatus.Success;

        await ResetAccountLockoutIfApplicableAsync(shouldApplyAccountLockout, user, provider.Key, context, cancellationToken);

        return await ProcessCredentialLifecycleAsync(
            new CredentialLifecycleContext(user, credential, originalCredential, result, provider, context, status, isFactor),
            cancellationToken);
    }

    private async Task<AuthenticationResponse?> BlockIfAccountLockoutAppliesAsync(
        bool shouldApplyAccountLockout,
        IUser? user,
        AuthenticationProviderKey providerKey,
        AuthenticationContext context,
        CancellationToken cancellationToken)
    {
        if (!shouldApplyAccountLockout)
        {
            return null;
        }

        var lockoutStatus = await CheckAccountLockoutAsync(user!, providerKey, context, cancellationToken);
        return lockoutStatus switch
        {
            AccountLockoutAuthenticationStatus.BackendFailure => await RecordRateLimitedAsync(context, providerKey, cancellationToken),
            AccountLockoutAuthenticationStatus.LockedOut => await RecordFailureAsync(context, providerKey, user!.Id, SecurityEventFailureReasons.AutomaticAccountLockout, cancellationToken),
            _ => null
        };
    }

    private async Task<AuthenticationResponse> RecordProviderFailureAsync(
        bool shouldApplyAccountLockout,
        IUser? user,
        AuthenticationProviderKey providerKey,
        AuthenticationContext context,
        CancellationToken cancellationToken)
    {
        var reason = SecurityEventFailureReasons.InvalidCredentials;
        if (shouldApplyAccountLockout)
        {
            var lockoutFailureStatus = await RecordAccountLockoutFailureAsync(user!, providerKey, context, cancellationToken);
            if (lockoutFailureStatus == AccountLockoutAuthenticationStatus.BackendFailure)
            {
                return await RecordRateLimitedAsync(context, providerKey, cancellationToken);
            }

            if (lockoutFailureStatus == AccountLockoutAuthenticationStatus.LockedOut)
            {
                reason = SecurityEventFailureReasons.AutomaticAccountLockout;
            }
        }

        return await RecordFailureAsync(context, providerKey, user?.Id, reason, cancellationToken);
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
            RateLimiterCheckFailed(_logger, "primary", providerKey.ToString(), _primaryRateLimiterFailOpen, ex);
            return _primaryRateLimiterFailOpen;
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
            RateLimiterCheckFailed(_logger, "factor", providerKey.ToString(), _factorRateLimiterFailOpen, ex);
            return _factorRateLimiterFailOpen;
        }
    }

    private static bool ShouldApplyAccountLockout(IAuthenticationProvider provider, IUser? user)
    {
        return provider.Key == AuthenticationProviderKey.Local && user?.CanSignIn() == true;
    }

    private async Task<AccountLockoutAuthenticationStatus> CheckAccountLockoutAsync(
        IUser user,
        AuthenticationProviderKey providerKey,
        AuthenticationContext context,
        CancellationToken cancellationToken)
    {
        if (_accountLockoutService == null)
        {
            return AccountLockoutAuthenticationStatus.Allowed;
        }

        try
        {
            var status = await _accountLockoutService.GetStatusAsync(user, providerKey, CreateAccountLockoutContext(context), cancellationToken);
            return status.IsLockedOut
                ? AccountLockoutAuthenticationStatus.LockedOut
                : AccountLockoutAuthenticationStatus.Allowed;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            AccountLockoutOperationFailed(_logger, "get_status", user.Id, providerKey.ToString(), _accountLockoutFailOpen, ex);
            return _accountLockoutFailOpen
                ? AccountLockoutAuthenticationStatus.Allowed
                : AccountLockoutAuthenticationStatus.BackendFailure;
        }
    }

    private async Task<AccountLockoutAuthenticationStatus> RecordAccountLockoutFailureAsync(
        IUser user,
        AuthenticationProviderKey providerKey,
        AuthenticationContext context,
        CancellationToken cancellationToken)
    {
        if (_accountLockoutService == null)
        {
            return AccountLockoutAuthenticationStatus.Allowed;
        }

        try
        {
            var result = await _accountLockoutService.RecordFailureAsync(user, providerKey, CreateAccountLockoutContext(context), cancellationToken);
            return result.ThresholdReached || result.Status.IsLockedOut
                ? AccountLockoutAuthenticationStatus.LockedOut
                : AccountLockoutAuthenticationStatus.Allowed;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            AccountLockoutOperationFailed(_logger, "record_failure", user.Id, providerKey.ToString(), _accountLockoutFailOpen, ex);
            return _accountLockoutFailOpen
                ? AccountLockoutAuthenticationStatus.Allowed
                : AccountLockoutAuthenticationStatus.BackendFailure;
        }
    }

    private async Task ResetAccountLockoutAsync(
        IUser user,
        AuthenticationProviderKey providerKey,
        AuthenticationContext context,
        CancellationToken cancellationToken)
    {
        if (_accountLockoutService == null)
        {
            return;
        }

        try
        {
            await _accountLockoutService.ResetAsync(user, providerKey, CreateAccountLockoutContext(context), cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            AccountLockoutOperationFailed(_logger, "reset", user.Id, providerKey.ToString(), true, ex);
        }
    }

    private async Task ResetAccountLockoutIfApplicableAsync(
        bool shouldApplyAccountLockout,
        IUser user,
        AuthenticationProviderKey providerKey,
        AuthenticationContext context,
        CancellationToken cancellationToken)
    {
        if (shouldApplyAccountLockout)
        {
            await ResetAccountLockoutAsync(user, providerKey, context, cancellationToken);
        }
    }

    private static AccountLockoutContext CreateAccountLockoutContext(AuthenticationContext context)
    {
        return new AccountLockoutContext(
            new AuditContext(context.UserId, context.IpAddress, context.UserAgent, context.CorrelationId, context.Items),
            context.TenantId.HasValue ? new TenantContext(context.TenantId) : null);
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

        return new AuthenticationResponse(Status: AuthenticationStatus.RateLimited);
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

            return await CompleteSuccessfulLoginAsync(
                lifecycle,
                properties: null,
                credentialUpdatePersisted: false,
                cancellationToken);
        }

        Dictionary<string, string>? lifecycleFailureProperties = null;
        var credentialUpdatePersisted = false;
        try
        {
            var credentialUsageUpdate = await _credentialService.UpdateCredentialUsageAsync(
                lifecycle.Credential,
                lifecycle.OriginalCredential,
                lifecycle.Result,
                lifecycle.Provider,
                cancellationToken);
            if (!credentialUsageUpdate.CanProceed)
            {
                return await RecordFailureAsync(lifecycle.Context, lifecycle.Provider.Key, lifecycle.User.Id, SecurityEventFailureReasons.CredentialUpdateFailed, cancellationToken);
            }

            credentialUpdatePersisted = credentialUsageUpdate.UpdatePersisted;
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
                    lifecycle.Provider.Key.Type.StorageValue,
                    lifecycle.Provider.Key.Name,
                    ex);
                return await RecordFailureAsync(lifecycle.Context, lifecycle.Provider.Key, lifecycle.User.Id, SecurityEventFailureReasons.CredentialUpdateFailed, cancellationToken);
            }

            lifecycleFailureProperties = new Dictionary<string, string> { ["lifecycle_update_failed"] = "true" };
            CredentialLifecycleUpdateFailed(
                _logger,
                lifecycle.User.Id,
                lifecycle.Credential.Id,
                lifecycle.Provider.Key.Type.StorageValue,
                lifecycle.Provider.Key.Name,
                ex);
        }

        return await CompleteSuccessfulLoginAsync(
            lifecycle,
            lifecycleFailureProperties,
            credentialUpdatePersisted,
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

        return new AuthenticationResponse(returnedUser, returnedStatus);
    }

    private async Task<AuthenticationResponse> CompleteSuccessfulLoginAsync(
        CredentialLifecycleContext lifecycle,
        Dictionary<string, string>? properties,
        bool credentialUpdatePersisted,
        CancellationToken cancellationToken)
    {
        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);
        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.AuthenticationSucceeded,
            Outcome = SecurityEventOutcomes.Success,
            UserId = lifecycle.User.Id,
            Provider = lifecycle.Provider.Key,
            Context = lifecycle.Context,
            Properties = properties
        }, cancellationToken);

        await transaction.CommitAsync(cancellationToken);
        return new AuthenticationResponse(lifecycle.User, lifecycle.Status, lifecycle.Result.Claims, credentialUpdatePersisted)
        {
            StepUpSessionMarkingProof = lifecycle.IsFactor && lifecycle.Context.CurrentSessionId is { } sessionId
                ? StepUpSessionMarkingProof.Create(
                    lifecycle.User.Id,
                    sessionId,
                    lifecycle.Provider.Key,
                    ((ISecondaryAuthenticationFactorProvider)lifecycle.Provider).FactorType,
                    _timeProvider.GetUtcNow())
                : null
        };
    }

    private sealed record CredentialLifecycleContext(
        IUser User,
        UserCredential? Credential,
        UserCredential? OriginalCredential,
        AuthenticationResult Result,
        IAuthenticationProvider Provider,
        AuthenticationContext Context,
        AuthenticationStatus Status,
        bool IsFactor);

    private enum AccountLockoutAuthenticationStatus
    {
        Allowed,
        LockedOut,
        BackendFailure
    }
}

internal sealed record AuthenticationPipelineDependencies(
    ISecurityEventSink? SecurityEventSink = null,
    TimeProvider? TimeProvider = null,
    ILogger<AuthenticationPipeline>? Logger = null,
    IAccountLockoutService? AccountLockoutService = null,
    PrimaryAuthenticationRateLimitOptions? PrimaryRateLimitOptions = null,
    AuthenticationFactorRateLimitOptions? FactorRateLimitOptions = null,
    AccountLockoutOptions? AccountLockoutOptions = null);
