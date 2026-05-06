using Ashlar.Auditing;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;

namespace Ashlar.Identity;

public sealed class AuthenticationPipeline(
    IAuthenticationProviderRegistry providerRegistry,
    ICredentialService credentialService,
    IAshlarTransactionProvider transactionProvider,
    ISecurityEventSink? securityEventSink = null,
    TimeProvider? timeProvider = null)
    : IAuthenticationPipeline
{
    private readonly IAuthenticationProviderRegistry _providerRegistry = providerRegistry ?? throw new ArgumentNullException(nameof(providerRegistry));
    private readonly ICredentialService _credentialService = credentialService ?? throw new ArgumentNullException(nameof(credentialService));
    private readonly IAshlarTransactionProvider _transactionProvider = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
    private readonly SecurityEventEmitter _securityEvents = new(securityEventSink, timeProvider ?? TimeProvider.System);

    public async Task<AuthenticationResponse> LoginAsync(AuthenticationContext context, IAuthenticationAssertion assertion, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(assertion);

        if (!_providerRegistry.TryGetProvider(assertion, out var provider))
        {
            return await RecordFailureAsync(context, assertion.ProviderIdentity, null, SecurityEventFailureReasons.ProviderUnsupported, cancellationToken);
        }

        var (user, credential, originalCredential, unprotectFailed) = await _credentialService.ResolveAsync(context, assertion, provider, cancellationToken);

        var result = await provider.AuthenticateAsync(assertion, credential, cancellationToken);
        if (unprotectFailed || result.Status is not (AuthenticationResultStatus.Succeeded or AuthenticationResultStatus.SucceededWithCredentialUpdate or AuthenticationResultStatus.MfaRequired) || user == null)
        {
            var reason = unprotectFailed ? SecurityEventFailureReasons.UnprotectFailed : SecurityEventFailureReasons.InvalidCredentials;
            return await RecordFailureAsync(context, provider.Key, user?.Id, reason, cancellationToken);
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
                return await RecordFailureAsync(lifecycle.Context, lifecycle.Provider.Key, lifecycle.User.Id, SecurityEventFailureReasons.CredentialUpdateFailed, cancellationToken);
            }

            lifecycleUpdateFailed = true;
            // TODO: Log the swallowed infrastructure exception once Ashlar has a core logging convention.
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
        IDictionary<string, string>? claims,
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
