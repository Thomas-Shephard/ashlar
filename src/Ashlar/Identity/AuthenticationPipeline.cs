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
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.AuthenticationFailed,
                Outcome = SecurityEventOutcomes.Failure,
                Provider = assertion.ProviderIdentity,
                Context = context,
                FailureReason = SecurityEventFailureReasons.ProviderUnsupported
            }, cancellationToken);
            return new AuthenticationResponse(false, Status: AuthenticationStatus.Failed);
        }

        var (user, credential, originalCredential, unprotectFailed) = await _credentialService.ResolveAsync(context, assertion, provider, cancellationToken);

        var result = await provider.AuthenticateAsync(assertion, credential, cancellationToken);
        if (unprotectFailed || result.Status is not (AuthenticationResultStatus.Succeeded or AuthenticationResultStatus.SucceededWithCredentialUpdate) || user == null)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.AuthenticationFailed,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = user?.Id,
                Provider = provider.Key,
                Context = context,
                FailureReason = unprotectFailed ? SecurityEventFailureReasons.UnprotectFailed : SecurityEventFailureReasons.InvalidCredentials
            }, cancellationToken);

            return new AuthenticationResponse(false, Status: AuthenticationStatus.Failed);
        }

        if (!user.IsActive)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.AuthenticationFailed,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = user.Id,
                Provider = provider.Key,
                Context = context,
                FailureReason = SecurityEventFailureReasons.UserDisabled
            }, cancellationToken);

            return new AuthenticationResponse(false, user, AuthenticationStatus.Disabled);
        }

        var status = result.Status == AuthenticationResultStatus.SucceededWithCredentialUpdate ? AuthenticationStatus.SuccessWithCredentialUpdate : AuthenticationStatus.Success;

        if (credential == null)
        {
            return await CompleteSuccessfulLoginAsync(user, provider, context, status, result.Claims, properties: null, cancellationToken);
        }

        var lifecycleUpdateFailed = false;
        try
        {
            var credentialUsageUpdated = await _credentialService.UpdateCredentialUsageAsync(credential, originalCredential, result, provider, cancellationToken);
            if (!credentialUsageUpdated)
            {
                await _securityEvents.RecordAsync(new SecurityEventDescriptor
                {
                    EventType = AshlarSecurityEventTypes.AuthenticationFailed,
                    Outcome = SecurityEventOutcomes.Failure,
                    UserId = user.Id,
                    Provider = provider.Key,
                    Context = context,
                    FailureReason = SecurityEventFailureReasons.CredentialUpdateFailed
                }, cancellationToken);

                return new AuthenticationResponse(false, Status: AuthenticationStatus.Failed);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Fail authentication if a critical lifecycle operation (Consume or Required Update) threw an uncaught exception.
            if (result.IsCredentialConsumed || result.CredentialUpdateRequirement == CredentialUpdateRequirement.Required)
            {
                await _securityEvents.RecordAsync(new SecurityEventDescriptor
                {
                    EventType = AshlarSecurityEventTypes.AuthenticationFailed,
                    Outcome = SecurityEventOutcomes.Failure,
                    UserId = user.Id,
                    Provider = provider.Key,
                    Context = context,
                    FailureReason = SecurityEventFailureReasons.CredentialUpdateFailed
                }, cancellationToken);

                return new AuthenticationResponse(false, Status: AuthenticationStatus.Failed);
            }

            lifecycleUpdateFailed = true;
            // TODO: Log the swallowed infrastructure exception once Ashlar has a core logging convention.
        }

        return await CompleteSuccessfulLoginAsync(
            user,
            provider,
            context,
            status,
            result.Claims,
            lifecycleUpdateFailed ? new Dictionary<string, string> { ["lifecycle_update_failed"] = "true" } : null,
            cancellationToken);
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
}
