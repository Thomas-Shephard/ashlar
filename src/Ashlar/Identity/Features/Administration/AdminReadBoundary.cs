using Ashlar.Auditing;

namespace Ashlar.Identity.Features.Administration;

internal sealed class AdminReadBoundary(
    IAuthenticationSessionRepository sessions,
    IAccountSecurityOperationAuthorizer authorizer,
    IPersistentSecurityEventSink auditSink,
    TimeProvider timeProvider,
    string? proofPurpose = null,
    string? eventType = null)
{
    internal const string ProofPurpose = AccountSecurityActorContext.AdministrationReadProofPurpose;
    internal const string EventType = "administration.read";
    private readonly ActiveSessionFreshProofValidator _proof = new(
        sessions ?? throw new ArgumentNullException(nameof(sessions)),
        timeProvider ?? throw new ArgumentNullException(nameof(timeProvider)));
    private readonly IAccountSecurityOperationAuthorizer _authorizer = authorizer ?? throw new ArgumentNullException(nameof(authorizer));
    private readonly SecurityEventEmitter _audit = new(auditSink ?? throw new ArgumentNullException(nameof(auditSink)), timeProvider);
    private readonly string _proofPurpose = proofPurpose ?? ProofPurpose;
    private readonly string _eventType = eventType ?? EventType;

    internal async ValueTask<bool> AuthorizeAsync(AccountSecurityActorContext? actor, TenantContext? tenant,
        bool includeAllTenants, Guid targetUserId, AccountSecurityOperation operation, CancellationToken cancellationToken,
        bool recordSuccess = true, AuthenticationProviderKey? provider = null)
    {
        if (actor is null) return false;
        if (actor.Audit.ActorUserId != actor.ActorUserId)
        {
            await RecordAsync(actor, tenant, includeAllTenants, operation, false);
            return false;
        }
        AshlarFailureCode? proofFailure;
        try
        {
            proofFailure = await _proof.ValidateAsync(actor.ActorUserId, actor.ActorTenant, actor.FreshMfaProof,
                actor.CurrentSessionId, _proofPurpose, cancellationToken);
        }
        catch
        {
            await RecordAsync(actor, tenant, includeAllTenants, operation, false);
            throw;
        }
        if (proofFailure is not null)
        {
            await RecordAsync(actor, tenant, includeAllTenants, operation, false);
            return false;
        }
        bool authorized;
        try
        {
            authorized = await _authorizer.AuthorizeAsync(new AccountSecurityAuthorizationContext(
                actor.ActorUserId, actor.ActorTenant, targetUserId, tenant, includeAllTenants, operation,
                Provider: provider,
                CurrentSessionId: actor.CurrentSessionId), cancellationToken);
        }
        catch
        {
            await RecordAsync(actor, tenant, includeAllTenants, operation, false);
            throw;
        }
        if (!authorized || recordSuccess)
            await RecordAsync(actor, tenant, includeAllTenants, operation, authorized);
        return authorized;
    }

    internal Task RecordSuccessAsync(AccountSecurityActorContext actor, TenantContext? tenant, bool includeAllTenants,
        AccountSecurityOperation operation) =>
        RecordAsync(actor, tenant, includeAllTenants, operation, true);

    internal Task RecordFailureAsync(AccountSecurityActorContext actor, TenantContext? tenant, bool includeAllTenants,
        AccountSecurityOperation operation) =>
        RecordAsync(actor, tenant, includeAllTenants, operation, false);

    private Task RecordAsync(AccountSecurityActorContext actor, TenantContext? tenant, bool includeAllTenants,
        AccountSecurityOperation operation, bool succeeded)
    {
        var scope = "all-tenants";
        if (!includeAllTenants)
            scope = tenant == TenantContext.Global ? "global" : "tenant";
        return _audit.RecordAsync(new SecurityEventDescriptor
        {
            EventType = _eventType,
            Outcome = succeeded ? SecurityEventOutcomes.Success : SecurityEventOutcomes.Failure,
            TenantId = tenant?.TenantId,
            SessionId = actor.CurrentSessionId,
            Audit = actor.Audit with { ActorUserId = actor.ActorUserId },
            FailureReason = succeeded ? null : AshlarFailureCodes.ValidationError.Value,
            Properties = new Dictionary<string, string>
            {
                ["operation"] = operation.ToString(),
                ["scope"] = scope
            }
        }, CancellationToken.None);
    }
}
