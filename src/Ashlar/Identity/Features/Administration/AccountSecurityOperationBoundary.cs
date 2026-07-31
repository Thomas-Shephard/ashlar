using Ashlar.Auditing;

namespace Ashlar.Identity.Features.Administration;

/// <summary>
/// Enforces actor identity, active-session proof, host authorization, and durable audit around privileged operations.
/// </summary>
/// <param name="sessions">The authentication-session repository.</param>
/// <param name="authorizer">The host operation authorizer.</param>
/// <param name="auditSink">The durable audit sink.</param>
/// <param name="timeProvider">The clock used for proof validation and audit timestamps.</param>
/// <param name="proofPurpose">The required proof purpose, or the administration-read purpose by default.</param>
/// <param name="eventType">The durable audit event type, or the administration-read event type by default.</param>
public sealed class AccountSecurityOperationBoundary(
    IAuthenticationSessionRepository sessions,
    IAccountSecurityOperationAuthorizer authorizer,
    IPersistentSecurityEventSink auditSink,
    TimeProvider timeProvider,
    string? proofPurpose = null,
    string? eventType = null)
{
    /// <summary>Gets the default proof purpose for privileged reads.</summary>
    public const string ProofPurpose = AccountSecurityActorContext.AdministrationReadProofPurpose;
    /// <summary>Gets the default durable audit event type.</summary>
    public const string EventType = "administration.read";
    private readonly ActiveSessionFreshProofValidator _proof = new(
        sessions ?? throw new ArgumentNullException(nameof(sessions)),
        timeProvider ?? throw new ArgumentNullException(nameof(timeProvider)));
    private readonly IAccountSecurityOperationAuthorizer _authorizer = authorizer ?? throw new ArgumentNullException(nameof(authorizer));
    private readonly SecurityEventEmitter _audit = new(auditSink ?? throw new ArgumentNullException(nameof(auditSink)), timeProvider);
    private readonly string _proofPurpose = proofPurpose ?? ProofPurpose;
    private readonly string _eventType = eventType ?? EventType;

    /// <summary>Validates the actor, proof source session, audit identity, and host authorization.</summary>
    /// <param name="actor">The authenticated actor context.</param>
    /// <param name="tenant">The target tenant scope.</param>
    /// <param name="includeAllTenants">Whether the operation crosses all tenant scopes.</param>
    /// <param name="targetUserId">The target user, or an empty identifier for operational actions.</param>
    /// <param name="operation">The operation requiring authorization.</param>
    /// <param name="cancellationToken">A token that can cancel validation.</param>
    /// <param name="provider">The target authentication provider, when applicable.</param>
    /// <returns>The failure code, or <see langword="null" /> when every boundary check succeeds.</returns>
    public async ValueTask<AshlarFailureCode?> AuthorizeAsync(AccountSecurityActorContext? actor, TenantContext? tenant,
        bool includeAllTenants, Guid targetUserId, AccountSecurityOperation operation, CancellationToken cancellationToken,
        AuthenticationProviderKey? provider = null)
    {
        if (actor is null) return AshlarFailureCodes.ValidationError;
        if (!await ValidateActorAsync(actor, tenant, includeAllTenants, operation, cancellationToken))
            return AshlarFailureCodes.ValidationError;
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
        if (!authorized)
        {
            await RecordAsync(actor, tenant, includeAllTenants, operation, false, AshlarFailureCodes.AuthorizationDenied);
            return AshlarFailureCodes.AuthorizationDenied;
        }
        return null;
    }

    internal async Task RecordValidatedFailureAsync(AccountSecurityActorContext? actor, TenantContext? tenant,
        bool includeAllTenants, AccountSecurityOperation operation, CancellationToken cancellationToken)
    {
        if (actor is not null
            && await ValidateActorAsync(actor, tenant, includeAllTenants, operation, cancellationToken))
            await RecordAsync(actor, tenant, includeAllTenants, operation, false);
    }

    /// <summary>Records a successful authorized operation durably.</summary>
    /// <param name="actor">The authenticated actor context.</param>
    /// <param name="tenant">The target tenant scope.</param>
    /// <param name="includeAllTenants">Whether the operation crossed all tenant scopes.</param>
    /// <param name="operation">The completed operation.</param>
    /// <returns>A task representing durable audit emission.</returns>
    public Task RecordSuccessAsync(AccountSecurityActorContext actor, TenantContext? tenant, bool includeAllTenants,
        AccountSecurityOperation operation) =>
        RecordAsync(actor, tenant, includeAllTenants, operation, true);

    /// <summary>Records a failed authorized operation durably.</summary>
    /// <param name="actor">The authenticated actor context.</param>
    /// <param name="tenant">The target tenant scope.</param>
    /// <param name="includeAllTenants">Whether the operation crossed all tenant scopes.</param>
    /// <param name="operation">The failed operation.</param>
    /// <returns>A task representing durable audit emission.</returns>
    public Task RecordFailureAsync(AccountSecurityActorContext actor, TenantContext? tenant, bool includeAllTenants,
        AccountSecurityOperation operation) =>
        RecordAsync(actor, tenant, includeAllTenants, operation, false);

    private async Task<bool> ValidateActorAsync(AccountSecurityActorContext actor, TenantContext? tenant,
        bool includeAllTenants, AccountSecurityOperation operation, CancellationToken cancellationToken)
    {
        AshlarFailureCode? proofFailure;
        try
        {
            proofFailure = await _proof.ValidateAsync(actor.ActorUserId, actor.ActorTenant, actor.FreshMfaProof,
                actor.CurrentSessionId, _proofPurpose, cancellationToken);
        }
        catch
        {
            await RecordAsync(actor, tenant, includeAllTenants, operation, false, actorAuthenticated: false);
            throw;
        }
        if (proofFailure is not null)
        {
            await RecordAsync(actor, tenant, includeAllTenants, operation, false, actorAuthenticated: false);
            return false;
        }
        if (actor.Audit.ActorUserId != actor.ActorUserId)
        {
            await RecordAsync(actor, tenant, includeAllTenants, operation, false);
            return false;
        }
        return true;
    }

    private Task RecordAsync(AccountSecurityActorContext actor, TenantContext? tenant, bool includeAllTenants,
        AccountSecurityOperation operation, bool succeeded, AshlarFailureCode? failure = null, bool actorAuthenticated = true)
    {
        var scope = "all-tenants";
        if (!includeAllTenants)
            scope = tenant == TenantContext.Global ? "global" : "tenant";
        return _audit.RecordAsync(new SecurityEventDescriptor
        {
            EventType = _eventType,
            Outcome = succeeded ? SecurityEventOutcomes.Success : SecurityEventOutcomes.Failure,
            TenantId = tenant?.TenantId,
            SessionId = actorAuthenticated ? actor.CurrentSessionId : null,
            Audit = actor.Audit with { ActorUserId = actorAuthenticated ? actor.ActorUserId : null },
            FailureReason = succeeded ? null : (failure ?? AshlarFailureCodes.ValidationError).Value,
            Properties = new Dictionary<string, string>
            {
                ["operation"] = operation.ToString(),
                ["scope"] = scope
            }
        }, CancellationToken.None);
    }
}
