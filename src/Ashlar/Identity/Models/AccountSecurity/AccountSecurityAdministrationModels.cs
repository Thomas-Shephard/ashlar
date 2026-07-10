using Ashlar.Auditing;

namespace Ashlar.Identity.Models.AccountSecurity;

/// <summary>Identifies a destructive account-security operation for host authorization.</summary>
public enum AccountSecurityOperation
{
    /// <summary>Changes account state.</summary>
    SetAccountState,
    /// <summary>Revoke authentication sessions.</summary>
    RevokeSessions,
    /// <summary>Revoke provider credentials.</summary>
    RevokeCredentials,
    /// <summary>Resets MFA material.</summary>
    ResetMfa,
    /// <summary>Revokes one remembered MFA device.</summary>
    RevokeRememberedMfaDevice,
    /// <summary>Revokes all remembered MFA devices for the target user and scope.</summary>
    RevokeRememberedMfaDevices,
    /// <summary>Starts self-service TOTP enrollment.</summary>
    StartTotpEnrollment,
    /// <summary>Completes self-service TOTP enrollment.</summary>
    CompleteTotpEnrollment,
    /// <summary>Disables self-service TOTP.</summary>
    DisableTotp,
    /// <summary>Revokes one session owned by the actor.</summary>
    RevokeOwnSession,
    /// <summary>Revokes the actor's other sessions.</summary>
    RevokeOwnOtherSessions,
    /// <summary>Generates a new recovery-code credential set for the target account.</summary>
    GenerateRecoveryCodes,
    /// <summary>Revokes every recovery-code credential belonging to the target account.</summary>
    RevokeRecoveryCodes,
    /// <summary>Authorizes assignment of a role or permission grant to a target user and exact scope.</summary>
    CreateAuthorizationGrant,
    /// <summary>Authorizes removal of an authorization grant from a target user and requested scope.</summary>
    RevokeAuthorizationGrant
}

/// <summary>Context supplied to the required host authorizer.</summary>
/// <param name="ActorUserId">The authenticated actor.</param>
/// <param name="ActorTenant">The actor's authenticated tenant or global scope.</param>
/// <param name="TargetUserId">The user targeted by the <paramref name="Operation" />.</param>
/// <param name="TargetTenant">The explicit target tenant or global scope.</param>
/// <param name="IncludeAllTenants">Whether the <paramref name="Operation" /> crosses all target tenant scopes.</param>
/// <param name="Operation">The destructive operation being authorized.</param>
/// <param name="Provider">The credential provider being revoked, when applicable.</param>
/// <param name="AccountState">The requested account state, when applicable.</param>
/// <param name="RevokeSessionsAndRememberedMfaDevices">Whether an account-state change also revokes sessions and remembered MFA devices.</param>
/// <param name="PreservePrimarySignInMethod">Whether credential revocation must leave another usable primary sign-in method.</param>
/// <param name="TargetSessionId">The session targeted by a self-service <paramref name="Operation" />, when applicable.</param>
/// <param name="RememberedMfaDeviceId">The remembered MFA device targeted by the <paramref name="Operation" />, when applicable.</param>
/// <param name="CurrentSessionId">The actor's current session, when applicable.</param>
public sealed record AccountSecurityAuthorizationContext(
    Guid ActorUserId,
    TenantContext ActorTenant,
    Guid TargetUserId,
    TenantContext? TargetTenant,
    bool IncludeAllTenants,
    AccountSecurityOperation Operation,
    AuthenticationProviderKey? Provider = null,
    UserAccountState? AccountState = null,
    bool? RevokeSessionsAndRememberedMfaDevices = null,
    bool PreservePrimarySignInMethod = false,
    Guid? TargetSessionId = null,
    Guid? RememberedMfaDeviceId = null,
    Guid? CurrentSessionId = null);

/// <summary>Authenticated actor context required by destructive account-security requests.</summary>
public sealed record AccountSecurityActorContext
{
    /// <summary>Creates actor context bound to a current session and fresh MFA proof.</summary>
    /// <param name="actorUserId">The authenticated actor.</param>
    /// <param name="actorTenant">The actor's authenticated tenant or global scope.</param>
    /// <param name="currentSessionId">The actor's current authenticated session.</param>
    /// <param name="freshMfaProof">Ashlar-issued fresh MFA proof.</param>
    /// <param name="audit">Required audit metadata.</param>
    public AccountSecurityActorContext(Guid actorUserId, TenantContext actorTenant, Guid currentSessionId,
        FreshMfaVerificationProof freshMfaProof, AuditContext audit)
    {
        if (actorUserId == Guid.Empty) throw new ArgumentException("Actor user ID cannot be empty.", nameof(actorUserId));
        if (currentSessionId == Guid.Empty) throw new ArgumentException("Current session ID cannot be empty.", nameof(currentSessionId));
        ActorUserId = actorUserId;
        ActorTenant = actorTenant ?? throw new ArgumentNullException(nameof(actorTenant));
        CurrentSessionId = currentSessionId;
        FreshMfaProof = freshMfaProof ?? throw new ArgumentNullException(nameof(freshMfaProof));
        Audit = audit ?? throw new ArgumentNullException(nameof(audit));
    }

    /// <summary>Gets the authenticated actor.</summary>
    public Guid ActorUserId { get; }
    /// <summary>Gets the actor's authenticated tenant or global scope.</summary>
    public TenantContext ActorTenant { get; }
    /// <summary>Gets the actor's current authenticated session.</summary>
    public Guid CurrentSessionId { get; }
    /// <summary>Gets the Ashlar-issued fresh MFA proof.</summary>
    public FreshMfaVerificationProof FreshMfaProof { get; }
    /// <summary>Gets required audit metadata.</summary>
    public AuditContext Audit { get; }
}

/// <summary>Actor-bound request for a destructive account-security operation.</summary>
public record AccountSecurityAdministrationRequest
{
    /// <summary>Creates an actor-bound destructive account-security request.</summary>
    /// <param name="targetUserId">The target user.</param>
    /// <param name="actor">Authenticated actor, scope, current session, proof, and audit metadata.</param>
    /// <param name="tenant">The explicit target tenant or global scope.</param>
    /// <param name="includeAllTenants">Whether the target lookup may cross every tenant scope.</param>
    /// <param name="reason">An optional display-safe reason.</param>
    public AccountSecurityAdministrationRequest(Guid targetUserId, AccountSecurityActorContext actor,
        TenantContext? tenant = null, bool includeAllTenants = false, string? reason = null)
    {
        if (targetUserId == Guid.Empty) throw new ArgumentException("Target user ID cannot be empty.", nameof(targetUserId));
        ArgumentNullException.ThrowIfNull(actor);
        AdministrationScopeValidation.ThrowIfInvalidScope(tenant, includeAllTenants);
        TargetUserId = targetUserId; ActorUserId = actor.ActorUserId; ActorTenant = actor.ActorTenant;
        CurrentSessionId = actor.CurrentSessionId; FreshMfaProof = actor.FreshMfaProof;
        Audit = actor.Audit; Tenant = tenant; IncludeAllTenants = includeAllTenants;
        Reason = reason;
    }
    /// <summary>Gets the target user.</summary>
    public Guid TargetUserId { get; }
    /// <summary>Gets the authenticated actor.</summary>
    public Guid ActorUserId { get; }
    /// <summary>Gets the actor's authenticated tenant or global scope.</summary>
    public TenantContext ActorTenant { get; }
    /// <summary>Gets the actor's current authenticated session.</summary>
    public Guid CurrentSessionId { get; }
    /// <summary>Gets the Ashlar-issued fresh MFA proof.</summary>
    public FreshMfaVerificationProof FreshMfaProof { get; }
    /// <summary>Gets required audit metadata.</summary>
    public AuditContext Audit { get; }
    /// <summary>Gets the explicit target tenant or global scope.</summary>
    public TenantContext? Tenant { get; }
    /// <summary>Gets whether the target lookup may cross all tenant scopes.</summary>
    public bool IncludeAllTenants { get; }
    /// <summary>Gets the optional display-safe reason.</summary>
    public string? Reason { get; }
}

/// <summary>Actor-bound request for changing a target user's account state.</summary>
public sealed record SetUserAccountStateAdministrationRequest : AccountSecurityAdministrationRequest
{
    /// <summary>Creates an actor-bound account-state request.</summary>
    /// <param name="targetUserId">The target user.</param>
    /// <param name="accountState">The required target account state.</param>
    /// <param name="actor">Authenticated actor context.</param>
    /// <param name="tenant">The explicit target tenant or global scope.</param>
    /// <param name="includeAllTenants">Whether the target lookup may cross every tenant scope.</param>
    /// <param name="reason">An optional display-safe reason.</param>
    /// <param name="revokeSessionsAndRememberedMfaDevices">Whether disabling sign-in also revokes sessions and remembered MFA devices.</param>
    public SetUserAccountStateAdministrationRequest(
        Guid targetUserId,
        UserAccountState accountState,
        AccountSecurityActorContext actor,
        TenantContext? tenant = null,
        bool includeAllTenants = false,
        string? reason = null,
        bool revokeSessionsAndRememberedMfaDevices = true)
        : base(targetUserId, actor, tenant, includeAllTenants, reason)
    {
        if (!Enum.IsDefined(accountState))
        {
            throw new ArgumentOutOfRangeException(nameof(accountState), accountState, "Unknown user account state.");
        }

        AccountState = accountState;
        RevokeSessionsAndRememberedMfaDevices = revokeSessionsAndRememberedMfaDevices;
    }

    /// <summary>Gets the required target account state.</summary>
    public UserAccountState AccountState { get; }

    /// <summary>Gets whether disabling sign-in also revokes sessions and remembered MFA devices.</summary>
    public bool RevokeSessionsAndRememberedMfaDevices { get; }
}

/// <summary>Actor-bound request for credential-provider revocation.</summary>
public sealed record RevokeAccountCredentialsRequest : AccountSecurityAdministrationRequest
{
    /// <summary>Creates an actor-bound provider credential-revocation request.</summary>
    /// <param name="targetUserId">The target user.</param>
    /// <param name="provider">The configured non-internal provider to revoke.</param>
    /// <param name="actor">Authenticated actor context.</param>
    /// <param name="tenant">The explicit target tenant or global scope.</param>
    /// <param name="includeAllTenants">Whether the target lookup may cross every tenant scope.</param>
    /// <param name="reason">An optional display-safe reason.</param>
    /// <param name="preservePrimarySignInMethod">Whether revocation must leave another usable primary sign-in method.</param>
    public RevokeAccountCredentialsRequest(Guid targetUserId, AuthenticationProviderKey provider, AccountSecurityActorContext actor, TenantContext? tenant = null,
        bool includeAllTenants = false, string? reason = null, bool preservePrimarySignInMethod = false)
        : base(targetUserId, actor, tenant, includeAllTenants, reason)
    {
        if (!provider.IsConfigured || provider.Type == ProviderType.Internal) throw new ArgumentException("Provider must be a configured, non-internal provider.", nameof(provider));
        Provider = provider;
        PreservePrimarySignInMethod = preservePrimarySignInMethod;
    }
    /// <summary>Gets the configured provider whose credentials will be revoked.</summary>
    public AuthenticationProviderKey Provider { get; }

    /// <summary>Gets whether revocation must leave another usable primary sign-in method.</summary>
    public bool PreservePrimarySignInMethod { get; }
}

/// <summary>Actor-bound request for revoking one remembered MFA device.</summary>
public sealed record RevokeRememberedMfaDeviceAdministrationRequest : AccountSecurityAdministrationRequest
{
    /// <summary>Creates an actor-bound remembered-device revocation request.</summary>
    /// <param name="deviceId">The remembered device to revoke.</param>
    /// <param name="targetUserId">The device owner.</param>
    /// <param name="actor">Authenticated actor context.</param>
    /// <param name="tenant">The explicit target tenant or global scope.</param>
    /// <param name="includeAllTenants">Whether the target lookup crosses every tenant scope.</param>
    /// <param name="reason">An optional display-safe reason.</param>
    public RevokeRememberedMfaDeviceAdministrationRequest(Guid deviceId, Guid targetUserId, AccountSecurityActorContext actor,
        TenantContext? tenant = null, bool includeAllTenants = false, string? reason = null)
        : base(targetUserId, actor, tenant, includeAllTenants, reason)
    {
        if (deviceId == Guid.Empty) throw new ArgumentException("Remembered MFA device ID cannot be empty.", nameof(deviceId));
        DeviceId = deviceId;
    }

    /// <summary>Gets the remembered MFA device to revoke.</summary>
    public Guid DeviceId { get; }
}
