using Ashlar.Auditing;

namespace Ashlar.Authorization.Models;

/// <summary>Actor-bound request to revoke one authorization grant.</summary>
/// <remarks>The service verifies the Ashlar-issued proof, current session, audit actor, requested scope, and host authorization before mutation. Missing and unauthorized grants have the same outcome.</remarks>
public sealed record RevokeAuthorizationGrantRequest
{
    /// <summary>Creates a revocation request bound to an authenticated actor and explicit target scope.</summary>
    /// <param name="grantId">Grant to revoke.</param><param name="actor">Authenticated actor, current session, and fresh proof.</param><param name="audit">Required audit metadata whose actor must match <paramref name="actor"/>.</param>
    /// <param name="tenant">Explicit tenant or global target scope.</param><param name="includeAllTenants">Whether the lookup may cross all tenants.</param>
    public RevokeAuthorizationGrantRequest(Guid grantId, AccountSecurityActorContext actor, AuditContext audit, TenantContext? tenant = null, bool includeAllTenants = false)
    {
        ArgumentNullException.ThrowIfNull(actor);
        ArgumentNullException.ThrowIfNull(audit);
        AdministrationScopeValidation.ThrowIfInvalidScope(tenant, includeAllTenants);
        GrantId = grantId; Actor = actor; Audit = audit; TenantId = tenant?.TenantId; IncludeAllTenants = includeAllTenants;
    }

    internal RevokeAuthorizationGrantRequest(Guid GrantId, AuditContext Audit, Guid? TenantId = null)
    { this.GrantId = GrantId; this.Audit = Audit; this.TenantId = TenantId; IsInfrastructureMutation = true; }

    /// <summary>Gets the grant identifier.</summary>
    public Guid GrantId { get; }
    /// <summary>Gets the validated actor capability supplied by an app caller.</summary>
    public AccountSecurityActorContext? Actor { get; }
    /// <summary>Gets required audit metadata whose actor must match <see cref="Actor"/>.</summary>
    public AuditContext Audit { get; }
    /// <summary>Gets the exact tenant identifier, or <see langword="null"/> for global scope.</summary>
    public Guid? TenantId { get; }
    /// <summary>Gets whether all tenant scopes were requested.</summary>
    public bool IncludeAllTenants { get; }
    internal bool IsInfrastructureMutation { get; }
}

/// <summary>Describes the stable outcome of authorization grant revocation.</summary>
public enum AuthorizationGrantRevocationStatus
{
    /// <summary>An active matching grant was revoked.</summary>
    Revoked = 0,
    /// <summary>No grant matched the requested identifier and scope.</summary>
    NotFound = 1,
    /// <summary>The matching grant was not changed.</summary>
    NotRevoked = 2,
    /// <summary>Actor, proof, audit, or request validation failed.</summary>
    ValidationFailed = 3
}

/// <summary>Returns the revocation outcome without exposing grant data outside the requested scope.</summary>
/// <param name="Status">Stable revocation outcome.</param><param name="GrantId">Requested grant.</param>
/// <param name="TenantId">Requested exact tenant, or global scope.</param><param name="UserId">Grant recipient when safely available.</param>
public sealed record RevokeAuthorizationGrantResult(AuthorizationGrantRevocationStatus Status, Guid GrantId, Guid? TenantId, Guid? UserId = null);
