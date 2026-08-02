namespace Ashlar.Authorization.Models;

/// <summary>Request to revoke one authorization grant.</summary>
public sealed record RevokeAuthorizationGrantRequest
{
    /// <summary>Creates a revocation request with an explicit target scope.</summary>
    /// <param name="grantId">Grant to revoke.</param>
    /// <param name="tenant">Explicit tenant or global target scope.</param><param name="includeAllTenants">Whether the lookup may cross all tenants.</param>
    public RevokeAuthorizationGrantRequest(Guid grantId, TenantContext? tenant = null, bool includeAllTenants = false)
    {
        GrantId = grantId; TenantId = tenant?.TenantId; IncludeAllTenants = includeAllTenants;
        IsScopeInvalid = tenant is null || includeAllTenants;
    }

    /// <summary>Gets the grant identifier.</summary>
    public Guid GrantId { get; }
    /// <summary>Gets the exact tenant identifier, or <see langword="null"/> for global scope.</summary>
    public Guid? TenantId { get; }
    /// <summary>Gets whether all tenant scopes were requested.</summary>
    public bool IncludeAllTenants { get; }
    internal bool IsScopeInvalid { get; }
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
