using Ashlar.Auditing;

namespace Ashlar.Authorization.Models;

/// <summary>
/// Request to revoke an authorization grant.
/// </summary>
/// <param name="GrantId">Stable authorization grant identifier to revoke.</param>
/// <param name="Audit">Actor and request context to include in emitted security events. Grant revocation is a privilege change and requires audit context.</param>
/// <param name="TenantId">Tenant boundary that must match the grant. A <see langword="null" /> value matches only global grants.</param>
/// <remarks>Service-layer mutation rejects a missing <paramref name="Audit" />.</remarks>
public sealed record RevokeAuthorizationGrantRequest(Guid GrantId, AuditContext Audit, Guid? TenantId = null);

/// <summary>
/// Outcome for an authorization grant revocation request.
/// </summary>
public enum AuthorizationGrantRevocationStatus
{
    /// <summary>
    /// The requested active grant was revoked.
    /// </summary>
    Revoked = 0,

    /// <summary>
    /// No grant exists for the requested identifier within the requested tenant boundary.
    /// </summary>
    NotFound = 1,

    /// <summary>
    /// The grant existed in the requested tenant boundary, but the repository did not change it.
    /// </summary>
    NotRevoked = 2,

    /// <summary>
    /// The revocation request failed validation before storage was inspected.
    /// </summary>
    ValidationFailed = 3
}

/// <summary>
/// Result of an authorization grant revocation request.
/// </summary>
/// <param name="Status">Stable revocation outcome.</param>
/// <param name="GrantId">Grant targeted by the revocation request.</param>
/// <param name="TenantId">Tenant boundary requested for revocation, or <see langword="null" /> for global grants.</param>
/// <param name="UserId">User assigned to the grant, when the grant was available for safe audit context.</param>
public sealed record RevokeAuthorizationGrantResult(
    AuthorizationGrantRevocationStatus Status,
    Guid GrantId,
    Guid? TenantId,
    Guid? UserId = null);
