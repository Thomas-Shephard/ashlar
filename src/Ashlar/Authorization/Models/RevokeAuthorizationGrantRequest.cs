using Ashlar.Auditing;

namespace Ashlar.Authorization.Models;

/// <summary>
/// Request to revoke an authorization grant.
/// </summary>
/// <param name="GrantId">Stable authorization grant identifier to revoke.</param>
/// <param name="TenantId">Tenant boundary that must match the grant. A <see langword="null" /> value matches only global grants.</param>
/// <param name="Audit">Actor and request context to include in emitted security events.</param>
public sealed record RevokeAuthorizationGrantRequest(Guid GrantId, Guid? TenantId = null, AuditContext? Audit = null);
