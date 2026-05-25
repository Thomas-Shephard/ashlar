using Ashlar.Auditing;

namespace Ashlar.Authorization.Models;

/// <summary>
/// Represents the revoke authorization grant request data model.
/// </summary>
/// <param name="GrantId">The grant id value.</param>
/// <param name="TenantId">The tenant id value of the grant to revoke. A <see langword="null" /> value matches only global grants.</param>
/// <param name="Audit">The audit metadata value.</param>
public sealed record RevokeAuthorizationGrantRequest(Guid GrantId, Guid? TenantId = null, AuditContext? Audit = null);
