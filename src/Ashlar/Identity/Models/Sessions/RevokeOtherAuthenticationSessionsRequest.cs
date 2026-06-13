using Ashlar.Auditing;

namespace Ashlar.Identity.Models.Sessions;

/// <summary>
/// Request parameters for revoking all sessions for a user except one.
/// </summary>
public sealed record RevokeOtherAuthenticationSessionsRequest
{
    /// <summary>
    /// Current application session that must remain active while other sessions are revoked.
    /// </summary>
    public required Guid CurrentSessionId { get; init; }

    /// <summary>
    /// Optional provider-neutral, display-safe reason for audit events and notifications. Do not include secrets, tokens, or credentials.
    /// </summary>
    public string? Reason { get; init; }

    /// <summary>
    /// Tenant scope to revoke within. Use <see cref="TenantContext.Global" /> for global users; omit only when intentionally applying revocation across all tenant scopes.
    /// </summary>
    public TenantContext? Tenant { get; init; }

    /// <summary>
    /// Audit metadata describing who requested revocation.
    /// </summary>
    public AuditContext? Audit { get; init; }
}
