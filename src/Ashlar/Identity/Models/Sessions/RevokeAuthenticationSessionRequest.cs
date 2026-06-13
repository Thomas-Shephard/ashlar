using Ashlar.Auditing;

namespace Ashlar.Identity.Models.Sessions;

/// <summary>
/// Request parameters for revoking a specific authentication session.
/// </summary>
public sealed record RevokeAuthenticationSessionRequest
{
    /// <summary>
    /// Application session to revoke.
    /// </summary>
    public required Guid SessionId { get; init; }

    /// <summary>
    /// Optional provider-neutral, display-safe reason for audit events and notifications. Do not include secrets, tokens, or credentials.
    /// </summary>
    public string? Reason { get; init; }

    /// <summary>
    /// Tenant scope the target session must belong to. Use <see cref="TenantContext.Global" /> for global users; omit only when intentionally applying revocation across all tenant scopes.
    /// </summary>
    public TenantContext? Tenant { get; init; }

    /// <summary>
    /// Audit metadata describing who requested revocation.
    /// </summary>
    public AuditContext? Audit { get; init; }
}
