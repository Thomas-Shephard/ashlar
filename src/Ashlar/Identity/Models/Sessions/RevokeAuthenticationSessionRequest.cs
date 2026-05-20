using Ashlar.Auditing;

namespace Ashlar.Identity.Models.Sessions;

/// <summary>
/// Request parameters for revoking a specific authentication session.
/// </summary>
public sealed record RevokeAuthenticationSessionRequest
{
    /// <summary>
    /// The unique identifier of the session to revoke.
    /// </summary>
    public required Guid SessionId { get; init; }

    /// <summary>
    /// An optional reason for revocation.
    /// </summary>
    public string? Reason { get; init; }

    /// <summary>
    /// Tenant scope for the revocation event.
    /// </summary>
    public TenantContext? Tenant { get; init; }

    /// <summary>
    /// Audit metadata describing who requested revocation.
    /// </summary>
    public AuditContext? Audit { get; init; }
}
