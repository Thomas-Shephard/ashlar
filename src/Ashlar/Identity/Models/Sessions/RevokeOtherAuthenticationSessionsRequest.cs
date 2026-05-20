using Ashlar.Auditing;

namespace Ashlar.Identity.Models.Sessions;

/// <summary>
/// Request parameters for revoking all sessions for a user except one.
/// </summary>
public sealed record RevokeOtherAuthenticationSessionsRequest
{
    /// <summary>
    /// The session ID that should NOT be revoked.
    /// </summary>
    public required Guid CurrentSessionId { get; init; }

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





