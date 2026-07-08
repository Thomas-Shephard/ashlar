using Ashlar.Auditing;

namespace Ashlar.Identity.Models.Invitations;

/// <summary>
/// Request for revoking pending invitations by email address.
/// </summary>
/// <remarks>
/// Revocation requires an explicit tenant scope and audit metadata because it is a destructive operation.
/// Use <see cref="TenantContext.Global" /> for global invitations, or <see cref="IncludeAllTenants" /> for intentional operator-wide revocation.
/// </remarks>
public sealed record RevokeInvitationsRequest
{
    /// <summary>Email address whose pending invitations should be revoked.</summary>
    public string? Email { get; init; }

    /// <summary>Tenant scope to revoke within. Use <see cref="TenantContext.Global" /> for global invitations.</summary>
    public TenantContext? Tenant { get; init; }

    /// <summary>Whether to revoke matching pending invitations across all tenant scopes. Cannot be combined with <see cref="Tenant" />.</summary>
    public bool IncludeAllTenants { get; init; }

    /// <summary>Actor and request metadata required for revocation audit events.</summary>
    public AuditContext? Audit { get; init; }
}
