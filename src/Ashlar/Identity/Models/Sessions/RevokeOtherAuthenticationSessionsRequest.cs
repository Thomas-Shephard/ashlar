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
    /// Tenant scope to revoke within. Use <see cref="TenantContext.Global" /> for global users; leave <see langword="null" /> only when <see cref="IncludeAllTenants" /> is enabled.
    /// </summary>
    public TenantContext? Tenant { get; init; }

    /// <summary>
    /// Whether to revoke other sessions across all tenant scopes. Cannot be combined with <see cref="Tenant" />.
    /// </summary>
    public bool IncludeAllTenants { get; init; }

    /// <summary>
    /// Audit metadata describing who requested revocation.
    /// </summary>
    public AuditContext? Audit { get; init; }

    /// <summary>
    /// Throws when required metadata is missing or revocation scope is ambiguous.
    /// </summary>
    public void ThrowIfInvalid()
    {
        ArgumentNullException.ThrowIfNull(Audit);
        AdministrationScopeValidation.ThrowIfInvalidScope(Tenant, IncludeAllTenants);
    }
}
