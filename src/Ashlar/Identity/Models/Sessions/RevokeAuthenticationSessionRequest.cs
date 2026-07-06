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
    /// Tenant scope the target session must belong to. Use <see cref="TenantContext.Global" /> for global users; leave <see langword="null" /> only when <see cref="IncludeAllTenants" /> is enabled.
    /// </summary>
    public TenantContext? Tenant { get; init; }

    /// <summary>
    /// Whether to allow lookup across all tenant scopes. Cannot be combined with <see cref="Tenant" />.
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
