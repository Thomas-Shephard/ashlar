using Ashlar.Auditing;
using Ashlar.Identity.Models.Tenants;

namespace Ashlar.OAuth;

/// <summary>Audit metadata and tenant scope for unlinking the current user's external account.</summary>
public sealed record AshlarExternalAccountUnlinkRequest
{
    /// <summary>Creates an external-account unlink request.</summary>
    /// <param name="audit">Audit metadata whose actor is the current user.</param>
    /// <param name="tenant">The current user's explicit tenant or global scope.</param>
    /// <param name="reason">An optional display-safe reason.</param>
    public AshlarExternalAccountUnlinkRequest(AuditContext audit, TenantContext tenant, string? reason = null)
    {
        Audit = audit ?? throw new ArgumentNullException(nameof(audit));
        Tenant = tenant ?? throw new ArgumentNullException(nameof(tenant));
        Reason = reason;
    }

    /// <summary>Gets the required audit metadata.</summary>
    public AuditContext Audit { get; }

    /// <summary>Gets the explicit tenant or global scope.</summary>
    public TenantContext Tenant { get; }

    /// <summary>Gets the optional display-safe reason.</summary>
    public string? Reason { get; }
}
