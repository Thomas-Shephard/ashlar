using Ashlar.Auditing;

namespace Ashlar.Identity.Models.Sessions;

internal sealed record RevokeAuthenticationSessionRequest
{
    public required Guid SessionId { get; init; }
    public string? Reason { get; init; }
    public TenantContext? Tenant { get; init; }
    public bool IncludeAllTenants { get; init; }
    public AuditContext? Audit { get; init; }

    public void ThrowIfInvalid()
    {
        ArgumentNullException.ThrowIfNull(Audit);
        AdministrationScopeValidation.ThrowIfInvalidScope(Tenant, IncludeAllTenants);
    }
}
