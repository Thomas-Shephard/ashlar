namespace Ashlar.Identity.Models.Sessions;

internal sealed record RevokeAuthenticationSessionsForUserRequest(
    Auditing.AuditContext Audit,
    TenantContext? Tenant,
    string? Reason = null,
    bool IncludeAllTenants = false,
    Guid? AuditTenantId = null)
{
    public void ThrowIfInvalid()
    {
        ArgumentNullException.ThrowIfNull(Audit);
        AdministrationScopeValidation.ThrowIfInvalidScope(Tenant, IncludeAllTenants);
    }
}
