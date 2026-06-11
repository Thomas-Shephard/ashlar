namespace Ashlar.Identity.Models.Administration;

internal static class AdministrationScopeValidation
{
    public static void ThrowIfInvalidScope(TenantContext? tenant, bool includeAllTenants)
    {
        if (tenant == null && !includeAllTenants)
        {
            throw new ArgumentException("Tenant scope must be explicit. Set Tenant, TenantContext.Global, or IncludeAllTenants = true.", nameof(tenant));
        }

        if (tenant != null && includeAllTenants)
        {
            throw new ArgumentException("Tenant scope cannot be combined with IncludeAllTenants = true.", nameof(includeAllTenants));
        }
    }

    public static bool IncludesTenant(TenantContext tenant, Guid? itemTenantId)
    {
        return tenant.TenantId == itemTenantId;
    }
}
