namespace Ashlar.Identity.Models.Administration;

internal static class AdministrationScopeValidation
{
    public static void ThrowIfInvalidScope(TenantContext? tenant, bool includeAllTenants, object request)
    {
        if (tenant == null && !includeAllTenants)
        {
            throw new ArgumentException("Tenant scope must be explicit.", nameof(request));
        }

        if (tenant != null && includeAllTenants)
        {
            throw new ArgumentException("Tenant scope cannot be combined with all-tenant search.", nameof(request));
        }
    }

    public static bool IncludesTenant(TenantContext tenant, Guid? itemTenantId)
    {
        return tenant.TenantId == itemTenantId;
    }
}
