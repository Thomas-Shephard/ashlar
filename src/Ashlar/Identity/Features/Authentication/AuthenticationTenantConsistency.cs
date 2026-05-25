namespace Ashlar.Identity.Features.Authentication;

internal static class AuthenticationTenantConsistency
{
    public static bool Matches(AuthenticationContext context, IUser user)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(user);

        return context.TenantId switch
        {
            null => true,
            Guid tenantId => user is ITenantUser tenantUser && tenantUser.TenantId == tenantId
        };
    }
}
