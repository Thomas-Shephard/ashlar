namespace Ashlar.Identity.Features.Infrastructure;

internal static class UserTenantOwnership
{
    public static bool Matches(IUser user, Guid? tenantId)
    {
        ArgumentNullException.ThrowIfNull(user);

        var userTenantId = user is ITenantUser tenantUser ? tenantUser.TenantId : null;
        return userTenantId == tenantId;
    }
}
