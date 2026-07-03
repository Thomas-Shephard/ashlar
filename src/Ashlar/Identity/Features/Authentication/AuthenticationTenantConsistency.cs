namespace Ashlar.Identity.Features.Authentication;

internal static class AuthenticationTenantConsistency
{
    public static bool Matches(AuthenticationContext context, IUser user)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(user);

        var userTenantId = user is ITenantUser tenantUser ? tenantUser.TenantId : null;
        return context.TenantId == userTenantId;
    }
}
