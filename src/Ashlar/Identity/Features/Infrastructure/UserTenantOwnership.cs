namespace Ashlar.Identity.Features.Infrastructure;

/// <summary>
/// Provides tenant ownership checks for user-bound security operations.
/// </summary>
public static class UserTenantOwnership
{
    /// <summary>
    /// Gets whether the user belongs to the requested tenant boundary. A <see langword="null" /> tenant id matches global users only.
    /// </summary>
    /// <param name="user">The user to check.</param>
    /// <param name="tenantId">The requested tenant id, or <see langword="null" /> for global scope.</param>
    /// <returns><see langword="true" /> when the user belongs to the requested scope.</returns>
    public static bool Matches(IUser user, Guid? tenantId)
    {
        ArgumentNullException.ThrowIfNull(user);

        var userTenantId = user is ITenantUser tenantUser ? tenantUser.TenantId : null;
        return userTenantId == tenantId;
    }
}
