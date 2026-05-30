namespace Ashlar.Identity.Features.Infrastructure;

internal static class UserTenantValidator
{
    public static async Task<Result<IUser>> GetUserInTenantAsync(
        IUserRepository userRepository,
        Guid userId,
        TenantContext? tenant,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(userRepository);

        var user = await userRepository.GetUserByIdAsync(userId, cancellationToken);
        if (user == null)
        {
            return Result.Failure<IUser>(AshlarFailureCodes.UserNotFound);
        }

        return UserTenantOwnership.Matches(user, tenant?.TenantId)
            ? Result.Success(user)
            : Result.Failure<IUser>(AshlarFailureCodes.TenantMismatch);
    }
}
