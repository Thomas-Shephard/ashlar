namespace Ashlar.Identity.Features.Services;

internal sealed class UserProfileService(IUserRepository users) : IUserProfileService
{
    public async Task<UserProfile?> GetAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var user = await users.GetUserByIdAsync(userId, cancellationToken).ConfigureAwait(false);
        return user is null ? null : new(user.Id, user.DisplayEmail, user.Name);
    }

    public async Task<Result<UserProfile>> UpdateNameAsync(Guid userId, string? name, CancellationToken cancellationToken = default)
    {
        if (name?.Length > 100) return Result.Failure<UserProfile>(AshlarFailureCodes.ValidationError, "Name is too long.");
        if (await users.GetUserByIdAsync(userId, cancellationToken).ConfigureAwait(false) is not AshlarUser user)
            return Result.Failure<UserProfile>(AshlarFailureCodes.UserNotFound, "User not found.");
        var updated = user with { Name = name };
        await users.UpdateUserAsync(updated, cancellationToken).ConfigureAwait(false);
        return Result.Success(new UserProfile(updated.Id, updated.DisplayEmail, updated.Name));
    }
}
