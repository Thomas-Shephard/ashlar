namespace Ashlar.Identity.Features.Services;

internal sealed class UserProfileService(
    IUserRepository users,
    IAuthenticationSessionRepository sessions,
    TimeProvider timeProvider) : IUserProfileService
{
    public async Task<Result<UserProfile>> GetAsync(ValidatedAuthenticationSession session, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        if (!await IsActiveAsync(session, cancellationToken).ConfigureAwait(false))
            return Result.Failure<UserProfile>(AshlarFailureCodes.SessionNotFoundOrInactive);
        var user = await users.GetUserByIdAsync(session.UserId, cancellationToken).ConfigureAwait(false);
        if (user == null || !user.CanSignIn())
            return Result.Failure<UserProfile>(AshlarFailureCodes.UserNotFoundOrUnavailable);
        return UserTenantOwnership.Matches(user, session.TenantId)
            ? Result.Success(new UserProfile(user.Id, user.DisplayEmail, user.Name))
            : Result.Failure<UserProfile>(AshlarFailureCodes.TenantMismatch);
    }

    public async Task<Result<UserProfile>> UpdateNameAsync(UpdateCurrentUserProfileRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Session);
        ArgumentNullException.ThrowIfNull(request.Audit);
        if (request.Audit.ActorUserId != request.Session.UserId)
            return Result.Failure<UserProfile>(AshlarFailureCodes.ValidationError, "Audit actor must match the validated session user.");
        if (!await IsActiveAsync(request.Session, cancellationToken).ConfigureAwait(false))
            return Result.Failure<UserProfile>(AshlarFailureCodes.SessionNotFoundOrInactive);
        if (request.Name?.Length > 100) return Result.Failure<UserProfile>(AshlarFailureCodes.ValidationError, "Name is too long.");
        if (await users.GetUserByIdAsync(request.Session.UserId, cancellationToken).ConfigureAwait(false) is not AshlarUser user)
            return Result.Failure<UserProfile>(AshlarFailureCodes.UserNotFoundOrUnavailable);
        if (!user.CanSignIn())
            return Result.Failure<UserProfile>(AshlarFailureCodes.UserNotFoundOrUnavailable);
        if (!UserTenantOwnership.Matches(user, request.Session.TenantId))
            return Result.Failure<UserProfile>(AshlarFailureCodes.TenantMismatch);
        var updated = user with { Name = request.Name };
        await users.UpdateUserAsync(updated, cancellationToken).ConfigureAwait(false);
        return Result.Success(new UserProfile(updated.Id, updated.DisplayEmail, updated.Name));
    }

    private async Task<bool> IsActiveAsync(ValidatedAuthenticationSession capability, CancellationToken cancellationToken)
    {
        var session = await sessions.GetSessionAsync(capability.Id, cancellationToken).ConfigureAwait(false);
        return session is not null
            && session.Id == capability.Id
            && session.UserId == capability.UserId
            && Nullable.Equals(session.TenantId, capability.TenantId)
            && session.IsActive(timeProvider.GetUtcNow());
    }
}
