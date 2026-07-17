namespace Ashlar.Identity.Abstractions.Services;

/// <summary>Provides application-safe access to the current user's display profile.</summary>
public interface IUserProfileService
{
    /// <summary>Gets a user's display profile.</summary>
    /// <param name="userId">The user identifier.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The display profile, or <see langword="null"/> when the user does not exist.</returns>
    Task<UserProfile?> GetAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>Updates a user's display name.</summary>
    /// <param name="userId">The user identifier.</param>
    /// <param name="name">The new display name.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The updated display profile, or a failure result.</returns>
    Task<Result<UserProfile>> UpdateNameAsync(Guid userId, string? name, CancellationToken cancellationToken = default);
}

/// <summary>Display-safe user profile fields.</summary>
/// <param name="UserId">The user identifier.</param>
/// <param name="DisplayEmail">The display email address.</param>
/// <param name="Name">The display name.</param>
public sealed record UserProfile(Guid UserId, string DisplayEmail, string? Name);
