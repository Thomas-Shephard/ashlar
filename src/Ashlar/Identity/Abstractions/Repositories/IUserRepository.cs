namespace Ashlar.Identity.Abstractions.Repositories;

/// <summary>
/// Provider contract for storing and retrieving Ashlar users.
/// </summary>
public interface IUserRepository : IUserLookup
{
    /// <summary>
    /// Persists a new user.
    /// </summary>
    /// <param name="user">The user to create. <see cref="IUser.DisplayEmail" /> is the sanitized display/delivery address; repositories store a separate normalized form for lookup and uniqueness when their schema supports it.</param>
    /// <param name="cancellationToken">A token that can cancel user creation.</param>
    Task CreateUserAsync(IUser user, CancellationToken cancellationToken = default);

    /// <summary>
    /// Persists updates to an existing user.
    /// </summary>
    /// <param name="user">The user state to save. <see cref="IUser.DisplayEmail" /> remains the sanitized display/delivery address while lookup indexes use its normalized form.</param>
    /// <param name="cancellationToken">A token that can cancel user updates.</param>
    Task UpdateUserAsync(IUser user, CancellationToken cancellationToken = default);
}
