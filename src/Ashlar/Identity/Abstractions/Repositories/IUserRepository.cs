namespace Ashlar.Identity.Abstractions.Repositories;

/// <summary>
/// Stores and retrieves Ashlar users.
/// </summary>
public interface IUserRepository
{
    /// <summary>
    /// Finds a user by normalized email address within an optional tenant boundary.
    /// </summary>
    /// <param name="email">The email address to search for.</param>
    /// <param name="tenantId">The tenant boundary for the lookup, or <see langword="null" /> for tenantless users.</param>
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
    /// <returns>The matching user, or <see langword="null" /> when no user exists.</returns>
    Task<IUser?> GetUserByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Finds a user by its stable identifier.
    /// </summary>
    /// <param name="userId">The user identifier.</param>
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
    /// <returns>The matching user, or <see langword="null" /> when no user exists.</returns>
    Task<IUser?> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Finds the user linked to a provider-specific credential key.
    /// </summary>
    /// <param name="type">The provider category.</param>
    /// <param name="providerName">The provider name within the category.</param>
    /// <param name="providerKey">The provider's stable key for the credential.</param>
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
    /// <returns>The linked user, or <see langword="null" /> when the key is not linked.</returns>
    Task<IUser?> GetUserByProviderKeyAsync(ProviderType type, string providerName, string providerKey, CancellationToken cancellationToken = default);

    /// <summary>
    /// Persists a new user.
    /// </summary>
    /// <param name="user">The user to create.</param>
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
    Task CreateUserAsync(IUser user, CancellationToken cancellationToken = default);

    /// <summary>
    /// Persists updates to an existing user.
    /// </summary>
    /// <param name="user">The user state to save.</param>
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
    Task UpdateUserAsync(IUser user, CancellationToken cancellationToken = default);
}
