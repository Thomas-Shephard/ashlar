
namespace Ashlar.Identity.Abstractions.Repositories;

/// <summary>
/// Defines the contract for iidentity repository operations.
/// </summary>
public interface IIdentityRepository
{
    /// <summary>
    /// Performs the get user by email <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="email">The email value.</param>
    /// <param name="tenantId">The tenant id value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<IUser?> GetUserByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default);
    /// <summary>
    /// Performs the get user by id <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<IUser?> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a specific credential for a user.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="type">The type value.</param>
    /// <param name="providerName">The provider name value.</param>
    /// <param name="providerKey">The provider key value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    /// <remarks>
    /// SECURITY: Implementations MUST verify that the returned credential belongs to the specified <paramref name="userId"/>.
    /// If the credential exists but is linked to a different user, this method MUST return <see langword="null" />.
    /// </remarks>
    Task<UserCredential?> GetCredentialForUserAsync(Guid userId, ProviderType type, string providerName, string? providerKey = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Performs the get user by provider key <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="type">The type value.</param>
    /// <param name="providerName">The provider name value.</param>
    /// <param name="providerKey">The provider key value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<IUser?> GetUserByProviderKeyAsync(ProviderType type, string providerName, string providerKey, CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists credentials for a user.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="activeOnly">The active only value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<IReadOnlyList<UserCredential>> ListCredentialsForUserAsync(Guid userId, bool activeOnly = true, CancellationToken cancellationToken = default);

    /// <summary>
    /// Performs the create user <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="user">The user value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task CreateUserAsync(IUser user, CancellationToken cancellationToken = default);
    /// <summary>
    /// Performs the update user <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="user">The user value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task UpdateUserAsync(IUser user, CancellationToken cancellationToken = default);
    /// <summary>
    /// Performs the create credential <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="credential">The credential value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task CreateCredentialAsync(UserCredential credential, CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically creates a credential or replaces the existing credential with the same provider identity.
    /// </summary>
    /// <param name="credential">The credential value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task CreateOrReplaceCredentialAsync(UserCredential credential, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates a credential only if it still matches the version read by the caller.
    /// </summary>
    /// <param name="credential">The credential value.</param>
    /// <param name="expectedVersion">The expected version value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>
    /// <see langword="true" /> when the credential was updated; otherwise, <see langword="false" /> when it was missing,
    /// already changed, consumed, or otherwise did not match <paramref name="expectedVersion" />.
    /// </returns>
    Task<bool> UpdateCredentialAsync(UserCredential credential, string expectedVersion, CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically consumes a credential only if it still matches the version read by the caller.
    /// </summary>
    /// <param name="credentialId">The credential id value.</param>
    /// <param name="expectedVersion">The expected version value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>
    /// <see langword="true" /> when the credential was consumed; otherwise, <see langword="false" /> when it was missing,
    /// already consumed, changed, or otherwise did not match <paramref name="expectedVersion" />.
    /// </returns>
    Task<bool> ConsumeCredentialAsync(Guid credentialId, string expectedVersion, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all credentials for a specific user and provider.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="type">The type value.</param>
    /// <param name="providerName">The provider name value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<int> RevokeCredentialsAsync(Guid userId, ProviderType type, string providerName, CancellationToken cancellationToken = default);
}
