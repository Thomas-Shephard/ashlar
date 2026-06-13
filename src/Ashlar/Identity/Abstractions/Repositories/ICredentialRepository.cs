namespace Ashlar.Identity.Abstractions.Repositories;

/// <summary>
/// Stores credential records used by authentication providers.
/// </summary>
public interface ICredentialRepository
{
    /// <summary>
    /// Retrieves one credential for a user and provider.
    /// </summary>
    /// <param name="userId">The user that must own the credential.</param>
    /// <param name="type">The provider category.</param>
    /// <param name="providerName">The provider name within the category.</param>
    /// <param name="providerKey">The optional provider-specific credential key.</param>
    /// <param name="cancellationToken">A token that can cancel credential lookup.</param>
    /// <returns>The matching credential, or <see langword="null" /> when no matching credential belongs to the user.</returns>
    /// <remarks>
    /// Implementations must verify ownership by <paramref name="userId" />. If a matching provider key belongs to a different
    /// user, this method must return <see langword="null" />.
    /// </remarks>
    Task<UserCredential?> GetCredentialForUserAsync(Guid userId, ProviderType type, string providerName, string? providerKey = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists credentials for a user.
    /// </summary>
    /// <param name="userId">The user that owns the credentials.</param>
    /// <param name="activeOnly">When <see langword="true" />, excludes consumed or revoked credentials.</param>
    /// <param name="cancellationToken">A token that can cancel credential listing.</param>
    /// <returns>The user's credentials. Stored credential values must not be included in list results.</returns>
    Task<IReadOnlyList<UserCredential>> ListCredentialsForUserAsync(Guid userId, bool activeOnly = true, CancellationToken cancellationToken = default);

    /// <summary>
    /// Persists a new credential.
    /// </summary>
    /// <param name="credential">The credential to create.</param>
    /// <param name="cancellationToken">A token that can cancel credential creation.</param>
    Task CreateCredentialAsync(UserCredential credential, CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically creates a credential or replaces the existing credential with the same provider identity.
    /// </summary>
    /// <param name="credential">The credential to create or replace.</param>
    /// <param name="cancellationToken">A token that can cancel credential replacement.</param>
    /// <exception cref="CredentialProviderKeyConflictException">
    /// The credential provider key is already linked to a different user.
    /// </exception>
    Task CreateOrReplaceCredentialAsync(UserCredential credential, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates a credential only if it still matches the version read by the caller.
    /// </summary>
    /// <param name="credential">The credential state to save.</param>
    /// <param name="expectedVersion">The version observed before the update was prepared.</param>
    /// <param name="cancellationToken">A token that can cancel credential update.</param>
    /// <returns>
    /// <see langword="true" /> when the credential was updated; otherwise, <see langword="false" /> when it was missing,
    /// already changed, consumed, or otherwise did not match <paramref name="expectedVersion" />.
    /// </returns>
    Task<bool> UpdateCredentialAsync(UserCredential credential, string expectedVersion, CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically consumes a credential only if it still matches the version read by the caller.
    /// </summary>
    /// <param name="credentialId">Identifier of the credential to consume.</param>
    /// <param name="expectedVersion">The version observed before the consume attempt.</param>
    /// <param name="cancellationToken">A token that can cancel credential consumption.</param>
    /// <returns>
    /// <see langword="true" /> when the credential was consumed; otherwise, <see langword="false" /> when it was missing,
    /// already consumed, changed, or otherwise did not match <paramref name="expectedVersion" />.
    /// </returns>
    Task<bool> ConsumeCredentialAsync(Guid credentialId, string expectedVersion, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all active credentials for a user and provider.
    /// </summary>
    /// <param name="userId">The user that owns the credentials.</param>
    /// <param name="type">The provider category.</param>
    /// <param name="providerName">The provider name within the category.</param>
    /// <param name="cancellationToken">A token that can cancel credential revocation.</param>
    /// <returns>The number of credentials revoked.</returns>
    Task<int> RevokeCredentialsAsync(Guid userId, ProviderType type, string providerName, CancellationToken cancellationToken = default);
}
