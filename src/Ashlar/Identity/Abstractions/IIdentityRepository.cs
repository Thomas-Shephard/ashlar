using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

public interface IIdentityRepository
{
    Task<IUser?> GetUserByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default);
    Task<IUser?> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a specific credential for a user.
    /// </summary>
    /// <remarks>
    /// SECURITY: Implementations MUST verify that the returned credential belongs to the specified <paramref name="userId"/>.
    /// If the credential exists but is linked to a different user, this method MUST return null.
    /// </remarks>
    Task<UserCredential?> GetCredentialForUserAsync(Guid userId, ProviderType type, string providerName, string? providerKey = null, CancellationToken cancellationToken = default);

    Task<IUser?> GetUserByProviderKeyAsync(ProviderType type, string providerName, string providerKey, CancellationToken cancellationToken = default);

    Task CreateUserAsync(IUser user, CancellationToken cancellationToken = default);
    Task UpdateUserAsync(IUser user, CancellationToken cancellationToken = default);
    Task CreateCredentialAsync(UserCredential credential, CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically creates a credential or replaces the existing credential with the same provider identity.
    /// </summary>
    Task CreateOrReplaceCredentialAsync(UserCredential credential, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates a credential only if it still matches the version read by the caller.
    /// </summary>
    /// <param name="expectedVersion">
    /// The version value read with the credential. Implementations MUST compare this value atomically with
    /// the stored credential version and MUST NOT bypass the version check.
    /// </param>
    /// <returns>
    /// <c>true</c> when the credential was updated by this call; <c>false</c> when it was missing,
    /// already changed, consumed, or otherwise did not match <paramref name="expectedVersion"/>.
    /// </returns>
    Task<bool> UpdateCredentialAsync(UserCredential credential, string expectedVersion, CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically consumes a credential only if it still matches the version read by the caller.
    /// </summary>
    /// <param name="expectedVersion">
    /// The version value read with the credential. Implementations MUST compare this value atomically with
    /// the stored credential version and MUST NOT treat it as optional.
    /// </param>
    /// <returns>
    /// <c>true</c> when the credential was consumed by this call; <c>false</c> when it was missing,
    /// already consumed, changed, or otherwise did not match <paramref name="expectedVersion"/>.
    /// </returns>
    Task<bool> ConsumeCredentialAsync(Guid credentialId, string expectedVersion, CancellationToken cancellationToken = default);
}
