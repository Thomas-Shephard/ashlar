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

    /// <summary>
    /// Retrieves all credentials for a specific user.
    /// </summary>
    Task<IEnumerable<UserCredential>> GetCredentialsForUserAsync(Guid userId, CancellationToken cancellationToken = default);

    Task<IUser?> GetUserByProviderKeyAsync(ProviderType type, string providerName, string providerKey, CancellationToken cancellationToken = default);

    Task CreateUserAsync(IUser user, CancellationToken cancellationToken = default);
    Task UpdateUserAsync(IUser user, CancellationToken cancellationToken = default);
    Task CreateCredentialAsync(UserCredential credential, CancellationToken cancellationToken = default);
    Task UpdateCredentialAsync(UserCredential credential, CancellationToken cancellationToken = default);

    /// <summary>
    /// Permanently deletes a credential identified by its unique identifier.
    /// </summary>
    /// <param name="credentialId">The unique identifier of the credential to delete.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the delete operation.</param>
    Task DeleteCredentialAsync(Guid credentialId, CancellationToken cancellationToken = default);
}
