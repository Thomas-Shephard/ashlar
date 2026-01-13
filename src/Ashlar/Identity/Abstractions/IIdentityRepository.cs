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
    /// Retrieves all credentials for a user.
    /// </summary>
    Task<IReadOnlyList<UserCredential>> GetCredentialsForUserAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves all credentials of a specific type for a user.
    /// </summary>
    Task<IReadOnlyList<UserCredential>> GetCredentialsForUserAsync(Guid userId, ProviderType type, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if a user has any credentials of the specified type.
    /// </summary>
    Task<bool> HasCredentialAsync(Guid userId, ProviderType type, CancellationToken cancellationToken = default);

    Task<IUser?> GetUserByProviderKeyAsync(ProviderType type, string providerName, string providerKey, CancellationToken cancellationToken = default);

    Task CreateUserAsync(IUser user, CancellationToken cancellationToken = default);
    Task UpdateUserAsync(IUser user, CancellationToken cancellationToken = default);
    Task CreateCredentialAsync(UserCredential credential, CancellationToken cancellationToken = default);
    Task UpdateCredentialAsync(UserCredential credential, CancellationToken cancellationToken = default);
    Task DeleteCredentialAsync(Guid credentialId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies and immediately deletes a credential to prevent replay (e.g. for one-time recovery codes).
    /// </summary>
    Task<bool> ConsumeCredentialAsync(Guid credentialId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Stores a cryptographically secure challenge for a limited time.
    /// </summary>
    Task StoreChallengeAsync(byte[] challenge, Guid? userId, DateTimeOffset expiresAt, CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies and immediately deletes a challenge to prevent replay.
    /// </summary>
    Task<bool> ConsumeChallengeAsync(byte[] challenge, Guid? userId, CancellationToken cancellationToken = default);
}
