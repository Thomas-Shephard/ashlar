using Ashlar.Identity.Models.Passkeys;
using Ashlar.Identity.Passkeys;

namespace Ashlar.Tests.Passkeys;

internal sealed class RepositoryPasskeyPersistence(
    IUserRepository users,
    ICredentialRepository credentials,
    IPasskeyChallengeRepository challenges,
    string providerName) : IPasskeyCredentialStore, IPasskeyChallengeStore
{
    public Task<IUser?> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken = default) => users.GetUserByIdAsync(userId, cancellationToken);
    public Task<IUser?> GetUserByPasskeyAsync(string credentialId, CancellationToken cancellationToken = default) => users.GetUserByProviderKeyAsync(ProviderType.Passkey, providerName, credentialId, cancellationToken);
    public async Task<IReadOnlyList<UserCredential>> ListPasskeysAsync(Guid userId, CancellationToken cancellationToken = default) =>
        (await credentials.ListCredentialsForUserAsync(userId, cancellationToken: cancellationToken)).Where(credential => credential.ProviderType == ProviderType.Passkey && string.Equals(credential.ProviderName, providerName, StringComparison.OrdinalIgnoreCase)).ToArray();
    public Task<UserCredential?> GetPasskeyAsync(Guid userId, string credentialId, CancellationToken cancellationToken = default) => credentials.GetCredentialForUserAsync(userId, ProviderType.Passkey, providerName, credentialId, cancellationToken);
    public Task CreatePasskeyAsync(UserCredential credential, CancellationToken cancellationToken = default) => credentials.CreateOrReplaceCredentialAsync(credential, cancellationToken);
    public Task<bool> UpdatePasskeyAsync(UserCredential credential, string expectedVersion, CancellationToken cancellationToken = default) => credentials.UpdateCredentialAsync(credential, expectedVersion, cancellationToken);
    public Task CreateAsync(PasskeyChallenge challenge, CancellationToken cancellationToken = default) => challenges.CreateAsync(challenge, cancellationToken);
    public Task<PasskeyChallenge?> GetAsync(Guid id, CancellationToken cancellationToken = default) => challenges.GetAsync(id, cancellationToken);
    public Task<bool> ConsumeAsync(Guid id, string expectedVersion, DateTimeOffset consumedAt, CancellationToken cancellationToken = default) => challenges.ConsumeAsync(id, expectedVersion, consumedAt, cancellationToken);
}
