using Microsoft.Extensions.Options;
using Ashlar.Passkeys;

namespace Ashlar.Identity.Passkeys;

internal sealed class PasskeyCredentialStore(IUserRepository users, ICredentialRepository credentials, IOptions<PasskeyOptions> options) : IPasskeyCredentialStore, IPasskeyCredentialLookup
{
    private readonly string _providerName = options.Value.ProviderKey.Name;

    public async Task<bool> IsCredentialRegisteredAsync(string credentialId, CancellationToken cancellationToken = default) =>
        await GetUserByPasskeyAsync(credentialId, cancellationToken) is not null;

    public Task<IUser?> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken = default) =>
        users.GetUserByIdAsync(userId, cancellationToken);

    public Task<IUser?> GetUserByPasskeyAsync(string credentialId, CancellationToken cancellationToken = default) =>
        users.GetUserByProviderKeyAsync(ProviderType.Passkey, _providerName, credentialId, cancellationToken);

    public async Task<IReadOnlyList<UserCredential>> ListPasskeysAsync(Guid userId, CancellationToken cancellationToken = default) =>
        (await credentials.ListCredentialsForUserAsync(userId, cancellationToken: cancellationToken))
            .Where(credential => credential.ProviderType == ProviderType.Passkey && string.Equals(credential.ProviderName, _providerName, StringComparison.OrdinalIgnoreCase))
            .ToArray();

    public Task<UserCredential?> GetPasskeyAsync(Guid userId, string credentialId, CancellationToken cancellationToken = default) =>
        credentials.GetCredentialForUserAsync(userId, ProviderType.Passkey, _providerName, credentialId, cancellationToken);

    public Task CreatePasskeyAsync(UserCredential credential, CancellationToken cancellationToken = default) =>
        credentials.CreateOrReplaceCredentialAsync(credential, cancellationToken);

    public Task<bool> UpdatePasskeyAsync(UserCredential credential, string expectedVersion, CancellationToken cancellationToken = default) =>
        credentials.UpdateCredentialAsync(credential, expectedVersion, cancellationToken);
}
