namespace Ashlar.Identity.Passkeys;

internal interface IPasskeyCredentialStore
{
    Task<IUser?> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken = default);
    Task<IUser?> GetUserByPasskeyAsync(string credentialId, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<UserCredential>> ListCredentialsAsync(Guid userId, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<UserCredential>> ListPasskeysAsync(Guid userId, CancellationToken cancellationToken = default);
    Task<UserCredential?> GetPasskeyAsync(Guid userId, string credentialId, CancellationToken cancellationToken = default);
    Task CreatePasskeyAsync(UserCredential credential, CancellationToken cancellationToken = default);
    Task<bool> UpdatePasskeyAsync(UserCredential credential, string expectedVersion, CancellationToken cancellationToken = default);
}
