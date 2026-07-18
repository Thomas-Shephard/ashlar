namespace Ashlar.Identity.Passkeys;

/// <summary>Read-only lookup required by WebAuthn credential uniqueness validation.</summary>
public interface IPasskeyCredentialLookup
{
    /// <summary>Checks whether a passkey credential ID is already registered.</summary>
    /// <param name="credentialId">The WebAuthn credential ID.</param>
    /// <param name="cancellationToken">A token used to cancel the lookup.</param>
    /// <returns><see langword="true" /> when the credential ID is already registered.</returns>
    Task<bool> IsCredentialRegisteredAsync(string credentialId, CancellationToken cancellationToken = default);
}
