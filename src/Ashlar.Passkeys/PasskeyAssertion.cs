namespace Ashlar.Passkeys;

/// <summary>
/// Represents a verified passkey assertion for Ashlar authentication providers.
/// </summary>
/// <param name="CredentialId">The WebAuthn credential id.</param>
/// <param name="SignCount">The signature counter.</param>
/// <param name="UserVerified">Whether user verification was performed. Passkey factor verification requires this to be <see langword="true" />.</param>
/// <param name="ProviderKey">The optional provider key override.</param>
public sealed record PasskeyAssertion(string CredentialId, long SignCount, bool UserVerified = false, AuthenticationProviderKey? ProviderKey = null) : ICredentialKeyAuthenticationAssertion, IUserVerifiedAuthenticationAssertion
{
    /// <summary>
    /// Gets the authentication provider identity.
    /// </summary>
    public AuthenticationProviderKey ProviderIdentity => ProviderKey ?? AuthenticationProviderKey.Passkey;

    /// <summary>
    /// Gets the credential lookup key.
    /// </summary>
    public string CredentialKey => CredentialId;
}
