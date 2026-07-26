namespace Ashlar.Identity.Providers.External;

internal sealed record ExternalIdentityAssertion : ICredentialKeyAuthenticationAssertion
{
    internal ExternalIdentityAssertion(ProviderType type, string providerName, string providerKey, IReadOnlyDictionary<string, IReadOnlyList<string>> claims)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerKey);
        ArgumentNullException.ThrowIfNull(claims);

        ProviderKey = providerKey.Trim();
        Claims = AuthenticationClaims.Copy(claims);
        ProviderIdentity = new AuthenticationProviderKey(type, providerName);
    }

    internal ExternalIdentityAssertion(ProviderType type, string providerName, string providerKey, IDictionary<string, string> claims)
        : this(type, providerName, providerKey, AuthenticationClaims.FromSingleValues(claims))
    {
    }

    /// <summary>
    /// Stable external subject identifier used to resolve the stored credential.
    /// </summary>
    public string ProviderKey { get; }

    /// <inheritdoc />
    public string CredentialKey => ProviderKey;

    /// <summary>
    /// Claims supplied by the already-validated external identity.
    /// </summary>
    public IReadOnlyDictionary<string, IReadOnlyList<string>> Claims { get; }

    /// <summary>
    /// Configured external provider identity that issued the assertion.
    /// </summary>
    public AuthenticationProviderKey ProviderIdentity { get; }
}
