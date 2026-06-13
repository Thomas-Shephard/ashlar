namespace Ashlar.Identity.Providers.External;

/// <summary>
/// Represents authentication data supplied by an external identity provider.
/// </summary>
public sealed record ExternalIdentityAssertion : ICredentialKeyAuthenticationAssertion
{
    /// <summary>
    /// Creates an assertion for an identity already validated by an external provider.
    /// </summary>
    /// <param name="type">External provider family, such as OIDC, OAuth, or SAML2.</param>
    /// <param name="providerName">Configured external provider name.</param>
    /// <param name="providerKey">Stable subject identifier from the external provider.</param>
    /// <param name="claims">Claims from the already-validated external identity.</param>
    public ExternalIdentityAssertion(ProviderType type, string providerName, string providerKey, IReadOnlyDictionary<string, IReadOnlyList<string>> claims)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerKey);
        ArgumentNullException.ThrowIfNull(claims);

        ProviderKey = providerKey.Trim();
        Claims = AuthenticationClaims.Copy(claims);
        ProviderIdentity = new AuthenticationProviderKey(type, providerName);
    }

    /// <summary>
    /// Creates an assertion from single-value external identity claims.
    /// </summary>
    /// <param name="type">External provider family, such as OIDC, OAuth, or SAML2.</param>
    /// <param name="providerName">Configured external provider name.</param>
    /// <param name="providerKey">Stable subject identifier from the external provider.</param>
    /// <param name="claims">Claims from the already-validated external identity.</param>
    public ExternalIdentityAssertion(ProviderType type, string providerName, string providerKey, IDictionary<string, string> claims)
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
