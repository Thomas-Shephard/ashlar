namespace Ashlar.Identity.Providers.External;

/// <summary>
/// Represents authentication data supplied by an external identity provider.
/// </summary>
public sealed record ExternalIdentityAssertion : IAuthenticationAssertion
{
    /// <summary>
    /// Initializes a new instance of the external identity assertion class.
    /// </summary>
    /// <param name="type">The type value.</param>
    /// <param name="providerName">The provider name value.</param>
    /// <param name="providerKey">The provider key value.</param>
    /// <param name="claims">The multi-value claims value.</param>
    public ExternalIdentityAssertion(ProviderType type, string providerName, string providerKey, IReadOnlyDictionary<string, IReadOnlyList<string>> claims)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerKey);
        ArgumentNullException.ThrowIfNull(claims);

        ProviderKey = providerKey.Trim();
        Claims = AuthenticationClaims.Copy(claims);
        ProviderIdentity = new AuthenticationProviderKey(type, providerName);
    }

    /// <summary>
    /// Initializes a new instance of the external identity assertion class from single-value claims.
    /// </summary>
    /// <param name="type">The type value.</param>
    /// <param name="providerName">The provider name value.</param>
    /// <param name="providerKey">The provider key value.</param>
    /// <param name="claims">The single-value claims value.</param>
    public ExternalIdentityAssertion(ProviderType type, string providerName, string providerKey, IDictionary<string, string> claims)
        : this(type, providerName, providerKey, AuthenticationClaims.FromSingleValues(claims))
    {
    }

    /// <summary>
    /// Gets or sets the provider key value.
    /// </summary>
    public string ProviderKey { get; }

    /// <summary>
    /// Gets or sets the claims value.
    /// </summary>
    public IReadOnlyDictionary<string, IReadOnlyList<string>> Claims { get; }

    /// <summary>
    /// Gets or sets the provider identity value.
    /// </summary>
    public AuthenticationProviderKey ProviderIdentity { get; }
}
