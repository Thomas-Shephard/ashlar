using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;

namespace Ashlar.Identity.Providers.External;

/// <summary>
/// Represents an identity assertion from an external provider (OIDC, SAML, etc.)
/// </summary>
public sealed record ExternalIdentityAssertion : IAuthenticationAssertion
{
    public ExternalIdentityAssertion(ProviderType type, string providerName, string providerKey, IDictionary<string, string> claims)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerKey);
        ArgumentNullException.ThrowIfNull(claims);

        ProviderKey = providerKey.Trim();
        Claims = new Dictionary<string, string>(claims).AsReadOnly();
        ProviderIdentity = new AuthenticationProviderKey(type, providerName);
    }

    public string ProviderKey { get; }

    public IDictionary<string, string> Claims { get; }

    public AuthenticationProviderKey ProviderIdentity { get; }
}
