using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;

namespace Ashlar.Identity.Providers;

/// <summary>
/// Represents an identity assertion from an external provider (OIDC, SAML, etc.)
/// </summary>
public sealed record ExternalIdentityAssertion(ProviderType Type, string ProviderName, string ProviderKey, IDictionary<string, string> Claims) : IAuthenticationAssertion
{
    public ProviderType ProviderType => Type;
}
