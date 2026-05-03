using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;

namespace Ashlar.Identity.Providers.Email;

public sealed record MagicLinkAssertion : IAuthenticationAssertion
{
    public string Token { get; }
    public AuthenticationProviderKey ProviderIdentity { get; }

    public MagicLinkAssertion(string token, AuthenticationProviderKey? providerIdentity = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        Token = token;
        ProviderIdentity = providerIdentity ?? AuthenticationProviderKey.MagicLink;
    }
}
