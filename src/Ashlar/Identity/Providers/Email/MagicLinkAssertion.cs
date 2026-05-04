using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;

namespace Ashlar.Identity.Providers.Email;

public sealed record MagicLinkAssertion : IAuthenticationAssertion
{
    public string Token { get; }
    public AuthenticationProviderKey ProviderIdentity { get; } = AuthenticationProviderKey.MagicLink;

    public MagicLinkAssertion(string token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        Token = token;
    }
}
