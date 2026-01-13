using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;

namespace Ashlar.Identity.Providers.Totp;

public sealed record TotpAssertion(string Code) : IAuthenticationAssertion
{
    public ProviderType ProviderType => ProviderType.Totp;
}
