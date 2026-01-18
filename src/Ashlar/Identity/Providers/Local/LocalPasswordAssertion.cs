using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;

namespace Ashlar.Identity.Providers.Local;

public sealed record LocalPasswordAssertion(string Password) : IAuthenticationAssertion
{
    public ProviderType ProviderType => ProviderType.Local;
}
