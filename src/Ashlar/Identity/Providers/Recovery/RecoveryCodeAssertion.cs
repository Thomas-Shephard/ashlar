using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;

namespace Ashlar.Identity.Providers.Recovery;

public sealed record RecoveryCodeAssertion(string Code) : IAuthenticationAssertion
{
    public ProviderType ProviderType => ProviderType.RecoveryCode;
}
