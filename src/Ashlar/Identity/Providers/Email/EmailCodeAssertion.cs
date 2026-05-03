using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;

namespace Ashlar.Identity.Providers.Email;

public sealed record EmailCodeAssertion : IAuthenticationAssertion
{
    public EmailCodeAssertion(string code)
        : this(code, AuthenticationProviderKey.EmailCode)
    {
    }

    public EmailCodeAssertion(string code, AuthenticationProviderKey providerIdentity)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(code);

        Code = code;
        ProviderIdentity = providerIdentity;
    }

    public string Code { get; }
    public AuthenticationProviderKey ProviderIdentity { get; }
}
