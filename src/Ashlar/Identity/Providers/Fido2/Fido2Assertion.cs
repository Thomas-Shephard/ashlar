using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;

namespace Ashlar.Identity.Providers.Fido2;

public sealed record Fido2Assertion(
    byte[] CredentialId,
    byte[] Challenge,
    byte[] AuthenticatorData,
    byte[] ClientDataJson,
    byte[] Signature,
    byte[] UserHandle,
    bool UserVerified) : IAuthenticationAssertion
{
    public ProviderType ProviderType => ProviderType.Fido2;
}
