using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

public interface IAuthenticationOrchestrator
{
    Task<MfaAuthenticationResult> AuthenticateAsync(
        AuthenticationContext context,
        IAuthenticationAssertion primaryAssertion,
        MfaOrchestrationOptions? options = null,
        CancellationToken cancellationToken = default);

    Task<MfaAuthenticationResult> VerifyFactorAsync(
        string handshakeToken,
        string factorType,
        AuthenticationContext context,
        IAuthenticationAssertion assertion,
        CancellationToken cancellationToken = default);
}
