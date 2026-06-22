namespace Ashlar.Identity.Features.Handshakes;

internal interface IAuthenticationHandshakeCompletionService
{
    Task<Result<AuthenticationHandshake>> CompleteFactorVerificationAsync(VerifyAuthenticationHandshakeRequest request, CancellationToken cancellationToken = default);
}
