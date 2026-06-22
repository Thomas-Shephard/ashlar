namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Creates and verifies MFA handshakes used to complete authentication after a primary factor succeeds.
/// </summary>
public interface IAuthenticationHandshakeService
{
    /// <summary>
    /// Creates a handshake token for the factors that must be verified before authentication can complete.
    /// </summary>
    /// <param name="request">The handshake creation details.</param>
    /// <param name="cancellationToken">A token that can cancel handshake creation.</param>
    /// <returns>The created handshake and one-time raw token. Return the token to the client once; do not log or persist this value.</returns>
    Task<Result<AuthenticationHandshakeCreated>> CreateHandshakeAsync(CreateAuthenticationHandshakeRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates that a factor challenge may be issued without consuming a factor verification attempt.
    /// </summary>
    /// <param name="request">The factor verification details.</param>
    /// <param name="cancellationToken">A token that can cancel challenge eligibility checks.</param>
    /// <returns>The current handshake when a factor challenge may be issued.</returns>
    Task<Result<AuthenticationHandshake>> BeginFactorChallengeAsync(VerifyAuthenticationHandshakeRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates and consumes a handshake verification attempt before orchestration resolves which pending factor will be completed.
    /// </summary>
    /// <param name="request">The handshake verification details.</param>
    /// <param name="cancellationToken">A token that can cancel handshake verification checks.</param>
    /// <returns>The current handshake when verification may proceed.</returns>
    Task<Result<AuthenticationHandshake>> BeginVerificationAsync(BeginAuthenticationHandshakeVerificationRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates and consumes a factor verification attempt before the factor credential is checked.
    /// </summary>
    /// <param name="request">The factor verification details.</param>
    /// <param name="cancellationToken">A token that can cancel factor verification checks.</param>
    /// <returns>The current handshake when verification may proceed.</returns>
    Task<Result<AuthenticationHandshake>> BeginFactorVerificationAsync(VerifyAuthenticationHandshakeRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a handshake so it can no longer complete authentication.
    /// </summary>
    /// <param name="handshakeToken">The raw handshake token presented by the client. Do not log or persist this value.</param>
    /// <param name="context">Optional authentication request context for auditing.</param>
    /// <param name="cancellationToken">A token that can cancel handshake revocation.</param>
    /// <returns>A result describing whether the handshake was revoked.</returns>
    Task<Result> RevokeHandshakeAsync(string? handshakeToken, AuthenticationContext? context = null, CancellationToken cancellationToken = default);
}
