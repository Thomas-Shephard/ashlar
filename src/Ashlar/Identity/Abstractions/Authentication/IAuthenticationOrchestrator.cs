namespace Ashlar.Identity.Abstractions.Authentication;

/// <summary>
/// Defines the contract for authentication orchestrator operations.
/// </summary>
public interface IAuthenticationOrchestrator
{
    /// <summary>
    /// Performs the authenticate <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="context">The context value.</param>
    /// <param name="primaryAssertion">The primary assertion value.</param>
    /// <param name="options">The options value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<MfaAuthenticationResult> AuthenticateAsync(
        AuthenticationContext context,
        IAuthenticationAssertion primaryAssertion,
        MfaOrchestrationOptions? options = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Performs the verify factor <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="handshakeToken">The handshake token value.</param>
    /// <param name="factorType">The factor type value.</param>
    /// <param name="context">The context value.</param>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<MfaAuthenticationResult> VerifyFactorAsync(
        string handshakeToken,
        string factorType,
        AuthenticationContext context,
        IAuthenticationAssertion assertion,
        CancellationToken cancellationToken = default);
}
