using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

/// <summary>
/// Creates and verifies MFA handshakes used to complete authentication after a primary factor succeeds.
/// </summary>
public interface IAuthenticationHandshakeService
{
    /// <summary>
    /// Creates a handshake token for the factors that must be verified before authentication can complete.
    /// </summary>
    /// <param name="request">The handshake creation details.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The created handshake and raw token when creation succeeds.</returns>
    Task<Result<AuthenticationHandshakeCreated>> CreateHandshakeAsync(CreateAuthenticationHandshakeRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Marks one factor as verified and returns the updated handshake state.
    /// </summary>
    /// <param name="request">The factor verification details.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The updated handshake when verification succeeds.</returns>
    Task<Result<AuthenticationHandshake>> VerifyFactorAsync(VerifyAuthenticationHandshakeRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Looks up an active handshake by its raw handshake token.
    /// </summary>
    /// <param name="handshakeToken">The raw handshake token.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The matching handshake, or <see langword="null" /> when no active handshake exists.</returns>
    Task<AuthenticationHandshake?> GetHandshakeAsync(string handshakeToken, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a handshake so it can no longer complete authentication.
    /// </summary>
    /// <param name="handshakeToken">The raw handshake token.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>A result describing whether the handshake was revoked.</returns>
    Task<Result> RevokeHandshakeAsync(string handshakeToken, CancellationToken cancellationToken = default);
}
