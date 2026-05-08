using Ashlar.Identity.Models.Totp;

namespace Ashlar.Identity.Abstractions;

/// <summary>
/// Defines services for managing TOTP (Time-based One-Time Password) enrollment and verification.
/// </summary>
public interface ITotpService
{
    /// <summary>
    /// Starts a new TOTP enrollment for a user.
    /// </summary>
    /// <param name="userId">The ID of the user.</param>
    /// <param name="issuer">The name of the system issuing the TOTP (e.g., "Ashlar").</param>
    /// <param name="accountName">The name of the user's account (e.g., their email).</param>
    /// <returns>The enrollment data containing the secret and authenticator URI.</returns>
    /// <remarks>
    /// This method generates a new secret but does not persist it. The secret must be verified
    /// via <see cref="VerifyAndEnrollAsync"/> to be finalized.
    /// </remarks>
    Task<TotpEnrollment> StartEnrollmentAsync(Guid userId, string issuer, string accountName, CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies a TOTP code and finalizes enrollment for a user.
    /// </summary>
    /// <param name="userId">The ID of the user.</param>
    /// <param name="sharedSecret">The shared secret generated during enrollment.</param>
    /// <param name="code">The TOTP code provided by the user.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>True if verification succeeded and enrollment was finalized; otherwise, false.</returns>
    Task<bool> VerifyAndEnrollAsync(Guid userId, string sharedSecret, string code, CancellationToken cancellationToken = default);

    /// <summary>
    /// Disables TOTP for a user.
    /// </summary>
    /// <param name="userId">The ID of the user.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>True if TOTP was disabled; otherwise, false.</returns>
    Task<bool> DisableTotpAsync(Guid userId, CancellationToken cancellationToken = default);
}
