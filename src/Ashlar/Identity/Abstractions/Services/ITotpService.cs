using Ashlar.Identity.Models.Totp;

namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Defines services for managing TOTP (Time-based One-Time Password) enrollment and verification.
/// </summary>
public interface ITotpService
{
    /// <summary>
    /// Starts a new TOTP enrollment for a user.
    /// </summary>
    /// <param name="request">Caller identity, tenant scope, audit context, and authenticator labels for the enrollment.</param>
    /// <param name="cancellationToken">A token that can cancel enrollment setup.</param>
    /// <returns>The shared secret and otpauth URI to show once to the user.</returns>
    /// <remarks>
    /// This self-service method derives the target account from
    /// <see cref="StartTotpEnrollmentRequest.ActorUserId" />. Hosts must pass the authenticated
    /// session owner, not a route or body value controlled by the client. The method keeps tenant
    /// checks and returns secret material only for an accepted owner. The secret must be verified
    /// via <see cref="CompleteEnrollmentAsync"/> to be finalized.
    /// </remarks>
    Task<TotpEnrollment> StartEnrollmentAsync(StartTotpEnrollmentRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies a TOTP code and finalizes enrollment for a user.
    /// </summary>
    /// <param name="request">Caller identity, secret, code, tenant scope, and audit context for enrollment completion.</param>
    /// <param name="cancellationToken">A token that can cancel verification.</param>
    /// <returns>A result indicating whether the credential was enrolled.</returns>
    /// <remarks>
    /// This self-service method derives the target account from
    /// <see cref="VerifyTotpEnrollmentRequest.ActorUserId" /> and mutates only when the tenant check
    /// succeeds. Rejected attempts are audited without recording the shared secret or TOTP code.
    /// </remarks>
    Task<Result> CompleteEnrollmentAsync(VerifyTotpEnrollmentRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Disables TOTP for a user.
    /// </summary>
    /// <param name="request">Caller identity, tenant scope, and audit context for the disable attempt.</param>
    /// <param name="cancellationToken">A token that can cancel the update.</param>
    /// <returns><see langword="true" /> when an active TOTP credential was disabled.</returns>
    /// <remarks>
    /// This is a self-service API, not an admin reset primitive. Hosts must use explicit recovery or
    /// administration services for privileged MFA resets. Tenant failures are rejected before
    /// credentials are revoked and are recorded as security events.
    /// </remarks>
    Task<bool> DisableAsync(DisableTotpRequest request, CancellationToken cancellationToken = default);
}
