using Ashlar.Identity.Models.Totp;

namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Defines services for managing TOTP (Time-based One-Time Password) enrollment and verification.
/// </summary>
public interface ITotpService
{
    /// <summary>
    /// Starts self-service TOTP enrollment for the authenticated account owner.
    /// </summary>
    /// <param name="request">Target user identity, fresh verification proof, current session id, tenant scope, audit context, and authenticator labels for the enrollment.</param>
    /// <param name="cancellationToken">A token that can cancel enrollment setup.</param>
    /// <returns>The shared secret and otpauth URI to show once to the user.</returns>
    /// <remarks>
    /// This self-service method derives the target account from
    /// <see cref="StartTotpEnrollmentRequest.ActorUserId" />. Hosts must pass the authenticated
    /// session owner, not a route or body value controlled by the client. Hosts must obtain
    /// <see cref="FreshPrimaryAuthenticationProof" /> only when the account has no usable additional-verification
    /// factor yet, or <see cref="FreshMfaVerificationProof" /> when any usable MFA or step-up factor already exists.
    /// The proof must match the same user, tenant, and current session id. The method keeps tenant
    /// checks, requires host authorization through <see cref="IAccountSecurityOperationAuthorizer" />, and returns secret material only for an accepted owner. The secret must be verified via
    /// <see cref="CompleteEnrollmentAsync"/> to be finalized.
    /// </remarks>
    Task<TotpEnrollment> StartEnrollmentAsync(StartTotpEnrollmentRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies a TOTP code and finalizes self-service enrollment for the authenticated account owner.
    /// </summary>
    /// <param name="request">Target user identity, fresh verification proof, current session id, secret, code, tenant scope, and audit context for enrollment completion.</param>
    /// <param name="cancellationToken">A token that can cancel verification.</param>
    /// <returns>A result containing an Ashlar-verified step-up completion result when self-service enrollment succeeds.</returns>
    /// <remarks>
    /// This self-service method derives the target account from
    /// <see cref="VerifyTotpEnrollmentRequest.ActorUserId" /> and mutates only when the tenant check succeeds and proof
    /// matches the same user, tenant, and session and the host authorizes the complete operation. Initial enrollment accepts fresh primary-authentication proof only
    /// while the account has no usable additional-verification factor; adding or replacing TOTP after any usable MFA
    /// factor exists requires fresh MFA proof. Rejected attempts are audited without recording the shared secret or TOTP code.
    /// </remarks>
    Task<Result<TotpEnrollmentCompletionResult>> CompleteEnrollmentAsync(VerifyTotpEnrollmentRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Disables TOTP for the authenticated account owner.
    /// </summary>
    /// <param name="request">Target user identity, fresh MFA proof, current session id, tenant scope, and audit context for the disable attempt.</param>
    /// <param name="cancellationToken">A token that can cancel the update.</param>
    /// <returns><see langword="true" /> when an active TOTP credential was disabled.</returns>
    /// <remarks>
    /// This is a self-service API requiring Ashlar-issued fresh MFA proof, not an admin reset primitive. Hosts must use explicit recovery or
    /// administration services for recovery/admin MFA resets. The required host authorizer and tenant checks run before
    /// credentials are revoked and are recorded as security events.
    /// </remarks>
    Task<bool> DisableAsync(DisableTotpRequest request, CancellationToken cancellationToken = default);
}
