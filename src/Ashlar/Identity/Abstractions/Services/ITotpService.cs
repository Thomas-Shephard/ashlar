using Ashlar.Auditing;
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
    /// <param name="userId">The user that will own the TOTP credential.</param>
    /// <param name="issuer">Issuer label shown by authenticator applications.</param>
    /// <param name="accountName">Account label shown by authenticator applications.</param>
    /// <param name="tenant">Tenant scope for the enrollment, or global scope when omitted.</param>
    /// <param name="audit">Audit context to include in emitted security events.</param>
    /// <param name="cancellationToken">A token that can cancel enrollment setup.</param>
    /// <returns>The shared secret and otpauth URI to show once to the user.</returns>
    /// <remarks>
    /// This method generates a new secret but does not persist it. The secret must be verified
    /// via <see cref="VerifyAndEnrollAsync"/> to be finalized.
    /// </remarks>
    Task<TotpEnrollment> StartEnrollmentAsync(Guid userId, string issuer, string accountName, TenantContext? tenant = null, AuditContext? audit = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies a TOTP code and finalizes enrollment for a user.
    /// </summary>
    /// <param name="userId">The user that will own the TOTP credential.</param>
    /// <param name="sharedSecret">The raw shared secret from enrollment setup. Do not log this value.</param>
    /// <param name="code">The TOTP code supplied by the user. Do not log this value.</param>
    /// <param name="tenant">Tenant scope for the enrollment, or global scope when omitted.</param>
    /// <param name="audit">Audit context to include in emitted security events.</param>
    /// <param name="cancellationToken">A token that can cancel verification.</param>
    /// <returns>A result indicating whether the credential was enrolled.</returns>
    Task<Result> VerifyAndEnrollAsync(Guid userId, string sharedSecret, string code, TenantContext? tenant = null, AuditContext? audit = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Disables TOTP for a user.
    /// </summary>
    /// <param name="userId">The user whose TOTP credential should be disabled.</param>
    /// <param name="tenant">Tenant scope for the credential, or global scope when omitted.</param>
    /// <param name="audit">Audit context to include in emitted security events.</param>
    /// <param name="cancellationToken">A token that can cancel the update.</param>
    /// <returns><see langword="true" /> when an active TOTP credential was disabled.</returns>
    Task<bool> DisableTotpAsync(Guid userId, TenantContext? tenant = null, AuditContext? audit = null, CancellationToken cancellationToken = default);
}
