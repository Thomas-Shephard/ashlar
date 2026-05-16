using Ashlar.Auditing;
using Ashlar.Identity.Models;
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
    /// <param name="userId">The user id value.</param>
    /// <param name="issuer">The issuer value.</param>
    /// <param name="accountName">The account name value.</param>
    /// <param name="tenant">The tenant context value.</param>
    /// <param name="audit">The audit context value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    /// <remarks>
    /// This method generates a new secret but does not persist it. The secret must be verified
    /// via <see cref="VerifyAndEnrollAsync"/> to be finalized.
    /// </remarks>
    Task<TotpEnrollment> StartEnrollmentAsync(Guid userId, string issuer, string accountName, TenantContext? tenant = null, AuditContext? audit = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies a TOTP code and finalizes enrollment for a user.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="sharedSecret">The shared secret value.</param>
    /// <param name="code">The code value.</param>
    /// <param name="tenant">The tenant context value.</param>
    /// <param name="audit">The audit context value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result> VerifyAndEnrollAsync(Guid userId, string sharedSecret, string code, TenantContext? tenant = null, AuditContext? audit = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Disables TOTP for a user.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="tenant">The tenant context value.</param>
    /// <param name="audit">The audit context value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<bool> DisableTotpAsync(Guid userId, TenantContext? tenant = null, AuditContext? audit = null, CancellationToken cancellationToken = default);
}
