using Ashlar.Auditing;

namespace Ashlar.Identity.Providers.RecoveryCode;

/// <summary>
/// Defines services for managing user recovery codes.
/// </summary>
public interface IRecoveryCodeService
{
    /// <summary>
    /// Generates a new set of recovery codes for the specified user.
    /// </summary>
    /// <param name="userId">User receiving the new recovery-code set.</param>
    /// <param name="request">Generation options, tenant scope, and audit context for the operation.</param>
    /// <param name="cancellationToken">Token for aborting generation and persistence work.</param>
    /// <returns>Raw recovery codes to show once to the user. Do not log or persist these values outside Ashlar's hashed credentials.</returns>
    Task<Result<IReadOnlyList<string>>> GenerateRecoveryCodesAsync(Guid userId, RecoveryCodeGenerationRequest? request = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all existing recovery codes for the specified user.
    /// </summary>
    /// <param name="userId">User whose recovery codes should be revoked.</param>
    /// <param name="reason">Optional provider-neutral, display-safe audit reason for revocation.</param>
    /// <param name="tenant">Tenant scope for the target user, or <see langword="null" /> to use <see cref="TenantContext.Global" />.</param>
    /// <param name="audit">Audit metadata for the revocation operation.</param>
    /// <param name="cancellationToken">Token for aborting revocation work.</param>
    /// <returns>Number of recovery-code credentials revoked.</returns>
    Task<int> RevokeRecoveryCodesAsync(Guid userId, string? reason = null, TenantContext? tenant = null, AuditContext? audit = null, CancellationToken cancellationToken = default);
}
