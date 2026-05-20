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
    /// <param name="userId">The user id value.</param>
    /// <param name="request">The request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result<IReadOnlyList<string>>> GenerateRecoveryCodesAsync(Guid userId, RecoveryCodeGenerationRequest? request = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all existing recovery codes for the specified user.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="reason">The reason value.</param>
    /// <param name="tenant">The tenant context value.</param>
    /// <param name="audit">The audit context value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<int> RevokeRecoveryCodesAsync(Guid userId, string? reason = null, TenantContext? tenant = null, AuditContext? audit = null, CancellationToken cancellationToken = default);
}


