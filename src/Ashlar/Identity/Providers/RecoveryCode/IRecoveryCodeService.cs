using Ashlar.Identity.Models;

namespace Ashlar.Identity;

/// <summary>
/// Defines services for managing user recovery codes.
/// </summary>
public interface IRecoveryCodeService
{
    /// <summary>
    /// Generates a new set of recovery codes for the specified user.
    /// </summary>
    /// <param name="userId">The user's ID.</param>
    /// <param name="request">The generation request. If null, default options are used.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A result containing the new recovery codes if successful.</returns>
    Task<Result<IReadOnlyList<string>>> GenerateRecoveryCodesAsync(Guid userId, RecoveryCodeGenerationRequest? request = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all existing recovery codes for the specified user.
    /// </summary>
    /// <param name="userId">The user's ID.</param>
    /// <param name="reason">An optional reason for revocation.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The number of recovery codes revoked.</returns>
    Task<int> RevokeRecoveryCodesAsync(Guid userId, string? reason = null, CancellationToken cancellationToken = default);
}
