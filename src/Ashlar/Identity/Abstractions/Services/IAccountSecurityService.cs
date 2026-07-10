namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Provides non-secret account security posture reads.
/// </summary>
public interface IAccountSecurityService
{
    /// <summary>
    /// Returns a non-secret account-security posture summary for a user account.
    /// </summary>
    /// <param name="userId">The user account whose posture should be returned.</param>
    /// <param name="request">Tenant scope and recent-event window options for the lookup.</param>
    /// <param name="cancellationToken">A token that can cancel posture lookup.</param>
    /// <returns>The non-secret posture summary or a lookup failure.</returns>
    Task<Result<AccountSecurityPosture>> GetUserSecurityPostureAsync(Guid userId, AccountSecurityPostureRequest? request = null, CancellationToken cancellationToken = default);
}
