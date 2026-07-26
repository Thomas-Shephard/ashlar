namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Provides validated-session self-service account security posture reads.
/// </summary>
public interface IAccountSecurityService
{
    /// <summary>
    /// Returns the current user's non-secret account-security posture after revalidating the supplied Ashlar session capability.
    /// </summary>
    /// <param name="session">Capability produced by successful Ashlar session validation; its user and tenant are the only permitted target.</param>
    /// <param name="recentSecurityEventWindow">Optional positive recent-event window that must fit within the UTC timestamp range.</param>
    /// <param name="cancellationToken">A token that can cancel posture lookup.</param>
    /// <returns>The non-secret posture summary or a lookup failure.</returns>
    Task<Result<AccountSecurityPosture>> GetSecurityPostureAsync(ValidatedAuthenticationSession session, TimeSpan? recentSecurityEventWindow = null, CancellationToken cancellationToken = default);
}
