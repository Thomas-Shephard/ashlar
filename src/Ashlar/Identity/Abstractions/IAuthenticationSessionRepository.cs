using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

/// <summary>
/// Stores and retrieves durable authentication sessions.
/// </summary>
public interface IAuthenticationSessionRepository
{
    /// <summary>
    /// Persists a new authentication session.
    /// </summary>
    /// <remarks>
    /// <see cref="AuthenticationSession.TokenHash"/> must contain a deterministic hash of the raw session token.
    /// Implementations must not persist raw session tokens.
    /// </remarks>
    /// <param name="session">The session to persist.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    Task CreateSessionAsync(AuthenticationSession session, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a session by its deterministic token hash.
    /// </summary>
    /// <remarks>
    /// This method may return revoked or expired sessions. Callers should evaluate
    /// <see cref="AuthenticationSession.IsActive(DateTimeOffset)"/> against their current clock when active-only behavior is required.
    /// </remarks>
    /// <param name="tokenHash">The deterministic hash of the raw session token.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The matching session, or <c>null</c> when no session exists for the token hash.</returns>
    Task<AuthenticationSession?> GetSessionByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates the time a session was last observed.
    /// </summary>
    /// <remarks>
    /// Implementations should avoid moving <see cref="AuthenticationSession.LastSeenAt"/> backwards when an older timestamp
    /// races with a newer update.
    /// </remarks>
    /// <param name="sessionId">The identifier of the session to update.</param>
    /// <param name="lastSeenAt">The timestamp to store as the session's last-seen time.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns><c>true</c> when the session was updated; otherwise <c>false</c> when the session does not exist or the update was stale.</returns>
    Task<bool> UpdateSessionLastSeenAsync(Guid sessionId, DateTimeOffset lastSeenAt, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a single authentication session.
    /// </summary>
    /// <remarks>
    /// Implementations should preserve the first revocation timestamp and reason when a session is revoked more than once.
    /// </remarks>
    /// <param name="sessionId">The identifier of the session to revoke.</param>
    /// <param name="revokedAt">The timestamp to store as the revocation time.</param>
    /// <param name="reason">An optional provider-neutral reason for revocation.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns><c>true</c> when the session was revoked; otherwise <c>false</c> when the session does not exist or was already revoked.</returns>
    Task<bool> RevokeSessionAsync(Guid sessionId, DateTimeOffset revokedAt, string? reason = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all currently unrevoked sessions for a user.
    /// </summary>
    /// <remarks>
    /// Implementations should not overwrite revocation data for sessions that were already revoked.
    /// </remarks>
    /// <param name="userId">The identifier of the user whose sessions should be revoked.</param>
    /// <param name="revokedAt">The timestamp to store as the revocation time.</param>
    /// <param name="reason">An optional provider-neutral reason for revocation.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The number of sessions revoked by this call.</returns>
    Task<int> RevokeSessionsForUserAsync(Guid userId, DateTimeOffset revokedAt, string? reason = null, CancellationToken cancellationToken = default);
}
