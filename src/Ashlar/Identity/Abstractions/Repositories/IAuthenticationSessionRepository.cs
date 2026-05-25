namespace Ashlar.Identity.Abstractions.Repositories;

/// <summary>
/// Stores and retrieves durable authentication sessions.
/// </summary>
public interface IAuthenticationSessionRepository
{
    /// <summary>
    /// Persists a new authentication session.
    /// </summary>
    /// <param name="session">The session value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    /// <remarks>
    /// <see cref="AuthenticationSession.TokenHash"/> must contain a deterministic hash of the raw session token.
    /// Implementations must not persist raw session tokens.
    /// </remarks>
    Task CreateSessionAsync(AuthenticationSession session, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a session by its deterministic token hash.
    /// </summary>
    /// <param name="tokenHash">The token hash value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    /// <remarks>
    /// This method may return revoked or expired sessions. Callers should evaluate
    /// <see cref="AuthenticationSession.IsActive(DateTimeOffset)"/> against their current clock when active-only behavior is required.
    /// </remarks>
    Task<AuthenticationSession?> GetSessionByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a session by its unique identifier.
    /// </summary>
    /// <param name="sessionId">The session id value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<AuthenticationSession?> GetSessionAsync(Guid sessionId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates the time a session was last observed.
    /// </summary>
    /// <param name="sessionId">The session id value.</param>
    /// <param name="lastSeenAt">The last seen at value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    /// <remarks>
    /// Implementations should avoid moving <see cref="AuthenticationSession.LastSeenAt"/> backwards when an older timestamp
    /// races with a newer update.
    /// </remarks>
    Task<bool> UpdateSessionLastSeenAsync(Guid sessionId, DateTimeOffset lastSeenAt, CancellationToken cancellationToken = default);

    /// <summary>
    /// Marks an active session as recently step-up verified if it belongs to the specified user.
    /// </summary>
    /// <param name="sessionId">The session id value.</param>
    /// <param name="userId">The user id value.</param>
    /// <param name="verifiedAt">The verification timestamp value.</param>
    /// <param name="verifiedProvider">The verified provider value.</param>
    /// <param name="verifiedFactor">The verified factor value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The updated session, or <see langword="null" /> when no active owned session was updated.</returns>
    Task<AuthenticationSession?> MarkStepUpVerifiedAsync(
        Guid sessionId,
        Guid userId,
        DateTimeOffset verifiedAt,
        AuthenticationProviderKey verifiedProvider,
        string verifiedFactor,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a single authentication session.
    /// </summary>
    /// <param name="sessionId">The session id value.</param>
    /// <param name="revokedAt">The revoked at value.</param>
    /// <param name="reason">The reason value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    /// <remarks>
    /// Implementations should preserve the first revocation timestamp and reason when a session is revoked more than once.
    /// </remarks>
    Task<bool> RevokeSessionAsync(Guid sessionId, DateTimeOffset revokedAt, string? reason = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all currently unrevoked sessions for a user.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="revokedAt">The revoked at value.</param>
    /// <param name="reason">The reason value.</param>
    /// <param name="tenant">The tenant scope value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    /// <remarks>
    /// Implementations should not overwrite revocation data for sessions that were already revoked.
    /// A <see langword="null" /> tenant means unrestricted; an explicit <see cref="TenantContext.Global" /> means global sessions only.
    /// </remarks>
    Task<int> RevokeSessionsForUserAsync(Guid userId, DateTimeOffset revokedAt, string? reason = null, TenantContext? tenant = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists sessions for a user.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="activeOnly">The active only value.</param>
    /// <param name="now">The now value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<IReadOnlyList<AuthenticationSession>> ListSessionsForUserAsync(Guid userId, bool activeOnly, DateTimeOffset now, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a single authentication session if it belongs to the specified user.
    /// </summary>
    /// <param name="sessionId">The session id value.</param>
    /// <param name="userId">The user id value.</param>
    /// <param name="revokedAt">The revoked at value.</param>
    /// <param name="reason">The reason value.</param>
    /// <param name="tenant">The tenant scope value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<bool> RevokeSessionByIdAsync(Guid sessionId, Guid userId, DateTimeOffset revokedAt, string? reason = null, TenantContext? tenant = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all currently unrevoked sessions for a user except the specified session.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="excludedSessionId">The excluded session id value.</param>
    /// <param name="revokedAt">The revoked at value.</param>
    /// <param name="reason">The reason value.</param>
    /// <param name="tenant">The tenant scope value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<int> RevokeOtherSessionsForUserAsync(Guid userId, Guid excludedSessionId, DateTimeOffset revokedAt, string? reason = null, TenantContext? tenant = null, CancellationToken cancellationToken = default);
}
