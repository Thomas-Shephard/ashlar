namespace Ashlar.Identity.Abstractions.Repositories;

/// <summary>
/// Stores and retrieves durable authentication sessions.
/// </summary>
public interface IAuthenticationSessionRepository
{
    /// <summary>
    /// Persists a new authentication session.
    /// </summary>
    /// <param name="session">Session to store. It must contain a storage-safe hash of the raw session token.</param>
    /// <param name="cancellationToken">A token that can cancel persistence.</param>
    /// <returns>A task that completes when the session has been stored.</returns>
    /// <remarks>
    /// <see cref="AuthenticationSession.TokenHash"/> must contain a storage-safe hash of the raw session token.
    /// Implementations must not persist raw session tokens.
    /// </remarks>
    Task CreateSessionAsync(AuthenticationSession session, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a session by its storage-safe token hash.
    /// </summary>
    /// <param name="tokenHash">Storage-safe hash of the raw session token presented by a caller.</param>
    /// <param name="cancellationToken">A token that can cancel lookup.</param>
    /// <returns>The matching session, or <see langword="null" /> when no session exists.</returns>
    /// <remarks>
    /// This method may return revoked or expired sessions. Callers should evaluate
    /// <see cref="AuthenticationSession.IsActive(DateTimeOffset)"/> against their current clock when active-only behavior is required.
    /// </remarks>
    Task<AuthenticationSession?> GetSessionByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a session by its unique identifier.
    /// </summary>
    /// <param name="sessionId">Identifier of the session to retrieve.</param>
    /// <param name="cancellationToken">A token that can cancel lookup.</param>
    /// <returns>The matching session, or <see langword="null" /> when no session exists.</returns>
    Task<AuthenticationSession?> GetSessionAsync(Guid sessionId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates the time a session was last observed.
    /// </summary>
    /// <param name="sessionId">Identifier of the session to update.</param>
    /// <param name="lastSeenAt">UTC time when the session was observed.</param>
    /// <param name="cancellationToken">A token that can cancel the update.</param>
    /// <returns><see langword="true" /> when the session timestamp was updated.</returns>
    /// <remarks>
    /// Implementations should avoid moving <see cref="AuthenticationSession.LastSeenAt"/> backwards when an older timestamp
    /// races with a newer update.
    /// </remarks>
    Task<bool> UpdateSessionLastSeenAsync(Guid sessionId, DateTimeOffset lastSeenAt, CancellationToken cancellationToken = default);

    /// <summary>
    /// Marks an active session as recently step-up verified if it belongs to the specified user.
    /// </summary>
    /// <param name="sessionId">Identifier of the application session to update.</param>
    /// <param name="userId">Owner that the session must belong to.</param>
    /// <param name="verifiedAt">UTC time when step-up verification completed.</param>
    /// <param name="verifiedProvider">Provider that verified the secondary factor.</param>
    /// <param name="verifiedFactor">Provider-neutral factor type that was verified.</param>
    /// <param name="cancellationToken">A token that can cancel the update.</param>
    /// <returns>The updated session, or <see langword="null" /> when no active owned session was updated.</returns>
    Task<AuthenticationSession?> MarkStepUpVerifiedAsync(
        Guid sessionId,
        Guid userId,
        DateTimeOffset verifiedAt,
        AuthenticationProviderKey verifiedProvider,
        string verifiedFactor,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all currently unrevoked sessions for a user.
    /// </summary>
    /// <param name="userId">Owner whose sessions should be revoked.</param>
    /// <param name="revokedAt">UTC time to record for revocation.</param>
    /// <param name="reason">Provider-neutral, display-safe revocation reason, or <see langword="null" /> when there is no display-safe reason.</param>
    /// <param name="tenant">Tenant scope to revoke within. Use <see cref="TenantContext.Global" /> for global sessions; leave <see langword="null" /> only when <paramref name="includeAllTenants" /> is enabled.</param>
    /// <param name="includeAllTenants">Whether to revoke across all tenant scopes. Cannot be combined with <paramref name="tenant" />.</param>
    /// <param name="cancellationToken">A token that can cancel revocation.</param>
    /// <returns>The number of sessions newly revoked.</returns>
    /// <remarks>
    /// Implementations should not overwrite revocation data for sessions that were already revoked.
    /// Callers must choose an explicit tenant scope, <see cref="TenantContext.Global" />, or <paramref name="includeAllTenants" /> for deliberate unrestricted revocation.
    /// </remarks>
    Task<int> RevokeSessionsForUserAsync(Guid userId, DateTimeOffset revokedAt, string? reason, TenantContext? tenant, bool includeAllTenants, CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists sessions for a user.
    /// </summary>
    /// <param name="userId">Owner whose sessions should be returned.</param>
    /// <param name="activeOnly">Whether to exclude expired and revoked sessions.</param>
    /// <param name="now">UTC time used for active-session evaluation.</param>
    /// <param name="cancellationToken">A token that can cancel the query.</param>
    /// <returns>The sessions for the requested user.</returns>
    Task<IReadOnlyList<AuthenticationSession>> ListSessionsForUserAsync(Guid userId, bool activeOnly, DateTimeOffset now, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a single authentication session if it belongs to the specified user.
    /// </summary>
    /// <param name="sessionId">Identifier of the session to revoke.</param>
    /// <param name="userId">Owner that the session must belong to.</param>
    /// <param name="revokedAt">UTC time to record for revocation.</param>
    /// <param name="reason">Provider-neutral, display-safe revocation reason, or <see langword="null" /> when there is no display-safe reason.</param>
    /// <param name="tenant">Tenant scope the session must belong to. Use <see cref="TenantContext.Global" /> for global sessions; leave <see langword="null" /> only when <paramref name="includeAllTenants" /> is enabled.</param>
    /// <param name="includeAllTenants">Whether to allow lookup across all tenant scopes. Cannot be combined with <paramref name="tenant" />.</param>
    /// <param name="cancellationToken">A token that can cancel revocation.</param>
    /// <returns><see langword="true" /> when the owned session was revoked.</returns>
    Task<bool> RevokeSessionByIdAsync(Guid sessionId, Guid userId, DateTimeOffset revokedAt, string? reason, TenantContext? tenant, bool includeAllTenants, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all currently unrevoked sessions for a user except the specified session.
    /// </summary>
    /// <param name="userId">Owner whose other sessions should be revoked.</param>
    /// <param name="excludedSessionId">Session identifier that must remain active.</param>
    /// <param name="revokedAt">UTC time to record for revocation.</param>
    /// <param name="reason">Provider-neutral, display-safe revocation reason, or <see langword="null" /> when there is no display-safe reason.</param>
    /// <param name="tenant">Tenant scope to revoke within. Use <see cref="TenantContext.Global" /> for global sessions; leave <see langword="null" /> only when <paramref name="includeAllTenants" /> is enabled.</param>
    /// <param name="includeAllTenants">Whether to revoke across all tenant scopes. Cannot be combined with <paramref name="tenant" />.</param>
    /// <param name="cancellationToken">A token that can cancel revocation.</param>
    /// <returns>The number of other sessions newly revoked.</returns>
    Task<int> RevokeOtherSessionsForUserAsync(Guid userId, Guid excludedSessionId, DateTimeOffset revokedAt, string? reason, TenantContext? tenant, bool includeAllTenants, CancellationToken cancellationToken = default);
}
