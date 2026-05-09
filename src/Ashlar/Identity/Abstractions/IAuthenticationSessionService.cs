using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

/// <summary>
/// Manages provider-neutral authentication session lifecycle operations.
/// </summary>
public interface IAuthenticationSessionService
{
    /// <summary>
    /// Creates and persists a new authentication session for a user.
    /// </summary>
    /// <param name="userId">The user that owns the session.</param>
    /// <param name="request">Session creation metadata and lifetime overrides.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The raw session token and persisted session metadata.</returns>
    Task<CreateAuthenticationSessionResult> CreateSessionAsync(
        Guid userId,
        CreateAuthenticationSessionRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates a presented raw session token.
    /// </summary>
    /// <param name="token">The raw session token presented by the application.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The validation result.</returns>
    Task<ValidateAuthenticationSessionResult> ValidateSessionAsync(
        string token,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a single authentication session.
    /// </summary>
    /// <param name="sessionId">The session identifier.</param>
    /// <param name="reason">An optional provider-neutral revocation reason.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns><c>true</c> when a session was revoked; otherwise <c>false</c>.</returns>
    Task<bool> RevokeSessionAsync(
        Guid sessionId,
        string? reason = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all currently unrevoked sessions for a user.
    /// </summary>
    /// <param name="userId">The user whose sessions should be revoked.</param>
    /// <param name="reason">An optional provider-neutral revocation reason.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The number of sessions revoked by this call.</returns>
    Task<int> RevokeSessionsForUserAsync(
        Guid userId,
        string? reason = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists authentication sessions for a user.
    /// </summary>
    /// <param name="userId">The user identifier.</param>
    /// <param name="request">Listing parameters.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>A read-only list of session summaries.</returns>
    Task<IReadOnlyList<AuthenticationSessionSummary>> ListSessionsForUserAsync(
        Guid userId,
        ListAuthenticationSessionsRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a single authentication session for a user.
    /// </summary>
    /// <param name="userId">The user identifier who must own the session.</param>
    /// <param name="request">Revocation parameters.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns><c>true</c> when the session was revoked; otherwise <c>false</c>.</returns>
    Task<bool> RevokeSessionForUserAsync(
        Guid userId,
        RevokeAuthenticationSessionRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all authentication sessions for a user except one.
    /// </summary>
    /// <param name="userId">The user identifier.</param>
    /// <param name="request">Revocation parameters.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The number of sessions revoked by this call.</returns>
    Task<int> RevokeOtherSessionsAsync(
        Guid userId,
        RevokeOtherAuthenticationSessionsRequest request,
        CancellationToken cancellationToken = default);
}
