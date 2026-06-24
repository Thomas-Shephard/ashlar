using Ashlar.Auditing;

namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Manages provider-neutral authentication session lifecycle operations.
/// </summary>
public interface IAuthenticationSessionService
{
    /// <summary>
    /// Creates and persists a new authentication session for a user.
    /// </summary>
    /// <param name="userId">The authenticated user that will own the session.</param>
    /// <param name="request">Session lifetime, tenant, audit, and client metadata supplied by the host application.</param>
    /// <param name="cancellationToken">A token that can cancel session creation.</param>
    /// <returns>The persisted session and the raw bearer token that must be returned to the client once.</returns>
    Task<CreateAuthenticationSessionResult> CreateSessionAsync(
        Guid userId,
        CreateAuthenticationSessionRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates a presented raw session token.
    /// </summary>
    /// <param name="token">The raw bearer token presented by a client. Do not log or persist this value.</param>
    /// <param name="cancellationToken">A token that can cancel validation.</param>
    /// <returns>Validation outcome and matching session when the token is active.</returns>
    Task<ValidateAuthenticationSessionResult> ValidateSessionAsync(
        string? token,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Marks an existing active session as recently verified by an additional factor.
    /// </summary>
    /// <param name="userId">Session owner user identifier.</param>
    /// <param name="request">Active session and factor metadata to mark as freshly verified.</param>
    /// <param name="cancellationToken">A token that can cancel the update.</param>
    /// <returns>Updated active session with step-up verification metadata, or a failure status.</returns>
    Task<Result<AuthenticationSession>> MarkStepUpVerifiedAsync(
        Guid userId,
        MarkSessionStepUpVerifiedRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all currently unrevoked sessions for a user.
    /// </summary>
    /// <param name="userId">The user whose sessions will be revoked.</param>
    /// <param name="reason">Optional provider-neutral, display-safe reason for audit and administrative display.</param>
    /// <param name="tenant">Tenant scope to constrain the revocation. Use <see cref="TenantContext.Global" /> for global users; omit only when intentionally revoking across all tenant scopes.</param>
    /// <param name="audit">Actor and request metadata to include in emitted security events.</param>
    /// <param name="cancellationToken">A token that can cancel revocation.</param>
    /// <returns>The number of sessions revoked.</returns>
    Task<int> RevokeSessionsForUserAsync(
        Guid userId,
        string? reason = null,
        TenantContext? tenant = null,
        AuditContext? audit = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists authentication sessions for a user.
    /// </summary>
    /// <param name="userId">The user whose sessions will be listed.</param>
    /// <param name="request">Active-session filtering and current-session marker options for the list operation.</param>
    /// <param name="cancellationToken">A token that can cancel the query.</param>
    /// <returns>Session summaries for the requested user. Raw session tokens are never returned.</returns>
    Task<IReadOnlyList<AuthenticationSessionSummary>> ListSessionsForUserAsync(
        Guid userId,
        ListAuthenticationSessionsRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a single authentication session for a user.
    /// </summary>
    /// <param name="userId">The session owner. Callers must enforce that the actor may administer this user.</param>
    /// <param name="request">The target session, tenant scope, display-safe revocation reason, and audit context.</param>
    /// <param name="cancellationToken">A token that can cancel revocation.</param>
    /// <returns><see langword="true" /> when the target session was revoked.</returns>
    Task<bool> RevokeSessionForUserAsync(
        Guid userId,
        RevokeAuthenticationSessionRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all authentication sessions for a user except one.
    /// </summary>
    /// <param name="userId">The session owner. Callers must enforce that the actor may administer this user.</param>
    /// <param name="request">The session to keep, tenant scope, display-safe revocation reason, and audit context.</param>
    /// <param name="cancellationToken">A token that can cancel revocation.</param>
    /// <returns>The number of other sessions revoked.</returns>
    Task<int> RevokeOtherSessionsAsync(
        Guid userId,
        RevokeOtherAuthenticationSessionsRequest request,
        CancellationToken cancellationToken = default);
}
