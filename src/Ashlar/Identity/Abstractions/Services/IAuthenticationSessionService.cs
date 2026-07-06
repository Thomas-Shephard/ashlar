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
    /// <returns>Public session details and the raw bearer token that must be returned to the client once. Token hashes are not returned.</returns>
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
    /// Revokes all currently unrevoked sessions for a user within an explicit scope.
    /// </summary>
    /// <param name="userId">The user whose sessions will be revoked.</param>
    /// <param name="request">Explicit tenant, global, or all-tenant/operator scope plus required audit metadata.</param>
    /// <param name="cancellationToken">A token that can cancel revocation.</param>
    /// <returns>The number of sessions revoked.</returns>
    /// <remarks>
    /// This is a destructive service-level operation. Omitted tenant scope is rejected unless
    /// <see cref="RevokeAuthenticationSessionsForUserRequest.IncludeAllTenants" /> is explicitly enabled.
    /// Host applications must authorize the actor before calling it.
    /// </remarks>
    Task<int> RevokeSessionsForUserAsync(
        Guid userId,
        RevokeAuthenticationSessionsForUserRequest request,
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
    /// <param name="request">The target session, explicit tenant/global/all-tenant scope, display-safe revocation reason, and required audit context.</param>
    /// <param name="cancellationToken">A token that can cancel revocation.</param>
    /// <returns><see langword="true" /> when the target session was revoked.</returns>
    /// <remarks>Host applications must authorize the actor before calling this destructive operation.</remarks>
    Task<bool> RevokeSessionForUserAsync(
        Guid userId,
        RevokeAuthenticationSessionRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all authentication sessions for a user except one.
    /// </summary>
    /// <param name="userId">The session owner. Callers must enforce that the actor may administer this user.</param>
    /// <param name="request">The session to keep, explicit tenant/global/all-tenant scope, display-safe revocation reason, and required audit context.</param>
    /// <param name="cancellationToken">A token that can cancel revocation.</param>
    /// <returns>The number of other sessions revoked.</returns>
    /// <remarks>Host applications must authorize the actor before calling this destructive operation.</remarks>
    Task<int> RevokeOtherSessionsAsync(
        Guid userId,
        RevokeOtherAuthenticationSessionsRequest request,
        CancellationToken cancellationToken = default);
}
