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
    /// <param name="userId">The user id value.</param>
    /// <param name="request">The request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<CreateAuthenticationSessionResult> CreateSessionAsync(
        Guid userId,
        CreateAuthenticationSessionRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates a presented raw session token.
    /// </summary>
    /// <param name="token">The token value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<ValidateAuthenticationSessionResult> ValidateSessionAsync(
        string token,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Marks an existing active session as recently verified by an additional factor.
    /// </summary>
    /// <param name="userId">The session owner user id.</param>
    /// <param name="request">The request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The updated session result.</returns>
    Task<Result<AuthenticationSession>> MarkStepUpVerifiedAsync(
        Guid userId,
        MarkSessionStepUpVerifiedRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a single authentication session.
    /// </summary>
    /// <param name="sessionId">The session id value.</param>
    /// <param name="reason">The reason value.</param>
    /// <param name="audit">The audit metadata value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<bool> RevokeSessionAsync(
        Guid sessionId,
        string? reason = null,
        AuditContext? audit = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all currently unrevoked sessions for a user.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="reason">The reason value.</param>
    /// <param name="tenant">The tenant context value.</param>
    /// <param name="audit">The audit metadata value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<int> RevokeSessionsForUserAsync(
        Guid userId,
        string? reason = null,
        TenantContext? tenant = null,
        AuditContext? audit = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists authentication sessions for a user.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="request">The request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<IReadOnlyList<AuthenticationSessionSummary>> ListSessionsForUserAsync(
        Guid userId,
        ListAuthenticationSessionsRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a single authentication session for a user.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="request">The request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<bool> RevokeSessionForUserAsync(
        Guid userId,
        RevokeAuthenticationSessionRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all authentication sessions for a user except one.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="request">The request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<int> RevokeOtherSessionsAsync(
        Guid userId,
        RevokeOtherAuthenticationSessionsRequest request,
        CancellationToken cancellationToken = default);
}
