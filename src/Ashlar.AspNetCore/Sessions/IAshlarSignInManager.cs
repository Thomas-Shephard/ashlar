using Ashlar.Identity.Models;
using Microsoft.AspNetCore.Http;

namespace Ashlar.AspNetCore.Sessions;

/// <summary>
/// Defines the contract for iashlar sign in manager operations.
/// </summary>
public interface IAshlarSignInManager
{
    /// <summary>
    /// Performs the sign in <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="httpContext">The http context value.</param>
    /// <param name="userId">The user id value.</param>
    /// <param name="request">The request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<AuthenticationSession> SignInAsync(
        HttpContext httpContext,
        Guid userId,
        CreateAuthenticationSessionRequest? request = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Performs the sign out <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="httpContext">The http context value.</param>
    /// <param name="reason">The reason value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task SignOutAsync(
        HttpContext httpContext,
        string? reason = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Performs the list sessions for current user <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="httpContext">The http context value.</param>
    /// <param name="activeOnly">The active only value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<IReadOnlyList<AuthenticationSessionSummary>> ListSessionsForCurrentUserAsync(
        HttpContext httpContext,
        bool activeOnly = true,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Performs the revoke session for current user <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="httpContext">The http context value.</param>
    /// <param name="sessionId">The session id value.</param>
    /// <param name="reason">The reason value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<bool> RevokeSessionForCurrentUserAsync(
        HttpContext httpContext,
        Guid sessionId,
        string? reason = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Performs the revoke other sessions for current user <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="httpContext">The http context value.</param>
    /// <param name="reason">The reason value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<int> RevokeOtherSessionsForCurrentUserAsync(
        HttpContext httpContext,
        string? reason = null,
        CancellationToken cancellationToken = default);
}
