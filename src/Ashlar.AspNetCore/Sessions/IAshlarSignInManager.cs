using Microsoft.AspNetCore.Http;

namespace Ashlar.AspNetCore.Sessions;

/// <summary>
/// Issues and revokes Ashlar authentication session cookies for the current HTTP request.
/// </summary>
public interface IAshlarSignInManager
{
    /// <summary>
    /// Creates an authentication session for the user and writes the session cookie.
    /// </summary>
    /// <param name="httpContext">The current HTTP request context.</param>
    /// <param name="userId">The user to sign in.</param>
    /// <param name="request">Optional session metadata such as lifetime, IP address, user agent, and correlation ID.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The created authentication session. The raw token is written only to the response cookie.</returns>
    Task<AuthenticationSession> SignInAsync(
        HttpContext httpContext,
        Guid userId,
        CreateAuthenticationSessionRequest? request = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes the current authentication session and clears the session cookie.
    /// </summary>
    /// <param name="httpContext">The current HTTP request context.</param>
    /// <param name="reason">Optional revocation reason stored with the session.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    Task SignOutAsync(
        HttpContext httpContext,
        string? reason = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists sessions that belong to the currently authenticated user.
    /// </summary>
    /// <param name="httpContext">The current HTTP request context.</param>
    /// <param name="activeOnly">Whether to return only active sessions.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The current user's matching sessions.</returns>
    Task<IReadOnlyList<AuthenticationSessionSummary>> ListSessionsForCurrentUserAsync(
        HttpContext httpContext,
        bool activeOnly = true,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes one session if it belongs to the currently authenticated user.
    /// </summary>
    /// <param name="httpContext">The current HTTP request context.</param>
    /// <param name="sessionId">The session to revoke.</param>
    /// <param name="reason">Optional revocation reason stored with the session.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns><see langword="true" /> when a matching session was revoked; otherwise, <see langword="false" />.</returns>
    Task<bool> RevokeSessionForCurrentUserAsync(
        HttpContext httpContext,
        Guid sessionId,
        string? reason = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes the current user's other sessions while keeping the current session active.
    /// </summary>
    /// <param name="httpContext">The current HTTP request context.</param>
    /// <param name="reason">Optional revocation reason stored with each revoked session.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The number of sessions revoked.</returns>
    Task<int> RevokeOtherSessionsForCurrentUserAsync(
        HttpContext httpContext,
        string? reason = null,
        CancellationToken cancellationToken = default);
}


