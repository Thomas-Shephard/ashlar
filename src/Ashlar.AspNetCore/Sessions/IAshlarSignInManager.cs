using Ashlar.Identity.Models;
using Microsoft.AspNetCore.Http;

namespace Ashlar.AspNetCore.Sessions;

public interface IAshlarSignInManager
{
    Task<AuthenticationSession> SignInAsync(
        HttpContext httpContext,
        Guid userId,
        CreateAuthenticationSessionRequest? request = null,
        CancellationToken cancellationToken = default);

    Task SignOutAsync(
        HttpContext httpContext,
        string? reason = null,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<AuthenticationSessionSummary>> ListSessionsForCurrentUserAsync(
        HttpContext httpContext,
        bool activeOnly = true,
        CancellationToken cancellationToken = default);

    Task<bool> RevokeSessionForCurrentUserAsync(
        HttpContext httpContext,
        Guid sessionId,
        string? reason = null,
        CancellationToken cancellationToken = default);

    Task<int> RevokeOtherSessionsForCurrentUserAsync(
        HttpContext httpContext,
        string? reason = null,
        CancellationToken cancellationToken = default);
}
