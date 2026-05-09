using Ashlar.AspNetCore.Authentication;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Ashlar.AspNetCore.Sessions;

public sealed class AshlarSignInManager(
    IAuthenticationSessionService sessionService,
    IOptionsMonitor<AshlarSessionAuthenticationOptions> options,
    AshlarSessionRegistration registration)
    : IAshlarSignInManager
{
    private readonly IAuthenticationSessionService _sessionService = sessionService ?? throw new ArgumentNullException(nameof(sessionService));
    private readonly IOptionsMonitor<AshlarSessionAuthenticationOptions> _options = options ?? throw new ArgumentNullException(nameof(options));
    private readonly AshlarSessionRegistration _registration = registration ?? throw new ArgumentNullException(nameof(registration));

    public async Task<AuthenticationSession> SignInAsync(
        HttpContext httpContext,
        Guid userId,
        CreateAuthenticationSessionRequest? request = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        var authenticationOptions = GetOptions();

        // If there is an existing session in the request, revoke it before creating a new one.
        var existingSessionId = await GetExistingSessionIdAsync(httpContext, authenticationOptions, cancellationToken);
        if (existingSessionId.HasValue)
        {
            await _sessionService.RevokeSessionAsync(existingSessionId.Value, "session-replaced", cancellationToken);
        }

        var sessionRequest = request ?? CreateRequestFromHttpContext(httpContext);
        var result = await _sessionService.CreateSessionAsync(userId, sessionRequest, cancellationToken);

        var cookieOptions = authenticationOptions.Cookie.Build(httpContext);
        cookieOptions.Expires = result.Session.ExpiresAt;
        httpContext.Response.Cookies.Append(authenticationOptions.CookieName, result.Token, cookieOptions);

        return result.Session;
    }

    public async Task SignOutAsync(
        HttpContext httpContext,
        string? reason = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        var authenticationOptions = GetOptions();
        var sessionId = await GetExistingSessionIdAsync(httpContext, authenticationOptions, cancellationToken);

        if (sessionId.HasValue)
        {
            await _sessionService.RevokeSessionAsync(sessionId.Value, reason ?? "signed-out", cancellationToken);
        }

        httpContext.Response.Cookies.Delete(authenticationOptions.CookieName, authenticationOptions.Cookie.Build(httpContext));
    }

    public async Task<IReadOnlyList<AuthenticationSessionSummary>> ListSessionsForCurrentUserAsync(
        HttpContext httpContext,
        bool activeOnly = true,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        var userId = TryGetUserId(httpContext.User) ?? throw new InvalidOperationException("User is not authenticated.");
        var currentSessionId = TryGetSessionId(httpContext.User);

        return await _sessionService.ListSessionsForUserAsync(
            userId,
            new ListAuthenticationSessionsRequest { ActiveOnly = activeOnly, CurrentSessionId = currentSessionId },
            cancellationToken);
    }

    public async Task<bool> RevokeSessionForCurrentUserAsync(
        HttpContext httpContext,
        Guid sessionId,
        string? reason = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        var userId = TryGetUserId(httpContext.User) ?? throw new InvalidOperationException("User is not authenticated.");

        return await _sessionService.RevokeSessionForUserAsync(
            userId,
            new RevokeAuthenticationSessionRequest { SessionId = sessionId, Reason = reason },
            cancellationToken);
    }

    public async Task<int> RevokeOtherSessionsForCurrentUserAsync(
        HttpContext httpContext,
        string? reason = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        var userId = TryGetUserId(httpContext.User) ?? throw new InvalidOperationException("User is not authenticated.");
        var currentSessionId = TryGetSessionId(httpContext.User) ?? throw new InvalidOperationException("Current session ID not found in claims.");

        return await _sessionService.RevokeOtherSessionsAsync(
            userId,
            new RevokeOtherAuthenticationSessionsRequest { CurrentSessionId = currentSessionId, Reason = reason },
            cancellationToken);
    }

    private async Task<Guid?> GetExistingSessionIdAsync(
        HttpContext httpContext,
        AshlarSessionAuthenticationOptions authenticationOptions,
        CancellationToken cancellationToken)
    {
        var sessionId = TryGetSessionId(httpContext.User);
        if (sessionId == null && httpContext.Request.Cookies.TryGetValue(authenticationOptions.CookieName, out var token) && !string.IsNullOrWhiteSpace(token))
        {
            var validation = await _sessionService.ValidateSessionAsync(token, cancellationToken);
            sessionId = validation.Succeeded ? validation.Session?.Id : null;
        }

        return sessionId;
    }

    private AshlarSessionAuthenticationOptions GetOptions()
    {
        return _options.Get(_registration.SchemeName);
    }

    private static CreateAuthenticationSessionRequest CreateRequestFromHttpContext(HttpContext httpContext)
    {
        return new CreateAuthenticationSessionRequest(
            IpAddress: httpContext.Connection.RemoteIpAddress?.ToString(),
            UserAgent: httpContext.Request.Headers.UserAgent.ToString(),
            CorrelationId: httpContext.TraceIdentifier);
    }

    private static Guid? TryGetSessionId(System.Security.Claims.ClaimsPrincipal principal)
    {
        var value = principal.FindFirst(AshlarClaimTypes.SessionId)?.Value;
        return Guid.TryParse(value, out var sessionId) ? sessionId : null;
    }

    private static Guid? TryGetUserId(System.Security.Claims.ClaimsPrincipal principal)
    {
        var value = principal.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        return Guid.TryParse(value, out var userId) ? userId : null;
    }
}
