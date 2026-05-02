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
        var sessionId = TryGetSessionId(httpContext.User);
        if (sessionId == null && httpContext.Request.Cookies.TryGetValue(authenticationOptions.CookieName, out var token) && !string.IsNullOrWhiteSpace(token))
        {
            var validation = await _sessionService.ValidateSessionAsync(token, cancellationToken);
            sessionId = validation.Session?.Id;
        }

        if (sessionId.HasValue)
        {
            await _sessionService.RevokeSessionAsync(sessionId.Value, reason ?? "signed-out", cancellationToken);
        }

        httpContext.Response.Cookies.Delete(authenticationOptions.CookieName, authenticationOptions.Cookie.Build(httpContext));
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
}
