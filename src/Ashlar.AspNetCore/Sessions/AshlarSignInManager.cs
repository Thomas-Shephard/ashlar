using System.Security.Claims;
using Ashlar.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Ashlar.AspNetCore.Sessions;

/// <summary>
/// Provides ashlar sign in manager behavior.
/// </summary>
/// <param name="sessionService">The session service value.</param>
/// <param name="options">The options value.</param>
/// <param name="registration">The registration value.</param>
public sealed class AshlarSignInManager(
    IAuthenticationSessionService sessionService,
    IOptionsMonitor<AshlarSessionAuthenticationOptions> options,
    AshlarSessionRegistration registration)
    : IAshlarSignInManager
{
    private readonly IAuthenticationSessionService _sessionService = sessionService ?? throw new ArgumentNullException(nameof(sessionService));
    private readonly IOptionsMonitor<AshlarSessionAuthenticationOptions> _options = options ?? throw new ArgumentNullException(nameof(options));
    private readonly AshlarSessionRegistration _registration = registration ?? throw new ArgumentNullException(nameof(registration));

    public async Task<CreatedAuthenticationSession> SignInAsync(
        HttpContext httpContext,
        Guid userId,
        CreateAuthenticationSessionRequest? request = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        var authenticationOptions = GetOptions();

        // If there is an existing session in the request, revoke it before creating a new one.
        var existingSession = await GetExistingSessionContextAsync(httpContext, authenticationOptions, cancellationToken);
        if (existingSession != null)
        {
            await RevokeCurrentSessionAsync(httpContext, existingSession, "session-replaced", cancellationToken);
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
        var session = await GetExistingSessionContextAsync(httpContext, authenticationOptions, cancellationToken);

        if (session != null)
        {
            await RevokeCurrentSessionAsync(httpContext, session, reason ?? "signed-out", cancellationToken);
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
            new RevokeAuthenticationSessionRequest
            {
                SessionId = sessionId,
                Reason = reason,
                Tenant = ResolveTenantContextOrThrow(httpContext.User),
                Audit = CreateAuditContextFromHttpContext(httpContext)
            },
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
            new RevokeOtherAuthenticationSessionsRequest
            {
                CurrentSessionId = currentSessionId,
                Reason = reason,
                Tenant = ResolveTenantContextOrThrow(httpContext.User),
                Audit = CreateAuditContextFromHttpContext(httpContext)
            },
            cancellationToken);
    }

    private async Task<CurrentSessionContext?> GetExistingSessionContextAsync(
        HttpContext httpContext,
        AshlarSessionAuthenticationOptions authenticationOptions,
        CancellationToken cancellationToken)
    {
        var sessionId = TryGetSessionId(httpContext.User);
        var userId = TryGetUserId(httpContext.User);
        var tenantClaim = ResolveTenantClaim(httpContext.User);
        if (sessionId.HasValue && userId.HasValue && tenantClaim.Status == TenantClaimStatus.Tenant)
        {
            return new CurrentSessionContext(sessionId.Value, userId.Value, tenantClaim.Context);
        }

        if (httpContext.Request.Cookies.TryGetValue(authenticationOptions.CookieName, out var token) && !string.IsNullOrWhiteSpace(token))
        {
            var validation = await _sessionService.ValidateSessionAsync(token, cancellationToken);
            if (validation is { Succeeded: true, Session: { } session })
            {
                return new CurrentSessionContext(session.Id, session.UserId, ToTenantContext(session.TenantId));
            }
        }

        if (sessionId.HasValue && userId.HasValue)
        {
            return tenantClaim.Status == TenantClaimStatus.Global
                ? new CurrentSessionContext(sessionId.Value, userId.Value, tenantClaim.Context)
                : null;
        }

        return null;
    }

    private Task<bool> RevokeCurrentSessionAsync(
        HttpContext httpContext,
        CurrentSessionContext session,
        string reason,
        CancellationToken cancellationToken)
    {
        return _sessionService.RevokeSessionForUserAsync(
            session.UserId,
            new RevokeAuthenticationSessionRequest
            {
                SessionId = session.SessionId,
                Reason = reason,
                Tenant = session.Tenant,
                Audit = CreateAuditContextFromHttpContext(httpContext)
            },
            cancellationToken);
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

    private static Ashlar.Auditing.AuditContext CreateAuditContextFromHttpContext(HttpContext httpContext)
    {
        return new Ashlar.Auditing.AuditContext(
            ActorUserId: TryGetUserId(httpContext.User),
            IpAddress: httpContext.Connection.RemoteIpAddress?.ToString(),
            UserAgent: httpContext.Request.Headers.UserAgent.ToString(),
            CorrelationId: httpContext.TraceIdentifier);
    }

    private static Guid? TryGetSessionId(ClaimsPrincipal principal)
    {
        var value = principal.FindFirst(AshlarClaimTypes.SessionId)?.Value;
        return Guid.TryParse(value, out var sessionId) ? sessionId : null;
    }

    private static Guid? TryGetUserId(ClaimsPrincipal principal)
    {
        var value = principal.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        return Guid.TryParse(value, out var userId) ? userId : null;
    }

    private static TenantContext ResolveTenantContextOrThrow(ClaimsPrincipal principal)
    {
        var tenantClaim = ResolveTenantClaim(principal);
        if (tenantClaim.Status == TenantClaimStatus.Invalid)
        {
            throw new InvalidOperationException("Tenant ID claim is invalid.");
        }

        return tenantClaim.Context;
    }

    private static TenantContext ToTenantContext(Guid? tenantId)
    {
        return tenantId.HasValue ? new TenantContext(tenantId) : TenantContext.Global;
    }

    private static TenantClaim ResolveTenantClaim(ClaimsPrincipal principal)
    {
        var value = principal.FindFirst(AshlarClaimTypes.TenantId)?.Value;
        if (value == null)
        {
            return new TenantClaim(TenantClaimStatus.Global, TenantContext.Global);
        }

        return Guid.TryParse(value, out var tenantId)
            ? new TenantClaim(TenantClaimStatus.Tenant, new TenantContext(tenantId))
            : new TenantClaim(TenantClaimStatus.Invalid, TenantContext.Global);
    }

    private sealed record CurrentSessionContext(Guid SessionId, Guid UserId, TenantContext Tenant);
    private sealed record TenantClaim(TenantClaimStatus Status, TenantContext Context);

    private enum TenantClaimStatus
    {
        Global,
        Tenant,
        Invalid
    }
}
