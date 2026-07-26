using System.Security.Claims;
using Ashlar.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Ashlar.AspNetCore.Sessions;

/// <summary>
/// Provides ashlar sign in manager behavior.
/// </summary>
/// <param name="sessionService">The session mutation service.</param>
/// <param name="sessionReader">The session reader.</param>
/// <param name="options">The options value.</param>
/// <param name="registration">The registration value.</param>
public sealed class AshlarSignInManager(
    IAuthenticationSessionService sessionService,
    IAuthenticationSessionReader sessionReader,
    IOptionsMonitor<AshlarSessionAuthenticationOptions> options,
    AshlarSessionRegistration registration)
    : IAshlarSignInManager
{
    private readonly IAuthenticationSessionService _sessionService = sessionService ?? throw new ArgumentNullException(nameof(sessionService));
    private readonly IAuthenticationSessionReader _sessionReader = sessionReader ?? throw new ArgumentNullException(nameof(sessionReader));
    private readonly IOptionsMonitor<AshlarSessionAuthenticationOptions> _options = options ?? throw new ArgumentNullException(nameof(options));
    private readonly AshlarSessionRegistration _registration = registration ?? throw new ArgumentNullException(nameof(registration));

    public async Task<CreatedAuthenticationSession> SignInAsync(
        HttpContext httpContext,
        MfaAuthenticationResult authenticationResult,
        CreateAuthenticationSessionRequest? request = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(authenticationResult);

        var authenticationOptions = GetOptions();
        var cookieOptions = authenticationOptions.Cookie.Build(httpContext);

        var existingSession = await GetExistingValidatedSessionAsync(httpContext, cancellationToken);
        var sessionRequest = request ?? CreateRequestFromHttpContext(httpContext);
        var result = await _sessionService.CreateSessionAsync(authenticationResult, sessionRequest, cancellationToken);

        try
        {
            if (existingSession != null)
            {
                await _sessionService.RevokeValidatedSessionAsync(
                    new RevokeValidatedAuthenticationSessionRequest(existingSession, CreateAuditContextFromHttpContext(httpContext), "session-replaced"),
                    cancellationToken);
            }

            cookieOptions.Expires = result.Session.ExpiresAt;
            httpContext.Response.Cookies.Append(authenticationOptions.CookieName, result.Token, cookieOptions);
        }
        catch (Exception exception)
        {
            await RollBackIssuedSessionAsync(httpContext, result.Session, exception);
            throw;
        }

        return result.Session;
    }

    private async Task RollBackIssuedSessionAsync(
        HttpContext httpContext,
        CreatedAuthenticationSession session,
        Exception originalException)
    {
        try
        {
            var ownerAudit = CreateAuditContextFromHttpContext(httpContext) with { ActorUserId = session.UserId };
            if (!await _sessionService.RevokeIssuedSessionAsync(
                new RevokeIssuedAuthenticationSessionRequest(session, ownerAudit, "session-replacement-failed"),
                CancellationToken.None))
            {
                throw new InvalidOperationException("Newly issued session rollback did not revoke the session.");
            }
        }
        catch (Exception rollbackException)
        {
            originalException.Data["AshlarSessionRollbackException"] = rollbackException;
        }
    }

    public async Task SignOutAsync(
        HttpContext httpContext,
        string? reason = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        var authenticationOptions = GetOptions();
        var session = await GetExistingValidatedSessionAsync(httpContext, cancellationToken);

        if (session != null)
        {
            await RevokeCurrentSessionAsync(httpContext, reason ?? "signed-out", cancellationToken);
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

        return await _sessionReader.ListSessionsForUserAsync(
            userId,
            new ListAuthenticationSessionsRequest { ActiveOnly = activeOnly, CurrentSessionId = currentSessionId },
            cancellationToken);
    }

    public async Task<bool> RevokeSessionForCurrentUserAsync(
        HttpContext httpContext,
        Guid sessionId,
        FreshMfaVerificationProof freshMfaProof,
        string? reason = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(freshMfaProof);

        var userId = TryGetUserId(httpContext.User) ?? throw new InvalidOperationException("User is not authenticated.");
        var currentSessionId = TryGetSessionId(httpContext.User) ?? throw new InvalidOperationException("Current session ID not found in claims.");

        return await _sessionService.RevokeSessionForCurrentUserAsync(
            new RevokeOwnAuthenticationSessionRequest(userId, ResolveTenantContextOrThrow(httpContext.User), currentSessionId,
                freshMfaProof, CreateAuditContextFromHttpContext(httpContext), sessionId, reason),
            cancellationToken);
    }

    public async Task<int> RevokeOtherSessionsForCurrentUserAsync(
        HttpContext httpContext,
        FreshMfaVerificationProof freshMfaProof,
        string? reason = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(freshMfaProof);

        var userId = TryGetUserId(httpContext.User) ?? throw new InvalidOperationException("User is not authenticated.");
        var currentSessionId = TryGetSessionId(httpContext.User) ?? throw new InvalidOperationException("Current session ID not found in claims.");

        return await _sessionService.RevokeOtherSessionsForCurrentUserAsync(
            new RevokeOwnOtherAuthenticationSessionsRequest(userId, ResolveTenantContextOrThrow(httpContext.User), currentSessionId,
                freshMfaProof, CreateAuditContextFromHttpContext(httpContext), reason),
            cancellationToken);
    }

    private async Task<ValidatedAuthenticationSession?> GetExistingValidatedSessionAsync(
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        var authenticationOptions = GetOptions();
        if (httpContext.Request.Cookies.TryGetValue(authenticationOptions.CookieName, out var token) && !string.IsNullOrWhiteSpace(token))
        {
            var validation = await _sessionService.ValidateSessionAsync(token, cancellationToken);
            return validation.ValidatedSession;
        }

        return null;
    }

    private Task<bool> RevokeCurrentSessionAsync(
        HttpContext httpContext,
        string reason,
        CancellationToken cancellationToken)
    {
        var authenticationOptions = GetOptions();
        var token = httpContext.Request.Cookies[authenticationOptions.CookieName]!;
        return _sessionService.RevokeCurrentSessionAsync(
            new RevokeCurrentAuthenticationSessionRequest(token, CreateAuditContextFromHttpContext(httpContext), reason),
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

    private sealed record TenantClaim(TenantClaimStatus Status, TenantContext Context);

    private enum TenantClaimStatus
    {
        Global,
        Tenant,
        Invalid
    }
}
