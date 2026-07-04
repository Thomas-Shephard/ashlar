using System.Security.Claims;
using Ashlar.AspNetCore.Authentication;
using Ashlar.AspNetCore.Sessions;
using Ashlar.Auditing;

namespace Ashlar.Sample.AspNetCore.Extensions;

internal static class HttpContextExtensions
{
    public static AuthenticationContext ToAuthenticationContext(this HttpContext httpContext, string? email = null)
    {
        return new AuthenticationContext(
            Email: email,
            TenantId: httpContext.GetDemoTenantIdFromUntrustedHeader(),
            IpAddress: httpContext.Connection.RemoteIpAddress?.ToString(),
            UserAgent: httpContext.Request.Headers.UserAgent.ToString(),
            CorrelationId: httpContext.TraceIdentifier);
    }

    public static AuditContext ToAuditContext(this HttpContext httpContext)
    {
        return new AuditContext(
            ActorUserId: TryGetAshlarUserId(httpContext.User),
            IpAddress: httpContext.Connection.RemoteIpAddress?.ToString(),
            UserAgent: httpContext.Request.Headers.UserAgent.ToString(),
            CorrelationId: httpContext.TraceIdentifier);
    }

    public static TenantContext ToTenantContext(this HttpContext httpContext)
    {
        return new TenantContext(httpContext.GetDemoTenantIdFromUntrustedHeader());
    }

    public static bool TryGetAshlarSessionContext(this HttpContext httpContext, out Guid userId, out Guid sessionId, out TenantContext? tenant)
    {
        userId = Guid.Empty;
        sessionId = Guid.Empty;
        tenant = null;

        if (TryGetAshlarUserId(httpContext.User) is not { } resolvedUserId)
        {
            return false;
        }

        var sessionValue = httpContext.User.FindFirstValue(AshlarClaimTypes.SessionId);
        if (!Guid.TryParse(sessionValue, out sessionId))
        {
            return false;
        }

        userId = resolvedUserId;
        var tenantValue = httpContext.User.FindFirstValue(AshlarClaimTypes.TenantId);
        if (tenantValue != null)
        {
            if (!Guid.TryParse(tenantValue, out var tenantId))
            {
                return false;
            }

            tenant = new TenantContext(tenantId);
        }

        return true;
    }

    public static CreateAuthenticationSessionRequest ToSessionRequest(
        this HttpContext httpContext,
        IUser? user = null,
        AuthenticationProviderKey? primaryProvider = null)
    {
        return new CreateAuthenticationSessionRequest(
            IpAddress: httpContext.Connection.RemoteIpAddress?.ToString(),
            UserAgent: httpContext.Request.Headers.UserAgent.ToString(),
            CorrelationId: httpContext.TraceIdentifier,
            TenantId: user is ITenantUser { TenantId: { } tenantId } ? tenantId : null,
            PrimaryProvider: primaryProvider);
    }

    public static async Task<Result<AuthenticationSession>> SignInAndMarkStepUpVerifiedAsync(
        this HttpContext httpContext,
        IAshlarSignInManager signInManager,
        IAuthenticationSessionService sessionService,
        IUser user,
        AuthenticationProviderKey verifiedProvider,
        string verifiedFactor,
        CancellationToken cancellationToken)
    {
        var session = await signInManager.SignInAsync(httpContext, user.Id, httpContext.ToSessionRequest(user), cancellationToken);

        try
        {
            var result = await sessionService.MarkStepUpVerifiedAsync(
                user.Id,
                new MarkSessionStepUpVerifiedRequest
                {
                    SessionId = session.Id,
                    VerifiedProvider = verifiedProvider,
                    VerifiedFactor = verifiedFactor,
                    Tenant = session.TenantId is null ? TenantContext.Global : new TenantContext(session.TenantId),
                    Audit = httpContext.ToAuditContext()
                },
                cancellationToken);

            if (!result.Succeeded)
            {
                await CleanupUnverifiedSessionAsync(httpContext, signInManager, sessionService, user.Id, session, cancellationToken);
            }

            return result;
        }
        catch
        {
            await CleanupUnverifiedSessionAsync(httpContext, signInManager, sessionService, user.Id, session, cancellationToken);
            throw;
        }
    }

    private static async Task CleanupUnverifiedSessionAsync(
        HttpContext httpContext,
        IAshlarSignInManager signInManager,
        IAuthenticationSessionService sessionService,
        Guid userId,
        CreatedAuthenticationSession session,
        CancellationToken cancellationToken)
    {
        Exception? revocationException = null;
        try
        {
            await sessionService.RevokeSessionForUserAsync(
                userId,
                new RevokeAuthenticationSessionRequest
                {
                    SessionId = session.Id,
                    Reason = "step-up-verification-mark-failed",
                    Tenant = session.TenantId is null ? TenantContext.Global : new TenantContext(session.TenantId),
                    Audit = httpContext.ToAuditContext()
                },
                cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            revocationException = ex;
        }

        await signInManager.SignOutAsync(httpContext, "step-up-verification-mark-failed", cancellationToken);
        if (revocationException != null)
        {
            throw new InvalidOperationException("The unverified session cookie was cleared, but session revocation failed.", revocationException);
        }
    }

    /// <summary>
    /// Reads the sample-only <c>X-Tenant-Id</c> tenant selector from the request.
    /// This header is caller controlled and must not be used as a trusted production tenant resolver.
    /// </summary>
    public static Guid? GetDemoTenantIdFromUntrustedHeader(this HttpContext httpContext)
    {
        var value = httpContext.Request.Headers["X-Tenant-Id"].FirstOrDefault();
        return Guid.TryParse(value, out var tenantId) ? tenantId : null;
    }

    private static Guid? TryGetAshlarUserId(ClaimsPrincipal principal)
    {
        var value = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        return Guid.TryParse(value, out var userId) ? userId : null;
    }
}

internal static class ClaimsPrincipalExtensions
{
    public static Guid GetAshlarUserId(this ClaimsPrincipal principal)
    {
        var value = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(value, out var userId))
        {
            throw new InvalidOperationException("The current principal does not contain an Ashlar user ID.");
        }

        return userId;
    }
}
