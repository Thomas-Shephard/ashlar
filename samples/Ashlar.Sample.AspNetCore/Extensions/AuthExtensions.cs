using System.Security.Claims;
using Ashlar.AspNetCore.Authentication;
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
        tenant = TenantContext.Global;

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
