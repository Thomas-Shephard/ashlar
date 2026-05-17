using System.Security.Claims;
using Ashlar.Auditing;
using Ashlar.Identity.Models;

namespace Ashlar.Sample.AspNetCore.Extensions;

internal static class HttpContextExtensions
{
    public static AuthenticationContext ToAuthenticationContext(this HttpContext httpContext, string? email = null)
    {
        return new AuthenticationContext(
            Email: email,
            TenantId: httpContext.GetAshlarTenantId(),
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
        return new TenantContext(httpContext.GetAshlarTenantId());
    }

    public static CreateAuthenticationSessionRequest ToSessionRequest(
        this HttpContext httpContext,
        AuthenticationProviderKey? primaryProvider = null,
        AuthenticationProviderKey? additionalVerificationProvider = null,
        string? additionalVerificationFactor = null)
    {
        return new CreateAuthenticationSessionRequest(
            IpAddress: httpContext.Connection.RemoteIpAddress?.ToString(),
            UserAgent: httpContext.Request.Headers.UserAgent.ToString(),
            CorrelationId: httpContext.TraceIdentifier,
            TenantId: httpContext.GetAshlarTenantId(),
            PrimaryProvider: primaryProvider,
            AdditionalVerificationAt: additionalVerificationProvider.HasValue
                ? httpContext.RequestServices.GetService<TimeProvider>()?.GetUtcNow() ?? DateTimeOffset.UtcNow
                : null,
            AdditionalVerificationProvider: additionalVerificationProvider,
            AdditionalVerificationFactor: additionalVerificationFactor);
    }

    public static Guid? GetAshlarTenantId(this HttpContext httpContext)
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
