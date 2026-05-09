using System.Security.Claims;
using Ashlar.Identity.Models;

namespace Ashlar.Sample.AspNetCore.Extensions;

internal static class HttpContextExtensions
{
    public static AuthenticationContext ToAuthenticationContext(this HttpContext httpContext, string? email = null)
    {
        return new AuthenticationContext(
            Email: email,
            IpAddress: httpContext.Connection.RemoteIpAddress?.ToString(),
            UserAgent: httpContext.Request.Headers.UserAgent.ToString(),
            CorrelationId: httpContext.TraceIdentifier);
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
