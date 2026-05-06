using Microsoft.AspNetCore.Http;

namespace Ashlar.AspNetCore.Middleware;

/// <summary>
/// Middleware that enforces the presence of an IP address on incoming HTTP requests.
/// Returns a 400 Bad Request if the client's IP address cannot be determined.
/// </summary>
public sealed class RequireIpAddressMiddleware(RequestDelegate next)
{
    private readonly RequestDelegate _next = next ?? throw new ArgumentNullException(nameof(next));

    public async Task InvokeAsync(HttpContext context)
    {
        if (context.Connection.RemoteIpAddress == null)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("Client IP address could not be determined.");
            return;
        }

        await _next(context);
    }
}
