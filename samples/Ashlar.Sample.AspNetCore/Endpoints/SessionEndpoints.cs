using Ashlar.AspNetCore.Sessions;
using Ashlar.Sample.AspNetCore.Extensions;

namespace Ashlar.Sample.AspNetCore.Endpoints;

internal static class SessionEndpoints
{
    public static void MapSessionEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/sessions", async (
            IAshlarSignInManager signInManager,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            var sessions = await signInManager.ListSessionsForCurrentUserAsync(httpContext, activeOnly: true, cancellationToken);
            return Results.Ok(sessions.Select(s => new
            {
                s.Id,
                s.CreatedAt,
                s.LastSeenAt,
                s.IpAddress,
                s.UserAgent,
                s.IsCurrent
            }));
        }).RequireAuthorization();

        app.MapDelete("/api/sessions/{sessionId:guid}", async (
            Guid sessionId,
            IAshlarSignInManager signInManager,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            var revoked = await signInManager.RevokeSessionForCurrentUserAsync(httpContext, sessionId, reason: "user-revoked", cancellationToken);
            return revoked ? Results.NoContent() : Results.NotFound();
        }).RequireAuthorization().RequireFreshMfaIfAvailable().RequireSampleAntiforgery();

        app.MapDelete("/api/sessions/others", async (
            IAshlarSignInManager signInManager,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            await signInManager.RevokeOtherSessionsForCurrentUserAsync(httpContext, reason: "user-revoked-others", cancellationToken);
            return Results.NoContent();
        }).RequireAuthorization().RequireFreshMfaIfAvailable().RequireSampleAntiforgery();
    }
}
