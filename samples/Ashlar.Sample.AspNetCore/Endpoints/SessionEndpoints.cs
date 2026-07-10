using Ashlar.AspNetCore.Sessions;
using Ashlar.AspNetCore.Mfa;
using Ashlar.Identity.Features.Mfa;
using Ashlar.Sample.AspNetCore.Extensions;

namespace Ashlar.Sample.AspNetCore.Endpoints;

internal static class SessionEndpoints
{
    private static readonly StepUpRequirement SessionManagementRequirement = new(TimeSpan.FromMinutes(10), Purpose: "session-management");

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
            StepUpAuthenticationService stepUp,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            var proof = httpContext.CreateFreshMfaProof(stepUp, SessionManagementRequirement);
            if (!proof.Succeeded || proof.Value == null) return Results.Forbid();
            var revoked = await signInManager.RevokeSessionForCurrentUserAsync(httpContext, sessionId, proof.Value, reason: "user-revoked", cancellationToken);
            return revoked ? Results.NoContent() : Results.NotFound();
        }).RequireAuthorization().RequireFreshMfaIfAvailable().RequireSampleAntiforgery();

        app.MapDelete("/api/sessions/others", async (
            IAshlarSignInManager signInManager,
            StepUpAuthenticationService stepUp,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            var proof = httpContext.CreateFreshMfaProof(stepUp, SessionManagementRequirement);
            if (!proof.Succeeded || proof.Value == null) return Results.Forbid();
            await signInManager.RevokeOtherSessionsForCurrentUserAsync(httpContext, proof.Value, reason: "user-revoked-others", cancellationToken);
            return Results.NoContent();
        }).RequireAuthorization().RequireFreshMfaIfAvailable().RequireSampleAntiforgery();
    }
}
