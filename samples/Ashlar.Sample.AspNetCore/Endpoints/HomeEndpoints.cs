using System.Security.Claims;
using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Ashlar.Identity.Abstractions;
using Ashlar.Sample.AspNetCore.Extensions;
using Ashlar.Sample.AspNetCore.Views;

namespace Ashlar.Sample.AspNetCore.Endpoints;

internal static class HomeEndpoints
{
    public static void MapHomeEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

        app.MapGet("/", async (
            ClaimsPrincipal user,
            IBootstrapService bootstrap,
            IAuthorizationEvaluator auth,
            IIdentityRepository users,
            CancellationToken cancellationToken) =>
        {
            var status = await bootstrap.GetStatusAsync(cancellationToken);
            var isAuthenticated = user.Identity?.IsAuthenticated ?? false;
            string? userEmail = null;
            var isAdmin = false;
            var canManageAlpha = false;
            var canManageBeta = false;

            if (!isAuthenticated)
            {
                return AppViews.RenderDashboard(status, isAuthenticated, userEmail, isAdmin, canManageAlpha, canManageBeta);
            }

            var userId = user.GetAshlarUserId();
            var ashlarUser = await users.GetUserByIdAsync(userId, cancellationToken);
            userEmail = ashlarUser?.Email;

            isAdmin = (await auth.EvaluateAsync(new AuthorizationEvaluationRequest(userId, Role: "admin"), cancellationToken)).Succeeded;
            canManageAlpha = (await auth.EvaluateAsync(new AuthorizationEvaluationRequest(userId, Permission: "project.manage", ScopeType: "project", ScopeId: "alpha"), cancellationToken)).Succeeded;
            canManageBeta = (await auth.EvaluateAsync(new AuthorizationEvaluationRequest(userId, Permission: "project.manage", ScopeType: "project", ScopeId: "beta"), cancellationToken)).Succeeded;

            return AppViews.RenderDashboard(status, isAuthenticated, userEmail, isAdmin, canManageAlpha, canManageBeta);
        });
    }
}
