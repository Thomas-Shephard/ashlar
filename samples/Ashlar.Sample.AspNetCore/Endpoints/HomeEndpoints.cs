using System.Security.Claims;
using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Ashlar.Sample.AspNetCore.Extensions;
using Ashlar.Sample.AspNetCore.Views;
using Dapper;
using Microsoft.AspNetCore.Mvc;
using Npgsql;

namespace Ashlar.Sample.AspNetCore.Endpoints;

internal static class HomeEndpoints
{
    public static void MapHomeEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/health", () => Results.Ok(new { status = "ok" }));

        app.MapGet("/", async (
            [AsParameters] HomeServices services,
            ClaimsPrincipal user,
            CancellationToken cancellationToken) =>
        {
            var status = await services.Bootstrap.GetStatusAsync(cancellationToken);
            var isAuthenticated = user.Identity?.IsAuthenticated ?? false;
            string? userName = null;
            bool isAdmin = false;
            var projectsWithAccess = new List<(string Id, string Name, bool HasAccess)>();

            if (isAuthenticated)
            {
                var userId = user.GetAshlarUserId();
                var profile = await services.Profiles.GetAsync(userId, cancellationToken);
                userName = profile?.Name;

                isAdmin = (await services.Auth.EvaluateAsync(new AuthorizationEvaluationRequest(userId, Role: "admin"), cancellationToken)).Succeeded;

                await using var connection = await services.DataSource.OpenConnectionAsync(cancellationToken);
                var projects = await connection.QueryAsync<(string Id, string Name)>(new CommandDefinition(
                    "SELECT id, name FROM sample_projects ORDER BY created_at",
                    cancellationToken: cancellationToken));

                foreach (var (id, name) in projects)
                {
                    var access = await services.Auth.EvaluateAsync(new AuthorizationEvaluationRequest(
                        userId, Permission: "project.manage", ScopeType: "project", ScopeId: id), cancellationToken);
                    projectsWithAccess.Add((id, name, access.Succeeded));
                }
            }

            return AppViews.RenderDashboard(
                status,
                isAuthenticated,
                userName,
                isAdmin,
                projectsWithAccess,
                SampleGoogleOidc.IsConfigured(services.Configuration),
                SampleGitHubOAuth.IsConfigured(services.Configuration));
        });
    }

    private sealed record HomeServices(
        [FromServices] IBootstrapService Bootstrap,
        [FromServices] IAuthorizationEvaluator Auth,
        [FromServices] IUserProfileService Profiles,
        [FromServices] NpgsqlDataSource DataSource,
        [FromServices] IConfiguration Configuration);
}
