using System.Security.Claims;
using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Ashlar.Sample.AspNetCore.Extensions;
using Ashlar.Sample.AspNetCore.Views;
using Dapper;
using Microsoft.AspNetCore.Mvc;

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
                var ashlarUser = await services.Users.GetUserByIdAsync(userId, cancellationToken);
                userName = ashlarUser?.Name;

                isAdmin = (await services.Auth.EvaluateAsync(new AuthorizationEvaluationRequest(userId, Role: "admin"), cancellationToken)).Succeeded;

                var connection = await services.ConnectionProvider.GetConnectionAsync(cancellationToken);
                await using (connection)
                {
                    var projects = await connection.Connection.QueryAsync<(string Id, string Name)>(new CommandDefinition(
                        "SELECT id, name FROM sample_projects ORDER BY created_at",
                        transaction: connection.Transaction,
                        cancellationToken: cancellationToken));

                    var userGrants = await services.Grants.ListGrantsAsync(new ListAuthorizationGrantsRequest(
                        UserId: userId,
                        ScopeType: "project",
                        ActiveOnly: true), cancellationToken);

                    var managedProjectIds = userGrants
                        .Where(g => g is { Permission: "project.manage", ScopeId: not null })
                        .Select(g => g.ScopeId)
                        .ToHashSet(StringComparer.OrdinalIgnoreCase);

                    foreach (var (id, name) in projects)
                    {
                        projectsWithAccess.Add((id, name, managedProjectIds.Contains(id)));
                    }
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
        [FromServices] IAuthorizationGrantService Grants,
        [FromServices] IIdentityRepository Users,
        [FromServices] IPostgresConnectionProvider ConnectionProvider,
        [FromServices] IConfiguration Configuration);
}
