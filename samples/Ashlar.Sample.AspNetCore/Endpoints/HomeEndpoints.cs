using System.Security.Claims;
using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Ashlar.Identity.Abstractions;
using Ashlar.Postgres;
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
            HttpContext _,
            [FromServices] IBootstrapService bootstrap,
            [FromServices] IAuthorizationEvaluator auth,
            [FromServices] IAuthorizationGrantService grants,
            [FromServices] IIdentityRepository users,
            [FromServices] IPostgresConnectionProvider connectionProvider,
            ClaimsPrincipal user,
            CancellationToken cancellationToken) =>
        {
            var status = await bootstrap.GetStatusAsync(cancellationToken);
            var isAuthenticated = user.Identity?.IsAuthenticated ?? false;
            string? userEmail = null;
            string? userName = null;
            bool isEmailVerified = false;
            bool isAdmin = false;
            var projectsWithAccess = new List<(string Id, string Name, bool HasAccess)>();

            if (isAuthenticated)
            {
                var userId = user.GetAshlarUserId();
                var ashlarUser = await users.GetUserByIdAsync(userId, cancellationToken);
                userEmail = ashlarUser?.Email;
                userName = ashlarUser?.Name;
                isEmailVerified = ashlarUser?.EmailVerifiedAt.HasValue ?? false;

                isAdmin = (await auth.EvaluateAsync(new AuthorizationEvaluationRequest(userId, Role: "admin"), cancellationToken)).Succeeded;

                var connection = await connectionProvider.GetConnectionAsync(cancellationToken);
                await using (connection)
                {
                    var projects = await connection.Connection.QueryAsync<(string Id, string Name)>(
                        "SELECT id, name FROM sample_projects ORDER BY created_at",
                        transaction: connection.Transaction);

                    var userGrants = await grants.ListGrantsAsync(new ListAuthorizationGrantsRequest(
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

            return AppViews.RenderDashboard(status, isAuthenticated, userEmail, userName, isEmailVerified, isAdmin, projectsWithAccess);
        });
    }
}
