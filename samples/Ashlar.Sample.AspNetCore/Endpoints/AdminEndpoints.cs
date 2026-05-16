using System.Security.Claims;
using System.Text.RegularExpressions;
using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Ashlar.Postgres;
using Ashlar.Sample.AspNetCore.Extensions;
using Ashlar.Sample.AspNetCore.Views;
using Dapper;

namespace Ashlar.Sample.AspNetCore.Endpoints;

internal sealed record CreateProjectRequest(string Id, string Name);

internal static partial class AdminEndpoints
{
    private const string AdminPolicy = "admin";

    public static void MapAdminEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/admin", () => AppViews.RenderAdminManage()).RequireAuthorization(AdminPolicy);

        app.MapGet("/api/admin/users", async (
            IPostgresConnectionProvider connectionProvider,
            CancellationToken cancellationToken) =>
        {
            var connection = await connectionProvider.GetConnectionAsync(cancellationToken);
            await using (connection)
            {
                var users = await connection.Connection.QueryAsync("SELECT id, email, name FROM ashlar_users", transaction: connection.Transaction);
                return Results.Ok(users);
            }
        }).RequireAuthorization(AdminPolicy);

        app.MapGet("/api/admin/projects", async (
            IPostgresConnectionProvider connectionProvider,
            CancellationToken cancellationToken) =>
        {
            var connection = await connectionProvider.GetConnectionAsync(cancellationToken);
            await using (connection)
            {
                var projects = await connection.Connection.QueryAsync("SELECT id, name FROM sample_projects ORDER BY created_at", transaction: connection.Transaction);
                return Results.Ok(projects);
            }
        }).RequireAuthorization(AdminPolicy);

        app.MapPost("/api/admin/projects", async (
            CreateProjectRequest request,
            IPostgresConnectionProvider connectionProvider,
            CancellationToken cancellationToken) =>
        {
            if (string.IsNullOrWhiteSpace(request.Id) || string.IsNullOrWhiteSpace(request.Name) || request.Name.Length > 100)
            {
                return Results.BadRequest(new { error = "Invalid project data." });
            }

            if (!ProjectIdRegex().IsMatch(request.Id))
            {
                return Results.BadRequest(new { error = "Project ID must contain only lowercase letters, numbers, and dashes." });
            }

            var connection = await connectionProvider.GetConnectionAsync(cancellationToken);
            await using (connection)
            {
                var rows = await connection.Connection.ExecuteAsync(
                    "INSERT INTO sample_projects (id, name) VALUES (@Id, @Name) ON CONFLICT DO NOTHING",
                    new { request.Id, request.Name },
                    transaction: connection.Transaction);
                
                if (connection.Transaction != null)
                {
                    await connection.Transaction.CommitAsync(cancellationToken);
                }

                return rows > 0 
                    ? Results.Created($"/projects/{request.Id}", new { id = request.Id })
                    : Results.Conflict(new { error = "Project already exists." });
            }
        }).RequireAuthorization(AdminPolicy);

        app.MapPost("/api/projects/{projectId}/grants", async (
            string projectId,
            ProjectGrantRequest request,
            IAuthorizationGrantService grants,
            CancellationToken cancellationToken) =>
        {
            var result = await grants.CreateGrantAsync(new CreateAuthorizationGrantRequest(
                UserId: request.UserId,
                ScopeType: "project",
                ScopeId: projectId,
                Permission: "project.manage"), cancellationToken);

            if (!result.Succeeded || result.Value == null)
            {
                return Results.BadRequest(new { error = result.FailureReason ?? "Failed to create grant" });
            }

            return Results.Ok(new { result.Value.Id });
        }).RequireAuthorization(AdminPolicy);

        app.MapGet("/projects/{projectId}", async (
            string projectId,
            IAuthorizationEvaluator auth,
            ClaimsPrincipal user,
            CancellationToken cancellationToken) =>
        {
            var isAdmin = (await auth.EvaluateAsync(new AuthorizationEvaluationRequest(user.GetAshlarUserId(), Role: AdminPolicy), cancellationToken)).Succeeded;
            return AppViews.RenderProjectManage(projectId, isAdmin);
        }).RequireAuthorization("project.manage");
    }

    [GeneratedRegex("^[a-z0-9-]+$", RegexOptions.CultureInvariant)]
    private static partial Regex ProjectIdRegex();
}
