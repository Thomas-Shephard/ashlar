using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Ashlar.Postgres;

namespace Ashlar.Sample.AspNetCore.Endpoints;

internal static class AdminEndpoints
{
    public static void MapAdminEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/admin", () => LandingPages.Layout("Admin Check", """
            <div class="card">
                <h1>Admin Access</h1>
                <div class="badge badge-success">Verified</div>
                <p style="margin-top: 1rem;">You have successfully accessed the protected administrative area.</p>
                <button class="secondary" onclick="location.href='/'">Back to Dashboard</button>
            </div>
        """)).RequireAuthorization("admin");

        app.MapGet("/admin/users", async (
            IPostgresConnectionProvider connectionProvider,
            CancellationToken cancellationToken) =>
        {
            var connection = await connectionProvider.GetConnectionAsync(cancellationToken);
            await using (connection)
            {
                var users = await Dapper.SqlMapper.QueryAsync(connection.Connection, "SELECT id, email, name FROM ashlar_users", transaction: connection.Transaction);
                return Results.Ok(users);
            }
        }).RequireAuthorization("admin");

        app.MapPost("/projects/{projectId}/grants", async (
            string projectId,
            ProjectGrantRequest request,
            IAuthorizationGrantService grants,
            CancellationToken cancellationToken) =>
        {
            var grant = await grants.CreateGrantAsync(new CreateAuthorizationGrantRequest(
                UserId: request.UserId,
                ScopeType: "project",
                ScopeId: projectId,
                Permission: "project.manage"), cancellationToken);

            return Results.Ok(new { grant.Id });
        }).RequireAuthorization("admin");

        app.MapGet("/projects/{projectId}/manage", (string projectId) => LandingPages.Layout("Project Management", $"""
            <div class="card">
                <h1>Manage Project: {System.Net.WebUtility.HtmlEncode(projectId)}</h1>
                <div class="badge badge-success">Manager</div>
                <p style="margin-top: 1rem;">You have 'project.manage' permission for project '{System.Net.WebUtility.HtmlEncode(projectId)}'.</p>
                <button class="secondary" onclick="location.href='/'">Back to Dashboard</button>
            </div>
        """)).RequireAuthorization("project.manage");
    }
}
