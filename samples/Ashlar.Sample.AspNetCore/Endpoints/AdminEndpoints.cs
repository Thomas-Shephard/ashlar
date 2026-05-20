using System.Security.Claims;
using System.Text.RegularExpressions;
using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Ashlar.Sample.AspNetCore.Extensions;
using Ashlar.Sample.AspNetCore.Views;
using Dapper;

namespace Ashlar.Sample.AspNetCore.Endpoints;

internal sealed record CreateProjectRequest(string Id, string Name);
internal sealed record AdminUserSecurityRequest(string? Reason);

internal static partial class AdminEndpoints
{
    private const string AdminPolicy = "admin";

    public static void MapAdminEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/admin", () => AppViews.RenderAdminManage()).RequireAuthorization(AdminPolicy);

        app.MapGet("/api/admin/users", async (
            IPostgresConnectionProvider connectionProvider,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            var connection = await connectionProvider.GetConnectionAsync(cancellationToken);
            await using (connection)
            {
                var tenantId = httpContext.GetAshlarTenantId();
                var users = await connection.Connection.QueryAsync(new CommandDefinition(
                    "SELECT id, email, name FROM ashlar_users WHERE (@TenantId IS NULL OR tenant_id = @TenantId) ORDER BY email, id LIMIT 100",
                    new { TenantId = tenantId },
                    transaction: connection.Transaction,
                    cancellationToken: cancellationToken));

                return Results.Ok(users);
            }
        }).RequireAuthorization(AdminPolicy);

        app.MapGet("/api/admin/users/{userId:guid}/security", async (
            Guid userId,
            IAccountSecurityService accountSecurity,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            var result = await accountSecurity.GetUserSecurityPostureAsync(userId, new UserSecurityPostureRequest(ToTenantContext(httpContext), TimeSpan.FromDays(30)), cancellationToken);
            return ToUserSecurityPostureResult(result);
        }).RequireAuthorization(AdminPolicy);

        app.MapPost("/api/admin/users/{userId:guid}/disable", async (
            Guid userId,
            AdminUserSecurityRequest? request,
            IAccountSecurityService accountSecurity,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            var result = await accountSecurity.DisableUserAsync(userId, ToAdminRequest(request, httpContext), cancellationToken);
            return ToAdminSecurityResult(result);
        }).RequireAuthorization(AdminPolicy).RequireFreshMfa();

        app.MapPost("/api/admin/users/{userId:guid}/reactivate", async (
            Guid userId,
            AdminUserSecurityRequest? request,
            IAccountSecurityService accountSecurity,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            var result = await accountSecurity.ReactivateUserAsync(userId, ToAdminRequest(request, httpContext), cancellationToken);
            return ToAdminSecurityResult(result);
        }).RequireAuthorization(AdminPolicy).RequireFreshMfa();

        app.MapPost("/api/admin/users/{userId:guid}/sessions/revoke", async (
            Guid userId,
            AdminUserSecurityRequest? request,
            IAccountSecurityService accountSecurity,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            var result = await accountSecurity.RevokeSessionsAsync(userId, ToAdminRequest(request, httpContext), cancellationToken);
            return ToAdminSecurityResult(result);
        }).RequireAuthorization(AdminPolicy).RequireFreshMfa();

        app.MapPost("/api/admin/users/{userId:guid}/mfa/reset", async (
            Guid userId,
            AdminUserSecurityRequest? request,
            IAccountSecurityService accountSecurity,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            var result = await accountSecurity.ResetMfaAsync(userId, ToAdminRequest(request, httpContext), cancellationToken);
            return ToAdminSecurityResult(result);
        }).RequireAuthorization(AdminPolicy).RequireFreshMfa();

        app.MapGet("/api/admin/projects", async (
            IPostgresConnectionProvider connectionProvider,
            CancellationToken cancellationToken) =>
        {
            var connection = await connectionProvider.GetConnectionAsync(cancellationToken);
            await using (connection)
            {
                var projects = await connection.Connection.QueryAsync(new CommandDefinition(
                    "SELECT id, name FROM sample_projects ORDER BY created_at",
                    transaction: connection.Transaction,
                    cancellationToken: cancellationToken));

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
                var rows = await connection.Connection.ExecuteAsync(new CommandDefinition(
                    "INSERT INTO sample_projects (id, name) VALUES (@Id, @Name) ON CONFLICT DO NOTHING",
                    new { request.Id, request.Name },
                    transaction: connection.Transaction,
                    cancellationToken: cancellationToken));

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
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            var result = await grants.CreateGrantAsync(new CreateAuthorizationGrantRequest(
                UserId: request.UserId,
                TenantId: httpContext.GetAshlarTenantId(),
                ScopeType: "project",
                ScopeId: projectId,
                Permission: "project.manage",
                Audit: httpContext.ToAuditContext()), cancellationToken);

            if (!result.Succeeded || result.Value == null)
            {
                return Results.BadRequest(SampleResultErrors.From(result, "Failed to create grant"));
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

    private static AccountSecurityOperationRequest ToAdminRequest(AdminUserSecurityRequest? request, HttpContext httpContext)
    {
        return new AccountSecurityOperationRequest(httpContext.ToAuditContext(), ToTenantContext(httpContext), request?.Reason);
    }

    private static TenantContext? ToTenantContext(HttpContext httpContext)
    {
        var tenantId = httpContext.GetAshlarTenantId();
        return tenantId.HasValue ? new TenantContext(tenantId.Value) : null;
    }

    private static IResult ToAdminSecurityResult(Result<AccountSecurityOperationResult> result)
    {
        if (result.Succeeded)
        {
            return Results.Ok(result.Value);
        }

        var error = SampleResultErrors.From(result, "Account security operation failed.");
        return result.FailureCode == AshlarFailureCodes.UserNotFound
            ? Results.NotFound(error)
            : Results.BadRequest(error);
    }

    private static IResult ToUserSecurityPostureResult(Result<UserSecurityPosture> result)
    {
        if (result.Succeeded)
        {
            return Results.Ok(result.Value);
        }

        var error = SampleResultErrors.From(result, "User not found");
        return result.FailureCode == AshlarFailureCodes.UserNotFound
            ? Results.NotFound(error)
            : Results.BadRequest(error);
    }
}


