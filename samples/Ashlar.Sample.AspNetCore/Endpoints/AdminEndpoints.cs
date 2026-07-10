using System.Security.Claims;
using System.Text.RegularExpressions;
using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Ashlar.AspNetCore.Mfa;
using Ashlar.Sample.AspNetCore.Extensions;
using Ashlar.Sample.AspNetCore.Views;
using Dapper;
using Npgsql;

namespace Ashlar.Sample.AspNetCore.Endpoints;

internal sealed record CreateProjectRequest(string Id, string Name);
internal sealed record AdminUserSecurityRequest(string? Reason);
internal sealed record AdminSetUserAccountStateRequest(UserAccountState AccountState, string? Reason, bool? RevokeSessionsAndRememberedMfaDevices);

internal static partial class AdminEndpoints
{
    private const string AdminPolicy = "admin";
    private static readonly StepUpRequirement AdminSecurityRequirement = new(TimeSpan.FromMinutes(5));

    public static void MapAdminEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/admin", () => AppViews.RenderAdminManage()).RequireAuthorization(AdminPolicy);
        MapAdminUserEndpoints(app);
        MapAdminProjectEndpoints(app);
    }

    private static void MapAdminUserEndpoints(IEndpointRouteBuilder app)
    {
        app.MapGet("/api/admin/users", async (
            IAuthorizationEvaluator auth,
            NpgsqlDataSource dataSource,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            var tenant = await ResolveAuthorizedAdminTenantScopeAsync(httpContext, auth, cancellationToken);
            if (tenant == null)
            {
                return Results.Forbid();
            }

            await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
            var command = tenant.TenantId.HasValue
                ? new CommandDefinition(
                    "SELECT id, display_email AS displayEmail, name FROM ashlar_users WHERE tenant_id = @TenantId ORDER BY display_email, id LIMIT 100",
                    new { tenant.TenantId },
                    cancellationToken: cancellationToken)
                : new CommandDefinition(
                    "SELECT id, display_email AS displayEmail, name FROM ashlar_users WHERE tenant_id IS NULL ORDER BY display_email, id LIMIT 100",
                    cancellationToken: cancellationToken);
            var users = await connection.QueryAsync(command);

            return Results.Ok(users);
        }).RequireAuthorization();

        app.MapGet("/api/admin/users/{userId:guid}/security", async (
            Guid userId,
            IAccountSecurityService accountSecurity,
            IAuthorizationEvaluator auth,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            var tenant = await ResolveAuthorizedAdminTenantScopeAsync(httpContext, auth, cancellationToken);
            if (tenant == null)
            {
                return Results.Forbid();
            }

            var result = await accountSecurity.GetUserSecurityPostureAsync(userId, new AccountSecurityPostureRequest(tenant, TimeSpan.FromDays(30)), cancellationToken);
            return ToAccountSecurityPostureResult(result);
        }).RequireAuthorization();

        app.MapPost("/api/admin/users/{userId:guid}/disable", async (
            Guid userId,
            AdminUserSecurityRequest? request,
            IAccountSecurityAdministrationService accountSecurity,
            IStepUpAuthenticationService stepUp,
            IAuthorizationEvaluator auth,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            return await SetUserAccountStateAsync(userId, UserAccountState.Disabled, request, accountSecurity, stepUp, auth, httpContext, cancellationToken);
        }).RequireAuthorization().RequireFreshMfa().RequireSampleAntiforgery();

        app.MapPost("/api/admin/users/{userId:guid}/account-state", async (
            Guid userId,
            AdminSetUserAccountStateRequest request,
            IAccountSecurityAdministrationService accountSecurity,
            IStepUpAuthenticationService stepUp,
            IAuthorizationEvaluator auth,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            if (!Enum.IsDefined(request.AccountState))
            {
                return Results.BadRequest(new { error = "Invalid account state." });
            }

            var setAccountStateRequest = await ToSetAccountStateRequestAsync(userId, request, httpContext, stepUp, auth, cancellationToken);
            return setAccountStateRequest == null
                ? Results.Forbid()
                : ToAdminSecurityResult(await accountSecurity.SetUserAccountStateAsync(setAccountStateRequest, cancellationToken));
        }).RequireAuthorization().RequireFreshMfa().RequireSampleAntiforgery();

        app.MapPost("/api/admin/users/{userId:guid}/reactivate", async (
            Guid userId,
            AdminUserSecurityRequest? request,
            IAccountSecurityAdministrationService accountSecurity,
            IStepUpAuthenticationService stepUp,
            IAuthorizationEvaluator auth,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            return await SetUserAccountStateAsync(userId, UserAccountState.Active, request, accountSecurity, stepUp, auth, httpContext, cancellationToken);
        }).RequireAuthorization().RequireFreshMfa().RequireSampleAntiforgery();

        app.MapPost("/api/admin/users/{userId:guid}/sessions/revoke", async (
            Guid userId,
            AdminUserSecurityRequest? request,
            IAccountSecurityAdministrationService accountSecurity,
            IStepUpAuthenticationService stepUp,
            IAuthorizationEvaluator auth,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            var adminRequest = await ToAdminRequestAsync(userId, request, httpContext, stepUp, auth, cancellationToken);
            return adminRequest == null
                ? Results.Forbid()
                : ToAdminSecurityResult(await accountSecurity.RevokeSessionsAsync(adminRequest, cancellationToken));
        }).RequireAuthorization().RequireFreshMfa().RequireSampleAntiforgery();

        app.MapPost("/api/admin/users/{userId:guid}/mfa/reset", async (
            Guid userId,
            AdminUserSecurityRequest? request,
            IAccountSecurityAdministrationService accountSecurity,
            IStepUpAuthenticationService stepUp,
            IAuthorizationEvaluator auth,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            var adminRequest = await ToAdminRequestAsync(userId, request, httpContext, stepUp, auth, cancellationToken);
            return adminRequest == null
                ? Results.Forbid()
                : ToAdminSecurityResult(await accountSecurity.ResetMfaAsync(adminRequest, cancellationToken));
        }).RequireAuthorization().RequireFreshMfa().RequireSampleAntiforgery();
    }

    private static void MapAdminProjectEndpoints(IEndpointRouteBuilder app)
    {
        app.MapGet("/api/admin/projects", ListProjectsAsync).RequireAuthorization();
        app.MapPost("/api/admin/projects", CreateProjectAsync).RequireAuthorization().RequireFreshMfa().RequireSampleAntiforgery();
        app.MapPost("/api/projects/{projectId}/grants", CreateProjectGrantAsync).RequireAuthorization().RequireFreshMfa().RequireSampleAntiforgery();

        app.MapGet("/projects/{projectId}", async (
            string projectId,
            IAuthorizationEvaluator auth,
            ClaimsPrincipal user,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            var isAdmin = (await auth.EvaluateAsync(new AuthorizationEvaluationRequest(user.GetAshlarUserId(), Role: AdminPolicy, TenantId: httpContext.GetDemoTenantIdFromUntrustedHeader()), cancellationToken)).Succeeded;
            return AppViews.RenderProjectManage(projectId, isAdmin);
        }).RequireAuthorization("project.manage");
    }

    private static async Task<IResult> ListProjectsAsync(
        IAuthorizationEvaluator auth,
        NpgsqlDataSource dataSource,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        if (!await IsAuthorizedGlobalAdminScopeAsync(httpContext, auth, cancellationToken))
        {
            return Results.Forbid();
        }

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        var projects = await connection.QueryAsync(new CommandDefinition(
            "SELECT id, name FROM sample_projects ORDER BY created_at",
            cancellationToken: cancellationToken));

        return Results.Ok(projects);
    }

    private static async Task<IResult> CreateProjectAsync(
        CreateProjectRequest request,
        IAuthorizationEvaluator auth,
        NpgsqlDataSource dataSource,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        if (!await IsAuthorizedGlobalAdminScopeAsync(httpContext, auth, cancellationToken))
        {
            return Results.Forbid();
        }

        if (string.IsNullOrWhiteSpace(request.Id) || string.IsNullOrWhiteSpace(request.Name) || request.Name.Length > 100)
        {
            return Results.BadRequest(new { error = "Invalid project data." });
        }

        if (!ProjectIdRegex().IsMatch(request.Id))
        {
            return Results.BadRequest(new { error = "Project ID must contain only lowercase letters, numbers, and dashes." });
        }

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        var rows = await connection.ExecuteAsync(new CommandDefinition(
            "INSERT INTO sample_projects (id, name) VALUES (@Id, @Name) ON CONFLICT DO NOTHING",
            new { request.Id, request.Name },
            cancellationToken: cancellationToken));

        return rows > 0
            ? Results.Created($"/projects/{request.Id}", new { id = request.Id })
            : Results.Conflict(new { error = "Project already exists." });
    }

    private static async Task<IResult> CreateProjectGrantAsync(
        string projectId,
        ProjectGrantRequest request,
        IAuthorizationGrantService grants,
        IAuthorizationEvaluator auth,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        var tenant = await ResolveAuthorizedAdminTenantScopeAsync(httpContext, auth, cancellationToken);
        if (tenant == null)
        {
            return Results.Forbid();
        }

        var result = await grants.CreateGrantAsync(new CreateAuthorizationGrantRequest(
            UserId: request.UserId,
            TenantId: tenant.TenantId,
            ScopeType: "project",
            ScopeId: projectId,
            Permission: "project.manage",
            Audit: httpContext.ToAuditContext()), cancellationToken);

        return !result.Succeeded || result.Value == null
            ? Results.BadRequest(SampleResultErrors.From(result, "Failed to create grant"))
            : Results.Ok(new { result.Value.Id });
    }

    [GeneratedRegex("^[a-z0-9-]+$", RegexOptions.CultureInvariant)]
    private static partial Regex ProjectIdRegex();

    private static async Task<IResult> SetUserAccountStateAsync(
        Guid userId,
        UserAccountState accountState,
        AdminUserSecurityRequest? request,
        IAccountSecurityAdministrationService accountSecurity,
        IStepUpAuthenticationService stepUp,
        IAuthorizationEvaluator auth,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        var adminRequest = await ToAdminRequestAsync(userId, request, httpContext, stepUp, auth, cancellationToken);
        if (adminRequest == null)
        {
            return Results.Forbid();
        }

        return ToAdminSecurityResult(await accountSecurity.SetUserAccountStateAsync(
            ToSetAccountStateRequest(adminRequest, accountState),
            cancellationToken));
    }

    private static async Task<AccountSecurityAdministrationRequest?> ToAdminRequestAsync(
        Guid targetUserId,
        AdminUserSecurityRequest? request,
        HttpContext httpContext,
        IStepUpAuthenticationService stepUp,
        IAuthorizationEvaluator auth,
        CancellationToken cancellationToken)
    {
        var tenant = await ResolveAuthorizedAdminTenantScopeAsync(httpContext, auth, cancellationToken);
        if (tenant == null || !httpContext.TryGetAshlarSessionContext(out var actorUserId, out var sessionId, out var actorTenant) || actorTenant == null)
        {
            return null;
        }

        var proof = httpContext.CreateFreshMfaProof(stepUp, AdminSecurityRequirement);
        return !proof.TryGetValue(out var freshProof)
            ? null
            : new AccountSecurityAdministrationRequest(targetUserId, actorUserId, actorTenant, sessionId, freshProof,
                httpContext.ToAuditContext(), tenant, reason: request?.Reason);
    }

    private static async Task<SetUserAccountStateAdministrationRequest?> ToSetAccountStateRequestAsync(
        Guid targetUserId,
        AdminSetUserAccountStateRequest request,
        HttpContext httpContext,
        IStepUpAuthenticationService stepUp,
        IAuthorizationEvaluator auth,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var baseRequest = await ToAdminRequestAsync(targetUserId, new AdminUserSecurityRequest(request.Reason), httpContext, stepUp, auth, cancellationToken);
        return baseRequest == null ? null : ToSetAccountStateRequest(
            baseRequest,
            request.AccountState,
            request.RevokeSessionsAndRememberedMfaDevices ?? true);
    }

    private static SetUserAccountStateAdministrationRequest ToSetAccountStateRequest(
        AccountSecurityAdministrationRequest request,
        UserAccountState accountState,
        bool revokeSessionsAndRememberedMfaDevices = true) =>
        new(request.TargetUserId, accountState, request.ActorUserId, request.ActorTenant, request.CurrentSessionId,
            request.FreshMfaProof, request.Audit, request.Tenant, request.IncludeAllTenants, request.Reason,
            revokeSessionsAndRememberedMfaDevices);

    private static async Task<TenantContext?> ResolveAuthorizedAdminTenantScopeAsync(
        HttpContext httpContext,
        IAuthorizationEvaluator auth,
        CancellationToken cancellationToken)
    {
        var tenantId = httpContext.GetDemoTenantIdFromUntrustedHeader();
        var result = await auth.EvaluateAsync(
            new AuthorizationEvaluationRequest(httpContext.User.GetAshlarUserId(), Role: AdminPolicy, TenantId: tenantId),
            cancellationToken);
        if (!result.Succeeded)
        {
            return null;
        }

        return tenantId.HasValue ? new TenantContext(tenantId.Value) : TenantContext.Global;
    }

    private static async Task<bool> IsAuthorizedGlobalAdminScopeAsync(
        HttpContext httpContext,
        IAuthorizationEvaluator auth,
        CancellationToken cancellationToken)
    {
        if (httpContext.GetDemoTenantIdFromUntrustedHeader().HasValue)
        {
            return false;
        }

        var result = await auth.EvaluateAsync(
            new AuthorizationEvaluationRequest(httpContext.User.GetAshlarUserId(), Role: AdminPolicy),
            cancellationToken);
        return result.Succeeded;
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

    private static IResult ToAccountSecurityPostureResult(Result<AccountSecurityPosture> result)
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
