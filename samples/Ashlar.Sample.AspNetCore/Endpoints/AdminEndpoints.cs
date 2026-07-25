using System.Security.Claims;
using System.Text.RegularExpressions;
using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Ashlar.AspNetCore.Mfa;
using Ashlar.Identity.Features.Mfa;
using Ashlar.Identity.Models.Administration;
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
    private static readonly StepUpRequirement AdminReadRequirement = new(TimeSpan.FromMinutes(5));
    private static readonly StepUpRequirement GrantAdministrationRequirement = new(TimeSpan.FromMinutes(5));

    public static void MapAdminEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/admin", () => AppViews.RenderAdminManage()).RequireAuthorization(AdminPolicy);
        MapAdminUserEndpoints(app);
        MapAdminProjectEndpoints(app);
    }

    private static void MapAdminUserEndpoints(IEndpointRouteBuilder app)
    {
        app.MapGet("/api/admin/users", ListAdminUsersAsync).RequireAuthorization().RequireFreshMfa();

        app.MapGet("/api/admin/users/{userId:guid}/security", GetAdminUserSecurityAsync).RequireAuthorization().RequireFreshMfa();

        app.MapPost("/api/admin/users/{userId:guid}/disable", async (
            Guid userId,
            AdminUserSecurityRequest? request,
            IAccountSecurityAdministrationService accountSecurity,
            StepUpAuthenticationService stepUp,
            IAuthorizationEvaluator auth,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            var adminRequest = await ToAdminRequestAsync(userId, request, httpContext, stepUp, auth, cancellationToken);
            return adminRequest == null
                ? Results.Forbid()
                : ToAdminSecurityResult(await accountSecurity.SetUserAccountStateAsync(
                    ToSetAccountStateRequest(adminRequest, UserAccountState.Disabled), cancellationToken));
        }).RequireAuthorization().RequireFreshMfa().RequireSampleAntiforgery();

        app.MapPost("/api/admin/users/{userId:guid}/account-state", async (
            Guid userId,
            AdminSetUserAccountStateRequest request,
            IAccountSecurityAdministrationService accountSecurity,
            StepUpAuthenticationService stepUp,
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
            StepUpAuthenticationService stepUp,
            IAuthorizationEvaluator auth,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            var adminRequest = await ToAdminRequestAsync(userId, request, httpContext, stepUp, auth, cancellationToken);
            return adminRequest == null
                ? Results.Forbid()
                : ToAdminSecurityResult(await accountSecurity.SetUserAccountStateAsync(
                    ToSetAccountStateRequest(adminRequest, UserAccountState.Active), cancellationToken));
        }).RequireAuthorization().RequireFreshMfa().RequireSampleAntiforgery();

        app.MapPost("/api/admin/users/{userId:guid}/sessions/revoke", async (
            Guid userId,
            AdminUserSecurityRequest? request,
            IAccountSecurityAdministrationService accountSecurity,
            StepUpAuthenticationService stepUp,
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
            StepUpAuthenticationService stepUp,
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

    private static async Task<IResult> ListAdminUsersAsync(
        IAuthorizationEvaluator auth,
        IUserAdministrationService users,
        StepUpAuthenticationService stepUp,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        var tenant = await ResolveAuthorizedAdminTenantScopeAsync(httpContext, auth, cancellationToken);
        if (tenant == null || !httpContext.TryGetAshlarSessionContext(out var actorUserId, out var sessionId, out var actorTenant) || actorTenant == null)
        {
            return Results.Forbid();
        }

        var proof = httpContext.CreateFreshMfaProof(stepUp, AdminReadRequirement, AccountSecurityActorContext.AdministrationReadProofPurpose);
        if (!proof.TryGetValue(out var freshProof)) return Results.Forbid();
        var result = await users.SearchUsersAsync(new SearchUsersRequest
        {
            Actor = new AccountSecurityActorContext(actorUserId, actorTenant, sessionId, freshProof, httpContext.ToAuditContext()),
            Tenant = tenant,
            Limit = 100
        }, cancellationToken);
        return result.Succeeded
            ? Results.Ok(result.Value!.Items.Select(user => new { id = user.UserId, user.DisplayEmail, user.Name }))
            : Results.Forbid();
    }

    private static async Task<IResult> GetAdminUserSecurityAsync(
        Guid userId,
        IUserAdministrationService users,
        StepUpAuthenticationService stepUp,
        IAuthorizationEvaluator auth,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        var tenant = await ResolveAuthorizedAdminTenantScopeAsync(httpContext, auth, cancellationToken);
        if (tenant == null || !httpContext.TryGetAshlarSessionContext(out var actorUserId, out var sessionId, out var actorTenant) || actorTenant == null)
        {
            return Results.Forbid();
        }

        var proof = httpContext.CreateFreshMfaProof(stepUp, AdminReadRequirement, AccountSecurityActorContext.AdministrationReadProofPurpose);
        if (!proof.TryGetValue(out var freshProof)) return Results.Forbid();
        var result = await users.GetUserDetailAsync(new UserAdministrationDetailRequest(
            userId, tenant, RecentSecurityEventWindow: TimeSpan.FromDays(30),
            Actor: new AccountSecurityActorContext(actorUserId, actorTenant, sessionId, freshProof, httpContext.ToAuditContext())), cancellationToken);
        return ToAccountSecurityPostureResult(result);
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
        StepUpAuthenticationService stepUp,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        var tenant = await ResolveAuthorizedAdminTenantScopeAsync(httpContext, auth, cancellationToken);
        if (tenant == null || !httpContext.TryGetAshlarSessionContext(out var actorUserId, out var sessionId, out var actorTenant) || actorTenant == null)
        {
            return Results.Forbid();
        }

        var proof = httpContext.CreateFreshMfaProof(stepUp, GrantAdministrationRequirement, IAuthorizationGrantService.AdministrationProofPurpose);
        if (!proof.TryGetValue(out var freshProof))
        {
            return Results.Json(SampleResultErrors.From(proof, "Fresh MFA proof required"), statusCode: StatusCodes.Status403Forbidden);
        }

        var actor = new AccountSecurityActorContext(actorUserId, actorTenant, sessionId, freshProof,
            httpContext.ToAuditContext());

        var result = await grants.CreateGrantAsync(new CreateAuthorizationGrantRequest(
            request.UserId, actor, actor.Audit, tenant, new AuthorizationGrantSpecification
            {
                ScopeType = "project",
                ScopeId = projectId,
                Permission = "project.manage"
            }), cancellationToken);

        return !result.Succeeded || result.Value == null
            ? Results.BadRequest(SampleResultErrors.From(result, "Failed to create grant"))
            : Results.Ok(new { result.Value.Id });
    }

    [GeneratedRegex("^[a-z0-9-]+$", RegexOptions.CultureInvariant)]
    private static partial Regex ProjectIdRegex();

    private static async Task<AccountSecurityAdministrationRequest?> ToAdminRequestAsync(
        Guid targetUserId,
        AdminUserSecurityRequest? request,
        HttpContext httpContext,
        StepUpAuthenticationService stepUp,
        IAuthorizationEvaluator auth,
        CancellationToken cancellationToken)
    {
        var tenant = await ResolveAuthorizedAdminTenantScopeAsync(httpContext, auth, cancellationToken);
        if (tenant == null || !httpContext.TryGetAshlarSessionContext(out var actorUserId, out var sessionId, out var actorTenant) || actorTenant == null)
        {
            return null;
        }

        var proof = httpContext.CreateFreshMfaProof(stepUp, AdminSecurityRequirement, IAccountSecurityAdministrationService.ProofPurpose);
        return !proof.TryGetValue(out var freshProof)
            ? null
            : new AccountSecurityAdministrationRequest(targetUserId,
                new AccountSecurityActorContext(actorUserId, actorTenant, sessionId, freshProof, httpContext.ToAuditContext()),
                tenant, reason: request?.Reason);
    }

    private static async Task<SetUserAccountStateAdministrationRequest?> ToSetAccountStateRequestAsync(
        Guid targetUserId,
        AdminSetUserAccountStateRequest request,
        HttpContext httpContext,
        StepUpAuthenticationService stepUp,
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
        new(request.TargetUserId, accountState,
            new AccountSecurityActorContext(request.ActorUserId, request.ActorTenant, request.CurrentSessionId, request.FreshMfaProof, request.Audit),
            request.Tenant, request.IncludeAllTenants, request.Reason,
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

    private static IResult ToAccountSecurityPostureResult(Result<UserAdministrationDetail> result)
    {
        if (result is { Succeeded: true, Value: { } detail })
        {
            return Results.Ok(detail.SecurityPosture);
        }

        if (result.FailureCode == AshlarFailureCodes.UserNotFound)
        {
            return Results.NotFound(SampleResultErrors.From(result, "User not found"));
        }

        return Results.Forbid();
    }
}
