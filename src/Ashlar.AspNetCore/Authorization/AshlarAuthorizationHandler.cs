using System.Security.Claims;
using Ashlar.Authorization.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;

namespace Ashlar.AspNetCore.Authorization;

/// <summary>
/// Handles Ashlar authorization requirements by calling <see cref="IAuthorizationEvaluator"/>.
/// </summary>
public sealed class AshlarAuthorizationHandler : IAuthorizationHandler
{
    private readonly Ashlar.Authorization.Abstractions.IAuthorizationEvaluator _evaluator;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly AshlarAuthorizationOptions _options;

    /// <summary>
    /// Initializes a new instance of the <see cref="AshlarAuthorizationHandler"/> class.
    /// </summary>
    /// <param name="evaluator">The evaluator value.</param>
    /// <param name="httpContextAccessor">The http context accessor value.</param>
    /// <param name="options">The options value.</param>
    public AshlarAuthorizationHandler(
        Ashlar.Authorization.Abstractions.IAuthorizationEvaluator evaluator,
        IHttpContextAccessor httpContextAccessor,
        IOptions<AshlarAuthorizationOptions> options)
    {
        _evaluator = evaluator;
        _httpContextAccessor = httpContextAccessor;
        _options = options.Value;
    }

    /// <summary>
    /// Evaluates pending Ashlar authorization requirements for the current user.
    /// </summary>
    /// <param name="context">The authorization handler context.</param>
    /// <returns>A task that represents the asynchronous authorization operation.</returns>
    public async Task HandleAsync(AuthorizationHandlerContext context)
    {
        var user = context.User;
        if (user.Identity is not { IsAuthenticated: true })
        {
            return;
        }

        var userIdClaim = user.FindFirst(ClaimTypes.NameIdentifier);
        if (userIdClaim == null || !Guid.TryParse(userIdClaim.Value, out var userId))
        {
            return;
        }

        var httpContext = _httpContextAccessor.HttpContext;
        var routeData = httpContext?.GetRouteData();

        foreach (var requirement in context.PendingRequirements.ToList())
        {
            AuthorizationEvaluationRequest? request = null;

            if (requirement is AshlarPermissionRequirement permissionRequirement)
            {
                request = CreateRequest(userId, permissionRequirement.Permission, null, permissionRequirement.PolicyName, context, routeData);
            }
            else if (requirement is AshlarRoleRequirement roleRequirement)
            {
                request = CreateRequest(userId, null, roleRequirement.Role, roleRequirement.PolicyName, context, routeData);
            }

            if (request != null)
            {
                var result = await _evaluator.EvaluateAsync(request);
                if (result.Succeeded)
                {
                    context.Succeed(requirement);
                }
            }
        }
    }

    private AuthorizationEvaluationRequest? CreateRequest(
        Guid userId,
        string? permission,
        string? role,
        string policyName,
        AuthorizationHandlerContext context,
        RouteData? routeData)
    {
        if (!_options.PolicyScopes.TryGetValue(policyName, out var scopeOptions))
        {
            return new AuthorizationEvaluationRequest(userId, permission, role);
        }

        Guid? tenantId = null;
        if (!string.IsNullOrWhiteSpace(scopeOptions.TenantIdSource))
        {
            var tenantValue = scopeOptions.UseClaimForTenantId
                ? context.User.FindFirst(scopeOptions.TenantIdSource)?.Value
                : routeData?.Values[scopeOptions.TenantIdSource]?.ToString();

            if (!Guid.TryParse(tenantValue, out var parsedTenantId))
            {
                return null;
            }

            tenantId = parsedTenantId;
        }

        var scopeId = scopeOptions.FixedScopeId;
        if (!string.IsNullOrWhiteSpace(scopeOptions.ScopeIdRouteValueName) && string.IsNullOrEmpty(scopeId))
        {
            scopeId = routeData?.Values[scopeOptions.ScopeIdRouteValueName]?.ToString();
            if (string.IsNullOrWhiteSpace(scopeId))
            {
                return null;
            }
        }

        return new AuthorizationEvaluationRequest(
            UserId: userId,
            Permission: permission,
            Role: role,
            TenantId: tenantId,
            ScopeType: scopeOptions.ScopeType,
            ScopeId: scopeId);
    }
}


