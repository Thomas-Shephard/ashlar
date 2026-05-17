using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;

namespace Ashlar.AspNetCore.Authorization;

/// <summary>
/// Handles Ashlar step-up authorization requirements using safe session claims.
/// </summary>
/// <param name="stepUpAuthentication">The step-up authentication service.</param>
/// <param name="httpContextAccessor">The HTTP context accessor.</param>
/// <param name="accountSecurity">The account security service.</param>
public sealed class AshlarStepUpAuthorizationHandler(
    IStepUpAuthenticationService stepUpAuthentication,
    IHttpContextAccessor httpContextAccessor,
    IAccountSecurityService? accountSecurity = null)
    : AuthorizationHandler<AshlarStepUpRequirement>
{
    private readonly IStepUpAuthenticationService _stepUpAuthentication = stepUpAuthentication ?? throw new ArgumentNullException(nameof(stepUpAuthentication));
    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));
    private readonly IAccountSecurityService? _accountSecurity = accountSecurity;

    /// <summary>
    /// Handles the step-up authorization requirement.
    /// </summary>
    /// <param name="context">The authorization handler context.</param>
    /// <param name="requirement">The step-up requirement.</param>
    /// <returns>A task that represents the asynchronous authorization operation.</returns>
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, AshlarStepUpRequirement requirement)
    {
        if (context.User.Identity is not { IsAuthenticated: true })
        {
            return;
        }

        var session = GetCurrentSession(context.User);
        if (session == null)
        {
            return;
        }

        if (requirement.Mode == AshlarStepUpMode.IfAvailable)
        {
            var requiresStepUp = await TryRequiresConditionalStepUpAsync(context.User, session, requirement);
            if (!requiresStepUp.HasValue)
            {
                return;
            }

            if (!requiresStepUp.Value)
            {
                context.Succeed(requirement);
                return;
            }
        }

        var stepUpRequirement = new StepUpRequirement(
            requirement.FreshnessWindow,
            requirement.AllowedProviders,
            requirement.AllowedFactors);

        var result = _stepUpAuthentication.Evaluate(new StepUpEvaluationRequest(session, stepUpRequirement));
        if (result.Succeeded)
        {
            context.Succeed(requirement);
        }
    }

    private AuthenticationSession? GetCurrentSession(System.Security.Claims.ClaimsPrincipal user)
    {
        var claimedSession = AshlarStepUpClaims.ToSession(user);
        if (claimedSession == null)
        {
            return null;
        }

        if (_httpContextAccessor.HttpContext?.Items[AshlarHttpContextItems.AuthenticationSession] is not AuthenticationSession currentSession)
        {
            return claimedSession;
        }

        return currentSession.Id == claimedSession.Id && currentSession.UserId == claimedSession.UserId
            ? currentSession
            : null;
    }

    private async Task<bool?> TryRequiresConditionalStepUpAsync(
        System.Security.Claims.ClaimsPrincipal user,
        AuthenticationSession session,
        AshlarStepUpRequirement requirement)
    {
        if (_accountSecurity == null)
        {
            return null;
        }

        var posture = await _accountSecurity.GetUserSecurityPostureAsync(
            session.UserId,
            new UserSecurityPostureRequest(GetTenant(user)),
            _httpContextAccessor.HttpContext?.RequestAborted ?? default);

        if (!posture.Succeeded || posture.Value == null)
        {
            return null;
        }

        return posture.Value.AdditionalVerificationFactors.Any(factor =>
            factor.IsUsable &&
            requirement.AllowedFactors.Contains(factor.FactorType, StringComparer.OrdinalIgnoreCase));
    }

    private static TenantContext? GetTenant(System.Security.Claims.ClaimsPrincipal user)
    {
        var tenantClaim = user.FindFirst(AshlarClaimTypes.TenantId)?.Value;
        return Guid.TryParse(tenantClaim, out var tenantId) ? new TenantContext(tenantId) : null;
    }
}
