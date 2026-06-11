using Ashlar.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

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

        var currentSession = GetCurrentSession(context.User);
        if (currentSession == null)
        {
            return;
        }

        if (requirement.Mode == AshlarStepUpMode.IfAvailable)
        {
            var requiresStepUp = await TryRequiresConditionalStepUpAsync(currentSession.HttpContext, currentSession.Session, requirement);
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

        var result = _stepUpAuthentication.Evaluate(new StepUpEvaluationRequest(currentSession.Session, stepUpRequirement));
        if (result.Succeeded)
        {
            context.Succeed(requirement);
        }
    }

    private CurrentSessionContext? GetCurrentSession(System.Security.Claims.ClaimsPrincipal user)
    {
        if (_httpContextAccessor.HttpContext is not { } currentHttpContext)
        {
            return null;
        }

        if (currentHttpContext.Items[AshlarHttpContextItems.AuthenticationSession] is not AuthenticationSession currentSession)
        {
            return null;
        }

        if (!AshlarStepUpClaims.MatchesSession(user, currentSession))
        {
            return null;
        }

        return new CurrentSessionContext(currentSession, currentHttpContext);
    }

    private async Task<bool?> TryRequiresConditionalStepUpAsync(
        HttpContext httpContext,
        AuthenticationSession session,
        AshlarStepUpRequirement requirement)
    {
        var accountSecurityService = _accountSecurity;
        if (accountSecurityService == null && httpContext.RequestServices != null)
        {
            accountSecurityService = httpContext.RequestServices.GetService<IAccountSecurityService>();
        }

        if (accountSecurityService == null)
        {
            return null;
        }

        var postureRequest = new AccountSecurityPostureRequest(GetTenant(session));
        var posture = await accountSecurityService.GetUserSecurityPostureAsync(
            session.UserId,
            postureRequest,
            httpContext.RequestAborted);

        if (!posture.Succeeded || posture.Value == null)
        {
            return null;
        }

        return posture.Value.AdditionalVerificationFactors.Any(factor => IsEligibleFactor(factor, requirement));
    }

    private static TenantContext? GetTenant(AuthenticationSession session)
    {
        if (!session.TenantId.HasValue)
        {
            return null;
        }

        return new TenantContext(session.TenantId.Value);
    }

    private static bool IsEligibleFactor(AdditionalVerificationFactorPosture factor, AshlarStepUpRequirement requirement)
    {
        if (!factor.IsUsable)
        {
            return false;
        }

        return requirement.AllowedFactors.Contains(factor.FactorType, StringComparer.OrdinalIgnoreCase);
    }

    private sealed record CurrentSessionContext(AuthenticationSession Session, HttpContext HttpContext);
}
