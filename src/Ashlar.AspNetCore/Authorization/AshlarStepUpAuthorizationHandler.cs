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
public sealed class AshlarStepUpAuthorizationHandler(
    IStepUpAuthenticationService stepUpAuthentication,
    IHttpContextAccessor httpContextAccessor)
    : AuthorizationHandler<AshlarStepUpRequirement>
{
    private readonly IStepUpAuthenticationService _stepUpAuthentication = stepUpAuthentication ?? throw new ArgumentNullException(nameof(stepUpAuthentication));
    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));

    /// <summary>
    /// Handles the step-up authorization requirement.
    /// </summary>
    /// <param name="context">The authorization handler context.</param>
    /// <param name="requirement">The step-up requirement.</param>
    /// <returns>A task that represents the asynchronous authorization operation.</returns>
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, AshlarStepUpRequirement requirement)
    {
        if (context.User.Identity is not { IsAuthenticated: true })
        {
            return Task.CompletedTask;
        }

        var session = GetCurrentSession(context.User);
        if (session == null)
        {
            return Task.CompletedTask;
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

        return Task.CompletedTask;
    }

    private AuthenticationSession? GetCurrentSession(System.Security.Claims.ClaimsPrincipal user)
    {
        var claimedSession = AshlarStepUpClaims.ToSession(user);
        if (claimedSession == null)
        {
            return null;
        }

        var currentSession = _httpContextAccessor.HttpContext?.Items[AshlarHttpContextItems.AuthenticationSession] as AuthenticationSession;
        if (currentSession == null)
        {
            return claimedSession;
        }

        return currentSession.Id == claimedSession.Id && currentSession.UserId == claimedSession.UserId
            ? currentSession
            : null;
    }
}
