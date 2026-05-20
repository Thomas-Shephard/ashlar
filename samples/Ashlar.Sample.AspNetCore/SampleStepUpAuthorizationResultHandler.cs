using Ashlar.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;

namespace Ashlar.Sample.AspNetCore;

internal sealed class SampleStepUpAuthorizationResultHandler : IAuthorizationMiddlewareResultHandler
{
    private const string StepUpHeaderName = "X-Ashlar-Step-Up";
    private readonly AuthorizationMiddlewareResultHandler _defaultHandler = new();

    public Task HandleAsync(
        RequestDelegate next,
        HttpContext context,
        AuthorizationPolicy policy,
        PolicyAuthorizationResult authorizeResult)
    {
        if (IsStepUpOnlyFailure(authorizeResult))
        {
            context.Response.Headers[StepUpHeaderName] = "required";
        }

        return _defaultHandler.HandleAsync(next, context, policy, authorizeResult);
    }

    private static bool IsStepUpOnlyFailure(PolicyAuthorizationResult authorizeResult)
    {
        if (!authorizeResult.Forbidden || authorizeResult.AuthorizationFailure == null)
        {
            return false;
        }

        var failedRequirements = authorizeResult.AuthorizationFailure.FailedRequirements.ToArray();
        return failedRequirements.Length > 0 &&
            failedRequirements.All(requirement => requirement is AshlarStepUpRequirement);
    }
}


