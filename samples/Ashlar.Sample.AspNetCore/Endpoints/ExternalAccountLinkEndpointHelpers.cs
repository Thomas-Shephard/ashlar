using Ashlar.AspNetCore.Mfa;
using Ashlar.Sample.AspNetCore.Extensions;

namespace Ashlar.Sample.AspNetCore.Endpoints;

internal static class ExternalAccountLinkEndpointHelpers
{
    public static async Task<IResult> CompleteExternalAccountLinkAsync(
        IServiceProvider services,
        HttpContext httpContext,
        string providerName,
        Func<string, string, IResult> renderResult,
        CancellationToken cancellationToken)
    {
        if (!httpContext.TryGetAshlarSessionContext(out var userId, out var sessionId, out var tenant))
        {
            return Results.Forbid();
        }

        var proof = httpContext.CreateFreshMfaProof(
            services.GetRequiredService<IStepUpAuthenticationService>(),
            new StepUpRequirement(TimeSpan.FromMinutes(10), Purpose: "external-account-linking"));
        if (!proof.Succeeded || proof.Value == null)
        {
            return Results.Forbid();
        }

        var result = await services.GetRequiredService<AshlarExternalAccountLinkService>().CompleteExternalLinkAsync(
            httpContext,
            userId,
            providerName,
            proof.Value,
            sessionId,
            tenant ?? TenantContext.Global,
            cancellationToken);

        return result.Linked || result.AlreadyLinked
            ? renderResult($"{providerName} Account Linked", $"Your {providerName} account is linked.")
            : renderResult($"{providerName} Account Not Linked", $"Your {providerName} account could not be linked.");
    }
}
