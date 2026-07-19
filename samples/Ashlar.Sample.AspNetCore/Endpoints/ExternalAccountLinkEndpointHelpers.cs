using Ashlar.AspNetCore.Mfa;
using Ashlar.Identity.Features.Mfa;
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
            services.GetRequiredService<StepUpAuthenticationService>(),
            new StepUpRequirement(TimeSpan.FromMinutes(10)),
            AshlarExternalAccountLinkService.LinkingProofPurpose);
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

    public static async Task<IResult> UnlinkExternalAccountAsync(
        IServiceProvider services,
        HttpContext httpContext,
        string providerName,
        string auditReason,
        string failureError,
        CancellationToken cancellationToken)
    {
        if (!httpContext.TryGetAshlarSessionContext(out var userId, out var sessionId, out _))
        {
            return Results.Forbid();
        }

        var proof = httpContext.CreateFreshMfaProof(
            services.GetRequiredService<StepUpAuthenticationService>(),
            new StepUpRequirement(TimeSpan.FromMinutes(10)),
            AshlarExternalAccountLinkService.UnlinkingProofPurpose);
        if (!proof.Succeeded || proof.Value == null)
        {
            return Results.Forbid();
        }

        var result = await services.GetRequiredService<AshlarExternalAccountLinkService>().UnlinkExternalAccountAsync(
            userId,
            providerName,
            proof.Value,
            sessionId,
            new AshlarExternalAccountUnlinkRequest(httpContext.ToAuditContext(), httpContext.ToTenantContext(), auditReason),
            cancellationToken);

        return result.Status switch
        {
            AshlarExternalAccountUnlinkStatus.Unlinked => Results.Ok(new { status = "unlinked" }),
            AshlarExternalAccountUnlinkStatus.WouldRemoveLastSignInMethod => Results.BadRequest(new { error = "add_another_sign_in_method_first" }),
            _ => Results.BadRequest(new { error = failureError })
        };
    }
}
