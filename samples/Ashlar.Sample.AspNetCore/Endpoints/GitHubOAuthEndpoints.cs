using System.Security.Claims;
using Ashlar.AspNetCore.Mfa;
using Ashlar.AspNetCore.Sessions;
using Ashlar.Sample.AspNetCore.Extensions;
using Ashlar.Sample.AspNetCore.Views;
using Microsoft.AspNetCore.Authentication;

namespace Ashlar.Sample.AspNetCore.Endpoints;

internal static class GitHubOAuthEndpoints
{
    private const string GitHubSignInFailedTitle = "GitHub Sign-In Failed";

    public static void MapGitHubOAuthEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/auth/github", StartGitHubSignIn);
        app.MapGet("/auth/github/callback", CompleteGitHubSignInAsync);

        app.MapGet("/account/external/github/link", StartGitHubAccountLink).RequireAuthorization().RequireFreshMfa();
        app.MapGet("/account/external/github/link/callback", CompleteGitHubAccountLinkAsync).RequireAuthorization().RequireFreshMfa();
        app.MapPost("/api/account/external/github/unlink", UnlinkGitHubAccountAsync).RequireAuthorization().RequireFreshMfaIfAvailable().RequireSampleAntiforgery();
    }

    private static IResult StartGitHubSignIn(IConfiguration configuration)
    {
        if (!SampleGitHubOAuth.IsConfigured(configuration))
        {
            return Results.NotFound();
        }

        return Results.Challenge(new AuthenticationProperties { RedirectUri = "/auth/github/callback" }, [SampleGitHubOAuth.ProviderName]);
    }

    private static async Task<IResult> CompleteGitHubSignInAsync(
        IConfiguration configuration,
        IServiceProvider services,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        if (!SampleGitHubOAuth.IsConfigured(configuration))
        {
            return Results.NotFound();
        }

        var externalCredentialAuthentication = services.GetRequiredService<AshlarExternalCredentialAuthenticationService>();
        var orchestrator = services.GetRequiredService<IAuthenticationOrchestrator>();
        var signInManager = services.GetRequiredService<IAshlarSignInManager>();
        var result = await externalCredentialAuthentication.CompleteExternalAssertionAsync(httpContext, SampleGitHubOAuth.ProviderName, cancellationToken);
        if (result.Succeeded && result.Assertion != null)
        {
            var mfaResult = await orchestrator.AuthenticateAsync(
                httpContext.ToAuthenticationContext(),
                result.Assertion,
                cancellationToken: cancellationToken);

            if (mfaResult.Status == MfaAuthenticationStatus.MfaRequired && mfaResult.HandshakeToken != null)
            {
                return AppViews.RenderExternalProviderMfaCallback("GitHub", "github", mfaResult.HandshakeToken, mfaResult.RequiredFactors ?? []);
            }

            if (mfaResult.Status == MfaAuthenticationStatus.RateLimited)
            {
                return AppViews.RenderExternalProviderResult(
                    GitHubSignInFailedTitle,
                    "Too many GitHub sign-in attempts were made. Wait a few minutes and try again.");
            }

            if (mfaResult.Status != MfaAuthenticationStatus.Succeeded || mfaResult.User == null)
            {
                return AppViews.RenderExternalProviderResult(
                    GitHubSignInFailedTitle,
                    "We could not complete additional verification for GitHub sign-in. Use another sign-in method and try again.");
            }

            await signInManager.SignInAsync(
                httpContext,
                mfaResult.User.Id,
                httpContext.ToSessionRequest(mfaResult.User, new AuthenticationProviderKey(ProviderType.OAuth, SampleGitHubOAuth.ProviderName)),
                cancellationToken);
            return Results.Redirect("/?signedInWith=github");
        }

        if (result.Status == AshlarExternalAssertionStatus.AuthenticationFailed)
        {
            return AppViews.RenderExternalProviderResult(
                GitHubSignInFailedTitle,
                "GitHub sign-in was not completed. Try again, or use another sign-in method.");
        }

        if (result.Status == AshlarExternalAssertionStatus.RateLimited)
        {
            return AppViews.RenderExternalProviderResult(
                GitHubSignInFailedTitle,
                "Too many GitHub sign-in attempts were made. Wait a few minutes and try again.");
        }

        if (result.Status == AshlarExternalAssertionStatus.InvalidPrincipal)
        {
            return AppViews.RenderExternalProviderResult(
                GitHubSignInFailedTitle,
                "GitHub did not return the account information needed to sign you in. Try again, or use another sign-in method.");
        }

        return AppViews.RenderExternalProviderResult(
            GitHubSignInFailedTitle,
            "We could not sign you in with GitHub. The GitHub account may not be linked yet, or the GitHub sign-in was not completed. Sign in with another method, then link GitHub from Account -> Security.");
    }

    private static IResult StartGitHubAccountLink(IConfiguration configuration)
    {
        if (!SampleGitHubOAuth.IsConfigured(configuration))
        {
            return Results.NotFound();
        }

        return Results.Challenge(new AuthenticationProperties { RedirectUri = "/account/external/github/link/callback" }, [SampleGitHubOAuth.ProviderName]);
    }

    private static async Task<IResult> CompleteGitHubAccountLinkAsync(
        IConfiguration configuration,
        IServiceProvider services,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        if (!SampleGitHubOAuth.IsConfigured(configuration))
        {
            return Results.NotFound();
        }

        return await ExternalAccountLinkEndpointHelpers.CompleteExternalAccountLinkAsync(
            services,
            httpContext,
            SampleGitHubOAuth.ProviderName,
            AppViews.RenderExternalProviderResult,
            cancellationToken);
    }

    private static async Task<IResult> UnlinkGitHubAccountAsync(
        IConfiguration configuration,
        IServiceProvider services,
        ClaimsPrincipal user,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        if (!SampleGitHubOAuth.IsConfigured(configuration))
        {
            return Results.NotFound();
        }

        var accountLink = services.GetRequiredService<AshlarExternalAccountLinkService>();
        if (!httpContext.TryGetAshlarSessionContext(out var userId, out var sessionId, out _)) return Results.Forbid();
        var proof = httpContext.CreateFreshMfaProof(
            services.GetRequiredService<IStepUpAuthenticationService>(),
            new StepUpRequirement(TimeSpan.FromMinutes(10), Purpose: "external-account-unlinking"));
        if (!proof.Succeeded || proof.Value == null) return Results.Forbid();

        var result = await accountLink.UnlinkExternalAccountAsync(
            userId,
            SampleGitHubOAuth.ProviderName,
            proof.Value,
            sessionId,
            new AccountSecurityOperationRequest(httpContext.ToAuditContext(), httpContext.ToTenantContext(), "sample-github-unlink"),
            cancellationToken);

        return result.Status switch
        {
            AshlarExternalAccountUnlinkStatus.Unlinked => Results.Ok(new { status = "unlinked" }),
            AshlarExternalAccountUnlinkStatus.WouldRemoveLastSignInMethod => Results.BadRequest(new { error = "add_another_sign_in_method_first" }),
            _ => Results.BadRequest(new { error = "github_unlink_failed" })
        };
    }
}
