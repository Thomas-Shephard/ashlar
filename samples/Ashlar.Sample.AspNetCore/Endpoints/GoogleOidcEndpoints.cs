using System.Security.Claims;
using Ashlar.AspNetCore.Sessions;
using Ashlar.Sample.AspNetCore.Extensions;
using Ashlar.Sample.AspNetCore.Views;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Ashlar.Sample.AspNetCore.Endpoints;

internal static class GoogleOidcEndpoints
{
    private const string GoogleSignInFailedTitle = "Google Sign-In Failed";

    public static void MapGoogleOidcEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/auth/google", StartGoogleSignIn);
        app.MapGet("/auth/google/callback", CompleteGoogleSignInAsync);

        app.MapGet("/invitations/accept/google", StartGoogleInvitationRegistration);
        app.MapGet("/invitations/accept/google/callback", CompleteGoogleInvitationRegistrationAsync);

        app.MapGet("/account/external/google/link", StartGoogleAccountLink).RequireAuthorization().RequireFreshMfaIfAvailable();
        app.MapGet("/account/external/google/link/callback", CompleteGoogleAccountLinkAsync).RequireAuthorization().RequireFreshMfaIfAvailable();
        app.MapPost("/api/account/external/google/unlink", UnlinkGoogleAccountAsync).RequireAuthorization().RequireFreshMfaIfAvailable();
    }

    private static IResult StartGoogleSignIn(IConfiguration configuration)
    {
        if (!SampleGoogleOidc.IsConfigured(configuration))
        {
            return Results.NotFound();
        }

        return Results.Challenge(new AuthenticationProperties { RedirectUri = "/auth/google/callback" }, [SampleGoogleOidc.ProviderName]);
    }

    private static async Task<IResult> CompleteGoogleSignInAsync(
        IConfiguration configuration,
        IServiceProvider services,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        if (!SampleGoogleOidc.IsConfigured(configuration))
        {
            return Results.NotFound();
        }

        var externalCredentialAuthentication = services.GetRequiredService<AshlarExternalCredentialAuthenticationService>();
        var orchestrator = services.GetRequiredService<IAuthenticationOrchestrator>();
        var signInManager = services.GetRequiredService<IAshlarSignInManager>();
        var result = await externalCredentialAuthentication.CompleteExternalAssertionAsync(httpContext, SampleGoogleOidc.ProviderName, cancellationToken);
        if (result.Succeeded && result.Assertion != null)
        {
            var mfaResult = await orchestrator.AuthenticateAsync(
                httpContext.ToAuthenticationContext(),
                result.Assertion,
                cancellationToken: cancellationToken);

            if (mfaResult.Status == MfaAuthenticationStatus.MfaRequired && mfaResult.HandshakeToken != null)
            {
                return AppViews.RenderGoogleMfaCallback(mfaResult.HandshakeToken, mfaResult.RequiredFactors ?? []);
            }

            if (mfaResult.Status == MfaAuthenticationStatus.RateLimited)
            {
                return AppViews.RenderGoogleOidcResult(
                    GoogleSignInFailedTitle,
                    "Too many Google sign-in attempts were made. Wait a few minutes and try again.");
            }

            if (mfaResult.Status != MfaAuthenticationStatus.Succeeded || mfaResult.User == null)
            {
                return AppViews.RenderGoogleOidcResult(
                    GoogleSignInFailedTitle,
                    "We could not complete additional verification for Google sign-in. Use another sign-in method and try again.");
            }

            await signInManager.SignInAsync(
                httpContext,
                mfaResult.User.Id,
                httpContext.ToSessionRequest(mfaResult.User, new AuthenticationProviderKey(ProviderType.Oidc, SampleGoogleOidc.ProviderName)),
                cancellationToken);
            return Results.Redirect("/?signedInWith=google");
        }

        if (result.Status == AshlarExternalAssertionStatus.AuthenticationFailed)
        {
            return AppViews.RenderGoogleOidcResult(
                GoogleSignInFailedTitle,
                "Google sign-in was not completed. Try again, or use another sign-in method.");
        }

        if (result.Status == AshlarExternalAssertionStatus.RateLimited)
        {
            return AppViews.RenderGoogleOidcResult(
                GoogleSignInFailedTitle,
                "Too many Google sign-in attempts were made. Wait a few minutes and try again.");
        }

        if (result.Status == AshlarExternalAssertionStatus.InvalidPrincipal)
        {
            return AppViews.RenderGoogleOidcResult(
                GoogleSignInFailedTitle,
                "Google did not return the account information needed to sign you in. Try again, or use another sign-in method.");
        }

        return AppViews.RenderGoogleOidcResult(
            GoogleSignInFailedTitle,
            "We could not sign you in with Google. The Google account may not be linked yet, or the Google sign-in was not completed. Sign in with another method, then link Google from Account -> Security.");
    }

    private static IResult StartGoogleInvitationRegistration(
        string t,
        string? userName,
        IConfiguration configuration)
    {
        if (!SampleGoogleOidc.IsConfigured(configuration))
        {
            return Results.NotFound();
        }

        if (string.IsNullOrWhiteSpace(t))
        {
            return AppViews.RenderGoogleOidcResult("Invitation Could Not Be Accepted", "This invitation could not be accepted with Google. Check that you used the invited email address and try again, or ask an administrator for a new invitation.");
        }

        var properties = new AuthenticationProperties { RedirectUri = "/invitations/accept/google/callback" };
        properties.Items[SampleGoogleOidc.InvitationTokenProperty] = t;
        if (!string.IsNullOrWhiteSpace(userName))
        {
            properties.Items[SampleGoogleOidc.InvitationDisplayNameProperty] = userName;
        }

        return Results.Challenge(properties, [SampleGoogleOidc.ProviderName]);
    }

    private static async Task<IResult> CompleteGoogleInvitationRegistrationAsync(
        IConfiguration configuration,
        IServiceProvider services,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        if (!SampleGoogleOidc.IsConfigured(configuration))
        {
            return Results.NotFound();
        }

        var options = services.GetRequiredService<IOptionsMonitor<AshlarOAuthOptions>>();
        var ticket = await httpContext.AuthenticateAsync(options.CurrentValue.ExternalSignInScheme);
        if (!ticket.Succeeded || ticket.Properties == null ||
            !ticket.Properties.Items.TryGetValue(SampleGoogleOidc.InvitationTokenProperty, out var invitationToken) ||
            string.IsNullOrWhiteSpace(invitationToken))
        {
            return AppViews.RenderGoogleOidcResult("Invitation Could Not Be Accepted", "This invitation could not be accepted with Google. Check that you used the invited email address and try again, or ask an administrator for a new invitation.");
        }

        var registration = services.GetRequiredService<AshlarOidcInvitationRegistrationService>();
        var signInManager = services.GetRequiredService<IAshlarSignInManager>();
        var users = services.GetRequiredService<IUserRepository>();
        ticket.Properties.Items.TryGetValue(SampleGoogleOidc.InvitationDisplayNameProperty, out var displayName);
        if (displayName == null && ticket.Principal != null)
        {
            displayName = AshlarOidcProfileMapper.GetSuggestedDisplayName(ticket.Principal);
        }

        var result = await registration.CompleteOidcInvitationRegistrationAsync(
            httpContext,
            invitationToken,
            SampleGoogleOidc.ProviderName,
            displayName,
            httpContext.ToAuthenticationContext(),
            cancellationToken);

        if (result.Registered && result.UserId is { } userId)
        {
            var user = await users.GetUserByIdAsync(userId, cancellationToken);
            await signInManager.SignInAsync(
                httpContext,
                userId,
                httpContext.ToSessionRequest(user, new AuthenticationProviderKey(ProviderType.Oidc, SampleGoogleOidc.ProviderName)),
                cancellationToken);
            return Results.Redirect("/");
        }

        return AppViews.RenderGoogleOidcResult("Invitation Could Not Be Accepted", "This invitation could not be accepted with Google. Check that you used the invited email address and try again, or ask an administrator for a new invitation.");
    }

    private static IResult StartGoogleAccountLink(IConfiguration configuration)
    {
        if (!SampleGoogleOidc.IsConfigured(configuration))
        {
            return Results.NotFound();
        }

        return Results.Challenge(new AuthenticationProperties { RedirectUri = "/account/external/google/link/callback" }, [SampleGoogleOidc.ProviderName]);
    }

    private static async Task<IResult> CompleteGoogleAccountLinkAsync(
        IConfiguration configuration,
        IServiceProvider services,
        ClaimsPrincipal user,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        if (!SampleGoogleOidc.IsConfigured(configuration))
        {
            return Results.NotFound();
        }

        var accountLink = services.GetRequiredService<AshlarExternalAccountLinkService>();
        var result = await accountLink.CompleteExternalLinkAsync(
            httpContext,
            user.GetAshlarUserId(),
            SampleGoogleOidc.ProviderName,
            httpContext.ToTenantContext(),
            cancellationToken: cancellationToken);

        return result.Linked || result.AlreadyLinked
            ? AppViews.RenderGoogleOidcResult("Google Account Linked", "Your Google account is linked.")
            : AppViews.RenderGoogleOidcResult("Google Account Not Linked", "Your Google account could not be linked.");
    }

    private static async Task<IResult> UnlinkGoogleAccountAsync(
        IConfiguration configuration,
        IServiceProvider services,
        ClaimsPrincipal user,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        if (!SampleGoogleOidc.IsConfigured(configuration))
        {
            return Results.NotFound();
        }

        var accountLink = services.GetRequiredService<AshlarExternalAccountLinkService>();
        var result = await accountLink.UnlinkExternalAccountAsync(
            user.GetAshlarUserId(),
            SampleGoogleOidc.ProviderName,
            new AccountSecurityOperationRequest(httpContext.ToAuditContext(), httpContext.ToTenantContext(), "sample-google-unlink"),
            cancellationToken);

        return result.Status switch
        {
            AshlarExternalAccountUnlinkStatus.Unlinked => Results.Ok(new { status = "unlinked" }),
            AshlarExternalAccountUnlinkStatus.WouldRemoveLastSignInMethod => Results.BadRequest(new { error = "add_another_sign_in_method_first" }),
            _ => Results.BadRequest(new { error = "google_unlink_failed" })
        };
    }
}
