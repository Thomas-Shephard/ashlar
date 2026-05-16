using Ashlar.AspNetCore.Sessions;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.Providers.Email;
using Ashlar.Sample.AspNetCore.Extensions;
using Ashlar.Sample.AspNetCore.Views;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Ashlar.Sample.AspNetCore.Endpoints;

internal static class AuthEndpoints
{
    public static void MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapPost("/api/auth/magic-link/request", async (
            MagicLinkRequest request,
            IMagicLinkSignInService magicLinks,
            IOptions<SampleAshlarOptions> options,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            if (string.IsNullOrWhiteSpace(request.Email) || !request.Email.Contains('@'))
            {
                return Results.BadRequest(new { error = "invalid_email" });
            }

            var callback = new Uri(new Uri(options.Value.PublicAppUrl), "/auth/magic-link");
            await magicLinks.RequestLinkAsync(request.Email, callback, httpContext.ToAuthenticationContext(request.Email), cancellationToken);
            return Results.Accepted(value: new { status = "requested" });
        });

        app.MapGet("/auth/magic-link", (string t) => AppViews.RenderMagicLinkCallback(t));

        app.MapPost("/api/auth/magic-link/callback", async Task<IResult> (
            MagicLinkCallbackRequest request,
            [FromServices] IAuthenticationOrchestrator orchestrator,
            IAshlarSignInManager signInManager,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            var response = await orchestrator.AuthenticateAsync(
                httpContext.ToAuthenticationContext(),
                new MagicLinkAssertion(request.T),
                cancellationToken: cancellationToken);

            return await HandleAuthResponse(response, signInManager, httpContext, cancellationToken);
        });

        app.MapPost("/api/auth/email-code/request", async (
            EmailCodeRequest request,
            IEmailCodeSignInService emailCodes,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            if (string.IsNullOrWhiteSpace(request.Email) || !new System.ComponentModel.DataAnnotations.EmailAddressAttribute().IsValid(request.Email))
            {
                return Results.BadRequest(new { error = "invalid_email" });
            }

            await emailCodes.RequestCodeAsync(request.Email, httpContext.ToAuthenticationContext(request.Email), cancellationToken);
            return Results.Accepted(value: new { status = "requested" });
        });

        app.MapPost("/api/auth/email-code/verify", async Task<IResult> (
            EmailCodeVerifyRequest request,
            [FromServices] IAuthenticationOrchestrator orchestrator,
            IAshlarSignInManager signInManager,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            var response = await orchestrator.AuthenticateAsync(
                httpContext.ToAuthenticationContext(request.Email),
                new EmailCodeAssertion(request.Code),
                cancellationToken: cancellationToken);

            return await HandleAuthResponse(response, signInManager, httpContext, cancellationToken);
        });

        app.MapPost("/api/auth/logout", async (IAshlarSignInManager signInManager, HttpContext httpContext, CancellationToken cancellationToken) =>
        {
            await signInManager.SignOutAsync(httpContext, cancellationToken: cancellationToken);
            return Results.Redirect("/");
        });
    }

    private static async Task<IResult> HandleAuthResponse(MfaAuthenticationResult response, IAshlarSignInManager signInManager, HttpContext httpContext, CancellationToken cancellationToken)
    {
        if (response.Status == MfaAuthenticationStatus.Failed || response.User == null)
        {
            return Results.BadRequest(new { error = response.ErrorMessage ?? response.Status.ToString() });
        }

        if (response.Status == MfaAuthenticationStatus.MfaRequired)
        {
            return Results.Ok(new
            {
                status = "mfa_required",
                handshakeToken = response.HandshakeToken,
                requiredFactors = response.RequiredFactors
            });
        }

        await signInManager.SignInAsync(httpContext, response.User.Id, httpContext.ToSessionRequest(), cancellationToken);
        return Results.Ok(new { userId = response.User.Id });
    }
}
