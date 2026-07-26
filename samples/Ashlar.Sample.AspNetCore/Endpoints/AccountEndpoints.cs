using System.Security.Claims;
using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Ashlar.AspNetCore.Sessions;
using Ashlar.Sample.AspNetCore.Extensions;
using Ashlar.Sample.AspNetCore.Views;
using Microsoft.Extensions.Options;

namespace Ashlar.Sample.AspNetCore.Endpoints;

internal static class AccountEndpoints
{
    public static void MapAccountEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/account", RenderAccountSettingsAsync).RequireAuthorization();

        app.MapPost("/api/account/profile", UpdateProfileAsync).RequireAuthorization().RequireSampleAntiforgery();

        app.MapGet("/account/verify-email", (string? t, string? u) => AppViews.RenderEmailVerification(t, u));

        app.MapPost("/api/account/verify-email/request", RequestEmailVerificationAsync).RequireAuthorization().RequireSampleAntiforgery();

        app.MapPost("/api/account/verify-email/confirm", ConfirmEmailVerificationAsync);

        app.MapPost("/api/account/change-email/request", RequestEmailChangeAsync).RequireAuthorization().RequireFreshMfa().RequireSampleAntiforgery();

        app.MapGet("/account/change-email", (string? t, string? u) => AppViews.RenderEmailChangeConfirm(t, u));

        app.MapPost("/api/account/change-email/confirm", ConfirmEmailChangeAsync);
    }

    private static async Task<IResult> RenderAccountSettingsAsync(
        IUserProfileService profiles,
        IAuthorizationEvaluator auth,
        IAccountSecurityService accountSecurity,
        IConfiguration configuration,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        var session = httpContext.GetValidatedAuthenticationSession();
        if (session == null) return Results.Unauthorized();
        var userId = session.UserId;
        var profile = await profiles.GetAsync(session, cancellationToken);
        if (!profile.Succeeded) return profile.FailureCode == AshlarFailureCodes.SessionNotFoundOrInactive ? Results.Unauthorized() : Results.NotFound();
        var ashlarUser = profile.Value!;

        var posture = await accountSecurity.GetUserSecurityPostureAsync(userId, cancellationToken: cancellationToken);
        if (!posture.Succeeded || posture.Value == null) return Results.NotFound();
        var isAdmin = (await auth.EvaluateAsync(new AuthorizationEvaluationRequest(userId, Role: "admin"), cancellationToken)).Succeeded;

        return AppViews.RenderAccountSettings(
            ashlarUser.DisplayEmail,
            ashlarUser.Name,
            posture.Value,
            isAdmin,
            SampleGoogleOidc.IsConfigured(configuration),
            SampleGitHubOAuth.IsConfigured(configuration));
    }

    private static async Task<IResult> UpdateProfileAsync(
        UpdateProfileRequest request,
        IUserProfileService profiles,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        var session = httpContext.GetValidatedAuthenticationSession();
        if (session == null) return Results.Unauthorized();
        var result = await profiles.UpdateNameAsync(new(session, request.Name, httpContext.ToAuditContext()), cancellationToken);
        if (result.Succeeded) return Results.Ok(new { name = result.Value!.Name });

        if (result.FailureCode == AshlarFailureCodes.SessionNotFoundOrInactive) return Results.Unauthorized();
        return result.FailureCode == AshlarFailureCodes.UserNotFoundOrUnavailable
            ? Results.NotFound()
            : Results.BadRequest(new { error = result.FailureMessage });
    }

    private static async Task<IResult> RequestEmailVerificationAsync(
        IEmailVerificationService emailVerification,
        HttpContext httpContext,
        IOptions<SampleAshlarOptions> options,
        CancellationToken cancellationToken)
    {
        var session = httpContext.GetValidatedAuthenticationSession();
        if (session == null) return Results.Unauthorized();
        var callback = new Uri(new Uri(options.Value.PublicAppUrl), "/account/verify-email");
        var result = await emailVerification.RequestVerificationAsync(new EmailVerificationRequest
        {
            Session = session,
            CallbackBaseUri = callback,
            Audit = httpContext.ToAuditContext()
        }, cancellationToken);

        return result.Succeeded ? Results.Accepted() : Results.BadRequest(SampleResultErrors.From(result));
    }

    private static async Task<IResult> ConfirmEmailVerificationAsync(
        SampleEmailVerificationConfirmRequest request,
        IEmailVerificationService emailVerification,
        HttpContext httpContext,
        string? u,
        ClaimsPrincipal userPrincipal,
        CancellationToken cancellationToken)
    {
        if (!TryResolveUserId(u, userPrincipal, out var userId))
        {
            return Results.BadRequest(new { error = "Missing user context." });
        }

        var result = await emailVerification.ConfirmVerificationAsync(new ConfirmEmailVerificationRequest { UserId = userId, Token = request.Token, Audit = httpContext.ToAuditContext() }, cancellationToken);
        return result.Succeeded ? Results.Ok() : Results.BadRequest(SampleResultErrors.From(result));
    }

    private static async Task<IResult> RequestEmailChangeAsync(
        SampleEmailChangeRequest request,
        IEmailChangeService emailChange,
        HttpContext httpContext,
        IOptions<SampleAshlarOptions> options,
        CancellationToken cancellationToken)
    {
        var session = httpContext.GetValidatedAuthenticationSession();
        if (session == null) return Results.Unauthorized();

        if (string.IsNullOrWhiteSpace(request.NewEmail) || !new System.ComponentModel.DataAnnotations.EmailAddressAttribute().IsValid(request.NewEmail))
        {
            return Results.BadRequest(new { error = "invalid_email" });
        }

        var callback = new Uri(new Uri(options.Value.PublicAppUrl), "/account/change-email");
        var result = await emailChange.RequestChangeAsync(new RequestEmailChangeRequest
        {
            Session = session,
            NewEmail = request.NewEmail,
            CallbackBaseUri = callback,
            Audit = httpContext.ToAuditContext()
        }, cancellationToken);

        if (result.Succeeded) return Results.Accepted();
        return result.FailureCode == AshlarFailureCodes.SessionNotFoundOrInactive
            ? Results.Unauthorized()
            : Results.BadRequest(SampleResultErrors.From(result));
    }

    private static async Task<IResult> ConfirmEmailChangeAsync(
        SampleEmailChangeConfirmRequest request,
        IEmailChangeService emailChange,
        HttpContext httpContext,
        string? u,
        ClaimsPrincipal userPrincipal,
        CancellationToken cancellationToken)
    {
        if (!TryResolveUserId(u, userPrincipal, out var userId))
        {
            return Results.BadRequest(new { error = "Missing user context." });
        }

        var result = await emailChange.ConfirmChangeAsync(new ConfirmEmailChangeRequest { UserId = userId, Token = request.Token, Audit = httpContext.ToAuditContext() }, cancellationToken);
        return result.Succeeded ? Results.Ok() : Results.BadRequest(SampleResultErrors.From(result));
    }

    private static bool TryResolveUserId(string? queryUserId, ClaimsPrincipal userPrincipal, out Guid userId)
    {
        if (Guid.TryParse(queryUserId, out userId))
        {
            return true;
        }

        if (userPrincipal.Identity?.IsAuthenticated != true)
        {
            return false;
        }

        userId = userPrincipal.GetAshlarUserId();
        return true;
    }
}
