using System.Security.Claims;
using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Ashlar.Sample.AspNetCore.Extensions;
using Ashlar.Sample.AspNetCore.Views;
using Microsoft.Extensions.Options;

namespace Ashlar.Sample.AspNetCore.Endpoints;

internal static class AccountEndpoints
{
    public static void MapAccountEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/account", RenderAccountSettingsAsync).RequireAuthorization();

        app.MapPost("/api/account/profile", UpdateProfileAsync).RequireAuthorization();

        app.MapGet("/account/verify-email", (string? t, string? u) => AppViews.RenderEmailVerification(t, u));

        app.MapPost("/api/account/verify-email/request", RequestEmailVerificationAsync).RequireAuthorization();

        app.MapPost("/api/account/verify-email/confirm", ConfirmEmailVerificationAsync);

        app.MapPost("/api/account/change-email/request", RequestEmailChangeAsync).RequireAuthorization().RequireFreshMfa();

        app.MapGet("/account/change-email", (string? t, string? u) => AppViews.RenderEmailChangeConfirm(t, u));

        app.MapPost("/api/account/change-email/confirm", ConfirmEmailChangeAsync);
    }

    private static async Task<IResult> RenderAccountSettingsAsync(
        IIdentityRepository users,
        IAuthorizationEvaluator auth,
        IAccountSecurityService accountSecurity,
        ClaimsPrincipal user,
        CancellationToken cancellationToken)
    {
        var userId = user.GetAshlarUserId();
        var ashlarUser = await users.GetUserByIdAsync(userId, cancellationToken);
        if (ashlarUser == null) return Results.NotFound();

        var posture = await accountSecurity.GetUserSecurityPostureAsync(userId, cancellationToken: cancellationToken);
        if (!posture.Succeeded || posture.Value == null) return Results.NotFound();
        var isAdmin = (await auth.EvaluateAsync(new AuthorizationEvaluationRequest(userId, Role: "admin"), cancellationToken)).Succeeded;

        return AppViews.RenderAccountSettings(
            ashlarUser.Email,
            ashlarUser.Name,
            posture.Value,
            isAdmin);
    }

    private static async Task<IResult> UpdateProfileAsync(
        UpdateProfileRequest request,
        IIdentityRepository users,
        ClaimsPrincipal user,
        CancellationToken cancellationToken)
    {
        var userId = user.GetAshlarUserId();
        var ashlarUser = await users.GetUserByIdAsync(userId, cancellationToken);
        if (ashlarUser is not AshlarUser typedUser) return Results.NotFound();

        if (request.Name?.Length > 100)
        {
            return Results.BadRequest(new { error = "Name is too long." });
        }

        var updatedUser = typedUser with { Name = request.Name };
        await users.UpdateUserAsync(updatedUser, cancellationToken);

        return Results.Ok(new { name = updatedUser.Name });
    }

    private static async Task<IResult> RequestEmailVerificationAsync(
        IEmailVerificationService emailVerification,
        HttpContext httpContext,
        ClaimsPrincipal userPrincipal,
        IOptions<SampleAshlarOptions> options,
        CancellationToken cancellationToken)
    {
        var userId = userPrincipal.GetAshlarUserId();
        var callback = new Uri(new Uri(options.Value.PublicAppUrl), "/account/verify-email");
        var result = await emailVerification.RequestVerificationAsync(new EmailVerificationRequest
        {
            UserId = userId,
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
        ClaimsPrincipal userPrincipal,
        IOptions<SampleAshlarOptions> options,
        CancellationToken cancellationToken)
    {
        var userId = userPrincipal.GetAshlarUserId();

        if (string.IsNullOrWhiteSpace(request.NewEmail) || !new System.ComponentModel.DataAnnotations.EmailAddressAttribute().IsValid(request.NewEmail))
        {
            return Results.BadRequest(new { error = "invalid_email" });
        }

        var callback = new Uri(new Uri(options.Value.PublicAppUrl), "/account/change-email");
        var result = await emailChange.RequestChangeAsync(new RequestEmailChangeRequest
        {
            UserId = userId,
            NewEmail = request.NewEmail,
            CallbackBaseUri = callback,
            Audit = httpContext.ToAuditContext()
        }, cancellationToken);

        return result.Succeeded ? Results.Accepted() : Results.BadRequest(SampleResultErrors.From(result));
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
