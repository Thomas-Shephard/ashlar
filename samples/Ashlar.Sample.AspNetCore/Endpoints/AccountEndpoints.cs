using System.Security.Claims;
using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Sample.AspNetCore.Extensions;
using Ashlar.Sample.AspNetCore.Views;
using Microsoft.Extensions.Options;

namespace Ashlar.Sample.AspNetCore.Endpoints;

internal static class AccountEndpoints
{
    public static void MapAccountEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/account", async (
            IIdentityRepository users,
            IAuthorizationEvaluator auth,
            ClaimsPrincipal user,
            CancellationToken cancellationToken) =>
        {
            var userId = user.GetAshlarUserId();
            var ashlarUser = await users.GetUserByIdAsync(userId, cancellationToken);
            if (ashlarUser == null) return Results.NotFound();

            var totpCredential = await users.GetCredentialForUserAsync(userId, ProviderType.Mfa, "totp", null, cancellationToken);
            var hasTotp = totpCredential != null;

            var recoveryCredential = await users.GetCredentialForUserAsync(userId, ProviderType.RecoveryCode, "RecoveryCode", null, cancellationToken);
            var hasRecoveryCodes = recoveryCredential != null;

            var isAdmin = (await auth.EvaluateAsync(new AuthorizationEvaluationRequest(userId, Role: "admin"), cancellationToken)).Succeeded;

            return AppViews.RenderAccountSettings(ashlarUser.Email, ashlarUser.Name, ashlarUser.EmailVerifiedAt.HasValue, hasTotp, hasRecoveryCodes, isAdmin);
        }).RequireAuthorization();

        app.MapPost("/api/account/profile", async (
            UpdateProfileRequest request,
            IIdentityRepository users,
            ClaimsPrincipal user,
            CancellationToken cancellationToken) =>
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
        }).RequireAuthorization();

        app.MapGet("/account/verify-email", (string? t, string? u) => AppViews.RenderEmailVerification(t, u));

        app.MapPost("/api/account/verify-email/request", async (
            IEmailVerificationService emailVerification,
            ClaimsPrincipal userPrincipal,
            IOptions<SampleAshlarOptions> options,
            CancellationToken cancellationToken) =>
        {
            var userId = userPrincipal.GetAshlarUserId();
            var callback = new Uri(new Uri(options.Value.PublicAppUrl), "/account/verify-email");
            var result = await emailVerification.RequestVerificationAsync(new EmailVerificationRequest
            {
                UserId = userId,
                CallbackBaseUri = callback
            }, cancellationToken);
            return result.Succeeded ? Results.Accepted() : Results.BadRequest(new { error = result.FailureReason });
        }).RequireAuthorization();

        app.MapPost("/api/account/verify-email/confirm", async (
            SampleEmailVerificationConfirmRequest request,
            IEmailVerificationService emailVerification,
            string? u,
            ClaimsPrincipal userPrincipal,
            CancellationToken cancellationToken) =>
        {
            Guid userId;
            if (Guid.TryParse(u, out var queryUserId))
            {
                userId = queryUserId;
            }
            else if (userPrincipal.Identity?.IsAuthenticated == true)
            {
                userId = userPrincipal.GetAshlarUserId();
            }
            else
            {
                return Results.BadRequest(new { error = "Missing user context." });
            }

            var result = await emailVerification.VerifyTokenAsync(userId, request.Token, cancellationToken);
            return result.Succeeded ? Results.Ok() : Results.BadRequest(new { error = result.FailureReason });
        });

        app.MapPost("/api/account/change-email/request", async (
            SampleEmailChangeRequest request,
            IEmailChangeService emailChange,
            ClaimsPrincipal userPrincipal,
            IOptions<SampleAshlarOptions> options,
            CancellationToken cancellationToken) =>
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
                CallbackBaseUri = callback
            }, cancellationToken);
            return result.Succeeded ? Results.Accepted() : Results.BadRequest(new { error = result.FailureReason });
        }).RequireAuthorization();

        app.MapGet("/account/change-email", (string? t, string? u) => AppViews.RenderEmailChangeConfirm(t, u));

        app.MapPost("/api/account/change-email/confirm", async (
            SampleEmailChangeConfirmRequest request,
            IEmailChangeService emailChange,
            string? u,
            ClaimsPrincipal userPrincipal,
            CancellationToken cancellationToken) =>
        {
            Guid userId;
            if (Guid.TryParse(u, out var queryUserId))
            {
                userId = queryUserId;
            }
            else if (userPrincipal.Identity?.IsAuthenticated == true)
            {
                userId = userPrincipal.GetAshlarUserId();
            }
            else
            {
                return Results.BadRequest(new { error = "Missing user context." });
            }

            var result = await emailChange.ConfirmChangeAsync(new ConfirmEmailChangeRequest { UserId = userId, Token = request.Token }, cancellationToken);
            return result.Succeeded ? Results.Ok() : Results.BadRequest(new { error = result.FailureReason });
        });
    }
}
