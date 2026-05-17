using System.Security.Claims;
using Ashlar.AspNetCore.Sessions;
using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.Models.Totp;
using Ashlar.Sample.AspNetCore.Extensions;
using Ashlar.Sample.AspNetCore.Views;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Ashlar.Sample.AspNetCore.Endpoints;

internal static class MfaEndpoints
{
    public static void MapMfaEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapPost("/api/mfa/verify", VerifyMfaAsync);

        app.MapGet("/account/mfa/enroll", async (
            ITotpService totp,
            IIdentityRepository users,
            IAuthorizationEvaluator auth,
            HttpContext httpContext,
            ClaimsPrincipal user,
            IOptions<SampleAshlarOptions> options,
            CancellationToken cancellationToken) =>
        {
            var userId = user.GetAshlarUserId();
            var ashlarUser = await users.GetUserByIdAsync(userId, cancellationToken);
            if (ashlarUser == null) return Results.NotFound();

            var totpCredential = await users.GetCredentialForUserAsync(userId, ProviderType.Mfa, "totp", null, cancellationToken);
            var hasTotp = totpCredential != null;

            if (!hasTotp)
            {
                var enrollment = await totp.StartEnrollmentAsync(userId, options.Value.AppName, ashlarUser.Email, httpContext.ToTenantContext(), httpContext.ToAuditContext(), cancellationToken);
                var isAdmin = (await auth.EvaluateAsync(new AuthorizationEvaluationRequest(userId, Role: "admin"), cancellationToken)).Succeeded;
                return AppViews.RenderMfaSetup(enrollment.SharedSecret, enrollment.AuthenticatorUri, isAdmin);
            }

            return Results.Redirect("/account");
        }).RequireAuthorization();

        app.MapPost("/api/mfa/totp/verify", async Task<IResult> (
            TotpVerifyRequest request,
            ITotpService totp,
            HttpContext httpContext,
            ClaimsPrincipal user,
            CancellationToken cancellationToken) =>
        {
            var result = await totp.VerifyAndEnrollAsync(user.GetAshlarUserId(), request.SharedSecret, request.Code, httpContext.ToTenantContext(), httpContext.ToAuditContext(), cancellationToken);
            return result.Succeeded ? Results.Ok() : Results.BadRequest(new { error = "invalid_totp" });
        }).RequireAuthorization();

        app.MapPost("/api/mfa/totp/reset", async (
            ITotpService totp,
            HttpContext httpContext,
            ClaimsPrincipal user,
            CancellationToken cancellationToken) =>
        {
            await totp.DisableTotpAsync(user.GetAshlarUserId(), httpContext.ToTenantContext(), httpContext.ToAuditContext(), cancellationToken);
            return Results.Ok();
        }).RequireAuthorization();

        app.MapPost("/api/mfa/recovery-codes", async (
            IRecoveryCodeService recoveryCodes,
            HttpContext httpContext,
            ClaimsPrincipal user,
            CancellationToken cancellationToken) =>
        {
            var result = await recoveryCodes.GenerateRecoveryCodesAsync(
                user.GetAshlarUserId(),
                new RecoveryCodeGenerationRequest { Tenant = httpContext.ToTenantContext(), Audit = httpContext.ToAuditContext() },
                cancellationToken);
            return result.Succeeded ? Results.Ok(new { codes = result.Value }) : Results.BadRequest(SampleResultErrors.From(result));
        }).RequireAuthorization();
    }

    private static async Task<IResult> VerifyMfaAsync(
            MfaVerifyRequest request,
            [AsParameters] MfaVerifyServices services,
            HttpContext httpContext,
            CancellationToken cancellationToken)
    {
        var authContext = httpContext.ToAuthenticationContext();
        var handshake = await services.HandshakeService.GetHandshakeAsync(request.HandshakeToken, cancellationToken);
        if (handshake == null)
        {
            return Results.BadRequest(new { error = "handshake_not_found" });
        }

        var code = request.Code.Trim();
        if (IsTotpCode(code))
        {
            return await VerifyTotpAsync(request.HandshakeToken, code, authContext, services, httpContext, cancellationToken);
        }

        return await VerifyRecoveryCodeAsync(request.HandshakeToken, code, handshake, authContext, services, httpContext, cancellationToken);
    }

    private static bool IsTotpCode(string code) => code.Length == 6 && code.All(char.IsDigit);

    private static async Task<IResult> VerifyTotpAsync(
        string handshakeToken,
        string code,
        AuthenticationContext authContext,
        MfaVerifyServices services,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        var response = await services.Orchestrator.VerifyFactorAsync(
            handshakeToken,
            "totp",
            authContext,
            new TotpAssertion(code),
            cancellationToken: cancellationToken);

        if (response is not { Status: MfaAuthenticationStatus.Succeeded, User: not null })
        {
            return Results.BadRequest(new { error = response.ErrorMessage ?? "invalid_totp" });
        }

        await services.SignInManager.SignInAsync(httpContext, response.User.Id, httpContext.ToSessionRequest(), cancellationToken);
        return Results.Ok(new { userId = response.User.Id });
    }

    private static async Task<IResult> VerifyRecoveryCodeAsync(
        string handshakeToken,
        string code,
        AuthenticationHandshake handshake,
        AuthenticationContext authContext,
        MfaVerifyServices services,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        var user = await services.Users.GetUserByIdAsync(handshake.UserId, cancellationToken);
        var factorContext = authContext with { UserId = handshake.UserId, Email = user?.Email };
        var recoveryResponse = await services.Pipeline.LoginAsync(factorContext, new RecoveryCodeAssertion(code), cancellationToken);

        if (!recoveryResponse.Succeeded || recoveryResponse.User?.Id != handshake.UserId)
        {
            return Results.BadRequest(new { error = "invalid_mfa_code" });
        }

        var factorToSatisfy = handshake.RequiredFactors.FirstOrDefault() ?? "totp";
        var result = await services.HandshakeService.VerifyFactorAsync(
            new VerifyAuthenticationHandshakeRequest(handshakeToken, factorToSatisfy, new Dictionary<string, string> { ["mfa_recovery"] = "true" }, factorContext),
            cancellationToken);

        if (result is not { Succeeded: true, Value: not null })
        {
            return Results.BadRequest(new { error = "invalid_mfa_code" });
        }

        if (!result.Value.IsCompleted)
        {
            return Results.Ok(new
            {
                status = "mfa_required",
                handshakeToken,
                requiredFactors = result.Value.RequiredFactors.Except(result.Value.VerifiedFactors)
            });
        }

        await services.SignInManager.SignInAsync(httpContext, recoveryResponse.User.Id, httpContext.ToSessionRequest(), cancellationToken);
        return Results.Ok(new { userId = recoveryResponse.User.Id });
    }

    private sealed record MfaVerifyServices(
        [FromServices] IAuthenticationOrchestrator Orchestrator,
        [FromServices] IAuthenticationHandshakeService HandshakeService,
        [FromServices] IAuthenticationPipeline Pipeline,
        [FromServices] IIdentityRepository Users,
        [FromServices] IAshlarSignInManager SignInManager);
}
