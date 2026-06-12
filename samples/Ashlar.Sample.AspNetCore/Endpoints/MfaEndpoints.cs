using System.Security.Claims;
using Ashlar.AspNetCore.Sessions;
using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Ashlar.Identity.Models.Totp;
using Ashlar.Identity.Providers.RecoveryCode;
using Ashlar.Passkeys;
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
        app.MapGet("/api/account/security/step-up-options", GetStepUpOptionsAsync).RequireAuthorization();
        app.MapPost("/api/account/security/verify", VerifyCurrentSessionAsync).RequireAuthorization().RequireSampleAntiforgery();

        app.MapGet("/account/mfa/enroll", async ([AsParameters] MfaEnrollServices services) =>
        {
            var userId = services.User.GetAshlarUserId();
            var ashlarUser = await services.Users.GetUserByIdAsync(userId, services.CancellationToken);
            if (ashlarUser == null) return Results.NotFound();

            var totpCredential = await services.Credentials.GetCredentialForUserAsync(userId, ProviderType.Mfa, "totp", null, services.CancellationToken);
            var hasTotp = totpCredential != null;

            if (!hasTotp)
            {
                var enrollment = await services.Totp.StartEnrollmentAsync(userId, services.Options.Value.AppName, ashlarUser.Email, services.HttpContext.ToTenantContext(), services.HttpContext.ToAuditContext(), services.CancellationToken);
                var isAdmin = (await services.Auth.EvaluateAsync(new AuthorizationEvaluationRequest(userId, Role: "admin"), services.CancellationToken)).Succeeded;
                return AppViews.RenderMfaSetup(enrollment.SharedSecret, enrollment.AuthenticatorUri, isAdmin);
            }

            return Results.Redirect("/account");
        }).RequireAuthorization();

        app.MapPost("/api/mfa/totp/verify", async Task<IResult> (
            TotpVerifyRequest request,
            ITotpService totp,
            IStepUpAuthenticationService stepUp,
            HttpContext httpContext,
            ClaimsPrincipal user,
            CancellationToken cancellationToken) =>
        {
            var result = await totp.VerifyAndEnrollAsync(user.GetAshlarUserId(), request.SharedSecret, request.Code, httpContext.ToTenantContext(), httpContext.ToAuditContext(), cancellationToken);
            if (!result.Succeeded)
            {
                return Results.BadRequest(new { error = "invalid_totp" });
            }

            if (httpContext.TryGetAshlarSessionContext(out var userId, out var sessionId, out var tenant))
            {
                await stepUp.MarkVerifiedAsync(userId, new MarkSessionStepUpVerifiedRequest
                {
                    SessionId = sessionId,
                    VerifiedProvider = TotpOptions.DefaultProviderKey,
                    VerifiedFactor = AuthenticationFactorTypes.Totp,
                    Tenant = tenant,
                    Audit = httpContext.ToAuditContext()
                }, cancellationToken);
            }

            return Results.Ok();
        }).RequireAuthorization().RequireSampleAntiforgery();

        app.MapPost("/api/mfa/totp/reset", async (
            ITotpService totp,
            HttpContext httpContext,
            ClaimsPrincipal user,
            CancellationToken cancellationToken) =>
        {
            await totp.DisableTotpAsync(user.GetAshlarUserId(), httpContext.ToTenantContext(), httpContext.ToAuditContext(), cancellationToken);
            return Results.Ok();
        }).RequireAuthorization().RequireFreshMfa().RequireSampleAntiforgery();

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
        }).RequireAuthorization().RequireFreshMfa().RequireSampleAntiforgery();
    }

    private sealed record MfaEnrollServices(
        [FromServices] ITotpService Totp,
        [FromServices] IUserRepository Users,
        [FromServices] ICredentialRepository Credentials,
        [FromServices] IAuthorizationEvaluator Auth,
        HttpContext HttpContext,
        ClaimsPrincipal User,
        [FromServices] IOptions<SampleAshlarOptions> Options,
        CancellationToken CancellationToken);

    private static async Task<IResult> VerifyMfaAsync(
            MfaVerifyRequest request,
            [AsParameters] MfaVerifyServices services,
            HttpContext httpContext,
            CancellationToken cancellationToken)
    {
        var authContext = httpContext.ToAuthenticationContext();
        var code = request.Code.Trim();
        if (IsTotpCode(code))
        {
            return await VerifyTotpAsync(request.HandshakeToken, code, authContext, services, httpContext, cancellationToken);
        }

        return await VerifyRecoveryCodeAsync(request.HandshakeToken, code, authContext, services, httpContext, cancellationToken);
    }

    private static async Task<IResult> VerifyCurrentSessionAsync(
        StepUpVerifyRequest request,
        IAuthenticationFactorPipeline factorPipeline,
        IStepUpAuthenticationService stepUp,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        if (!httpContext.TryGetAshlarSessionContext(out var userId, out var sessionId, out var tenant))
        {
            return Results.Forbid();
        }

        var code = request.Code.Trim();
        var isTotp = IsTotpCode(code);
        var provider = isTotp
            ? TotpOptions.DefaultProviderKey
            : new AuthenticationProviderKey(ProviderType.RecoveryCode, "RecoveryCode");
        var factor = isTotp ? AuthenticationFactorTypes.Totp : AuthenticationFactorTypes.RecoveryCode;
        IAuthenticationAssertion assertion = isTotp
            ? new TotpAssertion(code)
            : new RecoveryCodeAssertion(code);

        var authContext = httpContext.ToAuthenticationContext() with { UserId = userId };
        var response = await factorPipeline.VerifyFactorAsync(authContext, assertion, cancellationToken);
        if (response.Status == AuthenticationStatus.RateLimited)
        {
            return Results.StatusCode(StatusCodes.Status429TooManyRequests);
        }

        if (!response.Succeeded || response.User?.Id != userId)
        {
            return Results.BadRequest(new { error = isTotp ? "invalid_totp" : "invalid_mfa_code" });
        }

        var result = await stepUp.MarkVerifiedAsync(userId, new MarkSessionStepUpVerifiedRequest
        {
            SessionId = sessionId,
            VerifiedProvider = provider,
            VerifiedFactor = factor,
            Tenant = tenant,
            Audit = httpContext.ToAuditContext()
        }, cancellationToken);

        return result.Succeeded
            ? Results.Ok(new { status = "verified" })
            : Results.BadRequest(SampleResultErrors.From(result));
    }

    private static async Task<IResult> GetStepUpOptionsAsync(
        ICredentialRepository credentials,
        IPasskeyService passkeys,
        ClaimsPrincipal user,
        CancellationToken cancellationToken)
    {
        var userId = user.GetAshlarUserId();
        var totpCredential = await credentials.GetCredentialForUserAsync(userId, ProviderType.Mfa, "totp", null, cancellationToken);
        var recoveryCredential = await credentials.GetCredentialForUserAsync(userId, ProviderType.RecoveryCode, "RecoveryCode", null, cancellationToken);
        var hasPasskeys = (await passkeys.ListAsync(userId, cancellationToken)).Count > 0;
        var canUseCode = totpCredential != null || recoveryCredential != null;

        return Results.Ok(new
        {
            hasTotp = totpCredential != null,
            hasRecoveryCodes = recoveryCredential != null,
            hasPasskeys,
            canUseCode,
            setupUrl = "/account#security"
        });
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

        if (response.Status == MfaAuthenticationStatus.RateLimited)
        {
            return Results.StatusCode(StatusCodes.Status429TooManyRequests);
        }

        if (response is not { Status: MfaAuthenticationStatus.Succeeded or MfaAuthenticationStatus.HandshakeIncomplete, User: not null })
        {
            return Results.BadRequest(new { error = response.ErrorMessage ?? "invalid_totp" });
        }

        if (response.Status == MfaAuthenticationStatus.HandshakeIncomplete)
        {
            return CreateIncompleteMfaResponse(response);
        }

        await services.SignInManager.SignInAsync(httpContext, response.User.Id, httpContext.ToSessionRequest(
            response.User,
            additionalVerificationProvider: TotpOptions.DefaultProviderKey,
            additionalVerificationFactor: "totp"), cancellationToken);
        return Results.Ok(new { userId = response.User.Id });
    }

    private static async Task<IResult> VerifyRecoveryCodeAsync(
        string handshakeToken,
        string code,
        AuthenticationContext authContext,
        MfaVerifyServices services,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        var response = await services.Orchestrator.VerifyFactorAsync(
            handshakeToken,
            AuthenticationFactorTypes.RecoveryCode,
            authContext,
            new RecoveryCodeAssertion(code),
            cancellationToken);

        if (response.Status == MfaAuthenticationStatus.RateLimited)
        {
            return Results.StatusCode(StatusCodes.Status429TooManyRequests);
        }

        if (response is not { Status: MfaAuthenticationStatus.Succeeded or MfaAuthenticationStatus.HandshakeIncomplete, User: not null })
        {
            return Results.BadRequest(new { error = "invalid_mfa_code" });
        }

        if (response.Status == MfaAuthenticationStatus.HandshakeIncomplete)
        {
            return CreateIncompleteMfaResponse(response);
        }

        await services.SignInManager.SignInAsync(httpContext, response.User.Id, httpContext.ToSessionRequest(
            response.User,
            additionalVerificationProvider: new AuthenticationProviderKey(ProviderType.RecoveryCode, "RecoveryCode"),
            additionalVerificationFactor: "recovery_code"), cancellationToken);
        return Results.Ok(new { userId = response.User.Id });
    }

    private static IResult CreateIncompleteMfaResponse(MfaAuthenticationResult response)
    {
        return Results.Ok(new
        {
            status = "mfa_required",
            response.HandshakeToken,
            response.RequiredFactors
        });
    }

    private sealed record MfaVerifyServices(
        [FromServices] IAuthenticationOrchestrator Orchestrator,
        [FromServices] IAshlarSignInManager SignInManager);

    private sealed record StepUpVerifyRequest(string Code);
}
