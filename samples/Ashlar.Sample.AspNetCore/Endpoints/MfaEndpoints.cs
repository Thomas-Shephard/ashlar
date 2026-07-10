using System.Security.Claims;
using Ashlar.AspNetCore.Mfa;
using Ashlar.Identity.Features.Mfa;
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
    private static readonly StepUpRequirement SelfServiceMfaManagementRequirement = new(TimeSpan.FromMinutes(10));

    public static void MapMfaEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapPost("/api/mfa/verify", VerifyMfaAsync);
        app.MapGet("/api/account/security/step-up-options", GetStepUpOptionsAsync).RequireAuthorization();
        app.MapPost("/api/account/security/verify", VerifyCurrentSessionAsync).RequireAuthorization().RequireSampleAntiforgery();

        app.MapGet("/account/mfa/enroll", StartTotpEnrollmentAsync).RequireAuthorization().RequireFreshMfaIfAvailable();
        app.MapPost("/api/mfa/totp/verify", VerifyTotpEnrollmentAsync).RequireAuthorization().RequireFreshMfaIfAvailable().RequireSampleAntiforgery();
        app.MapPost("/api/mfa/totp/reset", ResetTotpAsync).RequireAuthorization().RequireFreshMfa().RequireSampleAntiforgery();
        app.MapPost("/api/mfa/recovery-codes", GenerateRecoveryCodesAsync).RequireAuthorization().RequireFreshMfa().RequireSampleAntiforgery();
    }

    private sealed record MfaEnrollServices(
        [FromServices] ITotpService Totp,
        [FromServices] IUserRepository Users,
        [FromServices] ICredentialRepository Credentials,
        [FromServices] IAccountSecurityService AccountSecurity,
        [FromServices] IAuthorizationEvaluator Auth,
        [FromServices] StepUpAuthenticationService StepUp,
        HttpContext HttpContext,
        ClaimsPrincipal User,
        [FromServices] IOptions<SampleAshlarOptions> Options,
        CancellationToken CancellationToken);

    private static async Task<IResult> StartTotpEnrollmentAsync([AsParameters] MfaEnrollServices services)
    {
        var userId = services.User.GetAshlarUserId();
        var ashlarUser = await services.Users.GetUserByIdAsync(userId, services.CancellationToken);
        if (ashlarUser == null) return Results.NotFound();

        var totpCredential = await services.Credentials.GetCredentialForUserAsync(userId, ProviderType.Mfa, "totp", null, services.CancellationToken);
        if (totpCredential != null)
        {
            return Results.Redirect("/account");
        }

        if (!services.HttpContext.TryGetAshlarSessionContext(out _, out var sessionId, out _)) return Results.Forbid();
        var posture = await services.AccountSecurity.GetUserSecurityPostureAsync(userId, new AccountSecurityPostureRequest(services.HttpContext.ToTenantContext()), services.CancellationToken);
        if (!posture.Succeeded) return Results.Forbid();
        if (posture.Value is not { } securityPosture) return Results.Forbid();

        FreshMfaVerificationProof? freshMfaProof = null;
        FreshPrimaryAuthenticationProof? freshPrimaryProof = null;
        if (securityPosture.AdditionalVerificationFactors.Any(factor => factor.IsUsable))
        {
            var proof = services.HttpContext.CreateFreshMfaProof(services.StepUp, SelfServiceMfaManagementRequirement);
            if (!proof.Succeeded) return Results.Forbid();

            freshMfaProof = proof.Value;
        }
        else
        {
            var proof = services.HttpContext.CreateFreshPrimaryAuthenticationProof(services.StepUp, SelfServiceMfaManagementRequirement.FreshnessWindow);
            if (!proof.Succeeded) return Results.Forbid();

            freshPrimaryProof = proof.Value;
        }

        var verification = new TotpEnrollmentVerificationContext(userId, services.HttpContext.ToTenantContext(), sessionId,
            services.HttpContext.ToAuditContext(), freshMfaProof, freshPrimaryProof);
        var enrollmentRequest = new StartTotpEnrollmentRequest(verification, services.Options.Value.AppName, ashlarUser.DisplayEmail);
        var enrollment = await services.Totp.StartEnrollmentAsync(enrollmentRequest, services.CancellationToken);
        var isAdmin = (await services.Auth.EvaluateAsync(new AuthorizationEvaluationRequest(userId, Role: "admin"), services.CancellationToken)).Succeeded;
        return AppViews.RenderMfaSetup(enrollment.SharedSecret, enrollment.AuthenticatorUri, isAdmin);
    }

    private sealed record TotpEnrollmentVerifyServices(
        [FromServices] ITotpService Totp,
        [FromServices] StepUpAuthenticationService StepUp,
        [FromServices] ICredentialRepository Credentials,
        [FromServices] IAccountSecurityService AccountSecurity,
        HttpContext HttpContext,
        ClaimsPrincipal User,
        CancellationToken CancellationToken);

    private static async Task<IResult> VerifyTotpEnrollmentAsync(TotpVerifyRequest request, [AsParameters] TotpEnrollmentVerifyServices services)
    {
        var userId = services.User.GetAshlarUserId();
        if (!services.HttpContext.TryGetAshlarSessionContext(out _, out var currentSessionId, out _))
        {
            return Results.Forbid();
        }

        var totpCredential = await services.Credentials.GetCredentialForUserAsync(userId, ProviderType.Mfa, "totp", null, services.CancellationToken);
        var posture = await services.AccountSecurity.GetUserSecurityPostureAsync(userId, new AccountSecurityPostureRequest(services.HttpContext.ToTenantContext()), services.CancellationToken);
        if (!posture.Succeeded)
        {
            return Results.Forbid();
        }
        if (posture.Value is not { } securityPosture)
        {
            return Results.Forbid();
        }

        FreshMfaVerificationProof? freshMfaProof = null;
        FreshPrimaryAuthenticationProof? freshPrimaryProof = null;
        if (totpCredential == null && !securityPosture.AdditionalVerificationFactors.Any(factor => factor.IsUsable))
        {
            var proof = services.HttpContext.CreateFreshPrimaryAuthenticationProof(services.StepUp, SelfServiceMfaManagementRequirement.FreshnessWindow);
            if (!proof.Succeeded) return Results.Forbid();

            freshPrimaryProof = proof.Value;
        }
        else
        {
            var proof = services.HttpContext.CreateFreshMfaProof(services.StepUp, SelfServiceMfaManagementRequirement);
            if (!proof.Succeeded) return Results.Forbid();

            freshMfaProof = proof.Value;
        }

        var verification = new TotpEnrollmentVerificationContext(userId, services.HttpContext.ToTenantContext(), currentSessionId,
            services.HttpContext.ToAuditContext(), freshMfaProof, freshPrimaryProof);
        var verifyRequest = new VerifyTotpEnrollmentRequest(verification, request.SharedSecret, request.Code);
        var result = await services.Totp.CompleteEnrollmentAsync(
            verifyRequest,
            services.CancellationToken);
        if (!result.Succeeded)
        {
            return Results.BadRequest(new { error = "invalid_totp" });
        }

        if (result.Value?.StepUpAuthenticationResult is { } stepUpResult)
        {
            await services.StepUp.MarkVerifiedAsync(stepUpResult, new MarkSessionStepUpVerifiedRequest
            {
                SessionId = currentSessionId,
                VerifiedProvider = new AuthenticationProviderKey(ProviderType.Mfa, "totp"),
                VerifiedFactor = "totp",
                Tenant = services.HttpContext.ToTenantContext(),
                Audit = services.HttpContext.ToAuditContext()
            }, services.CancellationToken);
        }

        return Results.Ok();
    }

    private sealed record TotpResetServices(
        [FromServices] ITotpService Totp,
        [FromServices] StepUpAuthenticationService StepUp,
        HttpContext HttpContext,
        ClaimsPrincipal User,
        CancellationToken CancellationToken);

    private static async Task<IResult> ResetTotpAsync([AsParameters] TotpResetServices services)
    {
        var userId = services.User.GetAshlarUserId();
        var proof = services.HttpContext.CreateFreshMfaProof(services.StepUp, SelfServiceMfaManagementRequirement);
        if (!proof.Succeeded)
        {
            return Results.Forbid();
        }
        if (proof.Value is not { } freshProof)
        {
            return Results.Forbid();
        }
        if (!services.HttpContext.TryGetAshlarSessionContext(out _, out var currentSessionId, out _))
        {
            return Results.Forbid();
        }

        await services.Totp.DisableAsync(
            new DisableTotpRequest(userId, services.HttpContext.ToTenantContext(), currentSessionId, freshProof,
                services.HttpContext.ToAuditContext()),
            services.CancellationToken);
        return Results.Ok();
    }

    private sealed record RecoveryCodeGenerationServices(
        [FromServices] IRecoveryCodeService RecoveryCodes,
        [FromServices] StepUpAuthenticationService StepUp,
        HttpContext HttpContext,
        CancellationToken CancellationToken);

    private static async Task<IResult> GenerateRecoveryCodesAsync([AsParameters] RecoveryCodeGenerationServices services)
    {
        var proof = services.HttpContext.CreateFreshMfaProof(services.StepUp, SelfServiceMfaManagementRequirement);
        if (!proof.Succeeded)
        {
            return Results.Forbid();
        }
        if (proof.Value is not { } freshProof)
        {
            return Results.Forbid();
        }
        if (!services.HttpContext.TryGetAshlarSessionContext(out var userId, out var currentSessionId, out var tenant))
        {
            return Results.Forbid();
        }
        var scope = tenant ?? TenantContext.Global;

        var result = await services.RecoveryCodes.GenerateRecoveryCodesAsync(
            new RecoveryCodeGenerationRequest(
                userId,
                new AccountSecurityActorContext(userId, scope, currentSessionId, freshProof,
                    services.HttpContext.ToAuditContext()),
                scope),
            services.CancellationToken);
        return result.Succeeded ? Results.Ok(new { codes = result.Value }) : Results.BadRequest(SampleResultErrors.From(result));
    }

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
        StepUpAuthenticationService stepUp,
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

        var result = await stepUp.MarkVerifiedAsync(response, new MarkSessionStepUpVerifiedRequest
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
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        var userId = user.GetAshlarUserId();
        var totpCredential = await credentials.GetCredentialForUserAsync(userId, ProviderType.Mfa, "totp", null, cancellationToken);
        var recoveryCredential = await credentials.GetCredentialForUserAsync(userId, ProviderType.RecoveryCode, "RecoveryCode", null, cancellationToken);
        var hasPasskeys = (await passkeys.ListAsync(new ListPasskeysRequest(userId, httpContext.ToTenantContext()), cancellationToken)).Count > 0;
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

        return await SignInVerifiedMfaAsync(
            services,
            httpContext,
            response,
            TotpOptions.DefaultProviderKey,
            AuthenticationFactorTypes.Totp,
            cancellationToken);
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

        return await SignInVerifiedMfaAsync(
            services,
            httpContext,
            response,
            new AuthenticationProviderKey(ProviderType.RecoveryCode, "RecoveryCode"),
            AuthenticationFactorTypes.RecoveryCode,
            cancellationToken);
    }

    private static async Task<IResult> SignInVerifiedMfaAsync(
        MfaVerifyServices services,
        HttpContext httpContext,
        MfaAuthenticationResult authenticationResult,
        AuthenticationProviderKey verifiedProvider,
        string verifiedFactor,
        CancellationToken cancellationToken)
    {
        var result = await httpContext.SignInAndMarkStepUpVerifiedAsync(
            services.SignInManager,
            services.SessionService,
            authenticationResult,
            verifiedProvider,
            verifiedFactor,
            cancellationToken);

        return result.Succeeded && authenticationResult.User is { } user
            ? Results.Ok(new { userId = user.Id })
            : Results.BadRequest(SampleResultErrors.From(result));
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
        [FromServices] IAshlarSignInManager SignInManager,
        [FromServices] IAuthenticationSessionService SessionService);

    private sealed record StepUpVerifyRequest(string Code);
}
