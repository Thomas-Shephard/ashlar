using System.Security.Claims;
using System.Text.Json;
using Ashlar.AspNetCore.Mfa;
using Ashlar.Identity.Features.Mfa;
using Ashlar.AspNetCore.Sessions;
using Ashlar.Passkeys;
using Ashlar.Sample.AspNetCore.Extensions;

namespace Ashlar.Sample.AspNetCore.Endpoints;

internal static class PasskeyEndpoints
{
    private static readonly StepUpRequirement SelfServicePasskeyRegistrationRequirement = new(TimeSpan.FromMinutes(10));
    private static readonly StepUpRequirement SelfServicePasskeyManagementRequirement = new(TimeSpan.FromMinutes(10));

    public static void MapPasskeyEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapPost("/api/passkeys/registration/options", StartRegistrationAsync).RequireAuthorization().RequireFreshMfaIfAvailable().RequireSampleAntiforgery();
        app.MapPost("/api/passkeys/registration/complete", CompleteRegistrationAsync).RequireAuthorization().RequireFreshMfaIfAvailable().RequireSampleAntiforgery();
        app.MapPost("/api/passkeys/authentication/options", StartAuthenticationAsync);
        app.MapPost("/api/passkeys/authentication/complete", CompleteAuthenticationAsync);
        app.MapPost("/api/passkeys/factor/options", StartFactorAsync);
        app.MapPost("/api/passkeys/factor/complete", CompleteFactorAsync);
        app.MapGet("/api/passkeys", ListAsync).RequireAuthorization().RequireFreshMfa();
        app.MapPost("/api/passkeys/{credentialId:guid}/rename", RenameAsync).RequireAuthorization().RequireFreshMfa().RequireSampleAntiforgery();
        app.MapDelete("/api/passkeys/{credentialId:guid}", RevokeAsync).RequireAuthorization().RequireFreshMfa().RequireSampleAntiforgery();
    }

    private static async Task<IResult> StartRegistrationAsync(PasskeyDisplayNameRequest request, IPasskeyService passkeys, IAccountSecurityService accountSecurity, StepUpAuthenticationService stepUp, ClaimsPrincipal user, HttpContext httpContext, CancellationToken cancellationToken)
    {
        var verification = await CreateRegistrationVerificationAsync(accountSecurity, stepUp, user, httpContext, cancellationToken);
        if (verification == null) return Results.Forbid();

        var result = await passkeys.StartRegistrationAsync(verification, new StartPasskeyRegistrationRequest(request.DisplayName ?? "Passkey"), cancellationToken);
        return Results.Json(new { result.ChallengeId, result.ExpiresAt, options = JsonDocument.Parse(result.OptionsJson).RootElement });
    }

    private static async Task<IResult> CompleteRegistrationAsync(PasskeyCompleteRegistrationSampleRequest request, IPasskeyService passkeys, IAccountSecurityService accountSecurity, StepUpAuthenticationService stepUp, ClaimsPrincipal user, HttpContext httpContext, CancellationToken cancellationToken)
    {
        var verification = await CreateRegistrationVerificationAsync(accountSecurity, stepUp, user, httpContext, cancellationToken);
        if (verification == null) return Results.Forbid();

        var result = await passkeys.CompleteRegistrationAsync(verification, new CompletePasskeyRegistrationRequest(request.ChallengeId, request.CredentialResponse, request.DisplayName), cancellationToken);
        return result.Succeeded ? Results.Ok() : Results.BadRequest(SampleResultErrors.From(result));
    }

    private static async Task<PasskeyRegistrationVerificationContext?> CreateRegistrationVerificationAsync(IAccountSecurityService accountSecurity, StepUpAuthenticationService stepUp, ClaimsPrincipal user, HttpContext httpContext, CancellationToken cancellationToken)
    {
        var userId = user.GetAshlarUserId();
        if (!httpContext.TryGetAshlarSessionContext(out _, out var sessionId, out _)) return null;
        var session = httpContext.GetValidatedAuthenticationSession();
        if (session == null || session.UserId != userId) return null;
        var posture = await accountSecurity.GetSecurityPostureAsync(session, cancellationToken: cancellationToken);
        if (!posture.Succeeded || posture.Value == null) return null;

        if (posture.Value.AdditionalVerificationFactors.Any(factor => factor.IsUsable))
        {
            var proof = httpContext.CreateFreshMfaProof(stepUp, SelfServicePasskeyRegistrationRequirement, IPasskeyService.RegistrationProofPurpose);
            return proof.Succeeded ? new PasskeyRegistrationVerificationContext(userId, httpContext.ToTenantContext(), sessionId, httpContext.ToAuditContext(), freshMfaProof: proof.Value) : null;
        }

        var primaryProof = httpContext.CreateFreshPrimaryAuthenticationProof(stepUp, SelfServicePasskeyRegistrationRequirement.FreshnessWindow, IPasskeyService.RegistrationProofPurpose);
        return primaryProof.Succeeded ? new PasskeyRegistrationVerificationContext(userId, httpContext.ToTenantContext(), sessionId, httpContext.ToAuditContext(), freshPrimaryAuthenticationProof: primaryProof.Value) : null;
    }

    private static async Task<IResult> StartAuthenticationAsync(IPasskeyService passkeys, HttpContext httpContext, CancellationToken cancellationToken)
    {
        var result = await passkeys.StartAuthenticationAsync(new StartPasskeyAuthenticationRequest(Audit: httpContext.ToAuditContext()) { Tenant = httpContext.ToTenantContext() }, cancellationToken);
        if (result.Succeeded && result.Value != null)
        {
            return Results.Json(new { result.Value.ChallengeId, result.Value.ExpiresAt, options = JsonDocument.Parse(result.Value.OptionsJson).RootElement });
        }

        if (result.FailureCode == AshlarFailureCodes.RateLimited)
        {
            return Results.StatusCode(StatusCodes.Status429TooManyRequests);
        }

        return Results.BadRequest(SampleResultErrors.From(result));
    }

    private static async Task<IResult> CompleteAuthenticationAsync(PasskeyCompleteAuthenticationSampleRequest request, IPasskeyService passkeys, IAshlarSignInManager signIn, HttpContext httpContext, CancellationToken cancellationToken)
    {
        var result = await passkeys.CompleteAuthenticationAsync(new CompletePasskeyAuthenticationRequest(request.ChallengeId, request.AssertionResponse, httpContext.GetDemoTenantIdFromUntrustedHeader(), httpContext.ToAuditContext()), cancellationToken);
        if (result.AuthenticationStatus == MfaAuthenticationStatus.MfaRequired)
        {
            return Results.Ok(new
            {
                status = "mfa_required",
                handshakeToken = result.HandshakeToken,
                requiredFactors = result.RequiredFactors
            });
        }

        if (result.AuthenticationStatus == MfaAuthenticationStatus.RateLimited)
        {
            return Results.StatusCode(StatusCodes.Status429TooManyRequests);
        }

        if (!result.Succeeded || result.User == null || result.AuthenticationResult == null)
        {
            return Results.BadRequest(new { error = result.FailureCode?.Value ?? "passkey_validation_failed" });
        }

        await signIn.SignInAsync(httpContext, result.AuthenticationResult, httpContext.ToSessionRequest(result.User, AuthenticationProviderKey.Passkey), cancellationToken);
        return Results.Ok(new { status = "signed_in" });
    }

    private static async Task<IResult> StartFactorAsync(PasskeyStartFactorSampleRequest request, IPasskeyService passkeys, HttpContext httpContext, CancellationToken cancellationToken)
    {
        var result = await passkeys.StartFactorAsync(new StartPasskeyFactorRequest(request.HandshakeToken, request.FactorType ?? "passkey", httpContext.ToAuditContext()) { Tenant = httpContext.ToTenantContext() }, cancellationToken);
        if (result.Succeeded && result.Value != null)
        {
            return Results.Json(new { result.Value.ChallengeId, result.Value.ExpiresAt, options = JsonDocument.Parse(result.Value.OptionsJson).RootElement });
        }

        if (result.FailureCode == AshlarFailureCodes.RateLimitExceeded)
        {
            return Results.StatusCode(StatusCodes.Status429TooManyRequests);
        }

        return Results.BadRequest(SampleResultErrors.From(result));
    }

    private static async Task<IResult> CompleteFactorAsync(PasskeyCompleteFactorSampleRequest request, IPasskeyService passkeys, IAshlarSignInManager signIn, HttpContext httpContext, CancellationToken cancellationToken)
    {
        var result = await passkeys.CompleteFactorAsync(new CompletePasskeyFactorRequest(request.ChallengeId, request.AssertionResponse, request.HandshakeToken, request.FactorType ?? "passkey", httpContext.GetDemoTenantIdFromUntrustedHeader(), httpContext.ToAuditContext()), cancellationToken);
        if (result.AuthenticationStatus == MfaAuthenticationStatus.HandshakeIncomplete)
        {
            return Results.Ok(new
            {
                status = "mfa_required",
                handshakeToken = result.HandshakeToken,
                requiredFactors = result.RequiredFactors
            });
        }

        if (result.AuthenticationStatus == MfaAuthenticationStatus.RateLimited)
        {
            return Results.StatusCode(StatusCodes.Status429TooManyRequests);
        }

        if (!result.Succeeded || result.User == null || result.AuthenticationResult == null)
        {
            return Results.BadRequest(new { error = result.FailureCode?.Value ?? "passkey_validation_failed" });
        }

        await signIn.SignInAsync(
            httpContext,
            result.AuthenticationResult,
            httpContext.ToSessionRequest(result.User),
            cancellationToken);
        return Results.Ok(new { status = "signed_in" });
    }

    private static async Task<IResult> ListAsync(IPasskeyService passkeys, ClaimsPrincipal user, HttpContext httpContext, CancellationToken cancellationToken)
    {
        if (!httpContext.TryGetAshlarSessionContext(out _, out var sessionId, out _)) return Results.Forbid();
        var proof = httpContext.CreateFreshMfaProof(httpContext.RequestServices.GetRequiredService<StepUpAuthenticationService>(), SelfServicePasskeyManagementRequirement, IPasskeyService.ManagementProofPurpose);
        if (!proof.Succeeded || proof.Value == null) return Results.Forbid();

        var actor = new AccountSecurityActorContext(user.GetAshlarUserId(), httpContext.ToTenantContext(), sessionId, proof.Value, httpContext.ToAuditContext());
        var result = await passkeys.ListAsync(actor, cancellationToken);
        return result.Succeeded ? Results.Ok(result.Value) : Results.Forbid();
    }

    private static async Task<IResult> RenameAsync(Guid credentialId, PasskeyDisplayNameRequest request, IPasskeyService passkeys, ClaimsPrincipal user, HttpContext httpContext, CancellationToken cancellationToken)
    {
        if (!httpContext.TryGetAshlarSessionContext(out _, out var sessionId, out _)) return Results.Forbid();
        var proof = httpContext.CreateFreshMfaProof(httpContext.RequestServices.GetRequiredService<StepUpAuthenticationService>(), SelfServicePasskeyManagementRequirement, IPasskeyService.ManagementProofPurpose);
        if (!proof.Succeeded || proof.Value == null) return Results.Forbid();

        var actor = new AccountSecurityActorContext(user.GetAshlarUserId(), httpContext.ToTenantContext(), sessionId, proof.Value, httpContext.ToAuditContext());
        var result = await passkeys.RenameAsync(actor, new RenamePasskeyRequest(credentialId, request.DisplayName ?? "Passkey"), cancellationToken);
        return result.Succeeded ? Results.Ok() : Results.BadRequest(SampleResultErrors.From(result));
    }

    private static async Task<IResult> RevokeAsync(Guid credentialId, IPasskeyService passkeys, ClaimsPrincipal user, HttpContext httpContext, CancellationToken cancellationToken)
    {
        if (!httpContext.TryGetAshlarSessionContext(out _, out var sessionId, out _)) return Results.Forbid();
        var proof = httpContext.CreateFreshMfaProof(httpContext.RequestServices.GetRequiredService<StepUpAuthenticationService>(), SelfServicePasskeyManagementRequirement, IPasskeyService.ManagementProofPurpose);
        if (!proof.Succeeded || proof.Value == null) return Results.Forbid();

        var actor = new AccountSecurityActorContext(user.GetAshlarUserId(), httpContext.ToTenantContext(), sessionId, proof.Value, httpContext.ToAuditContext());
        var result = await passkeys.RevokeAsync(actor, new RevokePasskeyRequest(credentialId), cancellationToken);
        return result.Succeeded ? Results.NoContent() : Results.BadRequest(SampleResultErrors.From(result));
    }

    private sealed record PasskeyDisplayNameRequest(string? DisplayName);
    private sealed record PasskeyStartFactorSampleRequest(string HandshakeToken, string? FactorType);
    private sealed record PasskeyCompleteRegistrationSampleRequest(Guid ChallengeId, JsonElement CredentialResponse, string? DisplayName);
    private sealed record PasskeyCompleteAuthenticationSampleRequest(Guid ChallengeId, JsonElement AssertionResponse);
    private sealed record PasskeyCompleteFactorSampleRequest(Guid ChallengeId, JsonElement AssertionResponse, string HandshakeToken, string? FactorType);
}
