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
    private static readonly StepUpRequirement SelfServicePasskeyRegistrationRequirement = new(TimeSpan.FromMinutes(10), Purpose: "passkey-registration");
    private static readonly StepUpRequirement SelfServicePasskeyManagementRequirement = new(TimeSpan.FromMinutes(10), Purpose: "passkey-management");

    public static void MapPasskeyEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapPost("/api/passkeys/registration/options", StartRegistrationAsync).RequireAuthorization().RequireFreshMfaIfAvailable().RequireSampleAntiforgery();
        app.MapPost("/api/passkeys/registration/complete", CompleteRegistrationAsync).RequireAuthorization().RequireFreshMfaIfAvailable().RequireSampleAntiforgery();
        app.MapPost("/api/passkeys/authentication/options", StartAuthenticationAsync);
        app.MapPost("/api/passkeys/authentication/complete", CompleteAuthenticationAsync);
        app.MapPost("/api/passkeys/factor/options", StartFactorAsync);
        app.MapPost("/api/passkeys/factor/complete", CompleteFactorAsync);
        app.MapGet("/api/passkeys", ListAsync).RequireAuthorization();
        app.MapPost("/api/passkeys/{credentialId:guid}/rename", RenameAsync).RequireAuthorization().RequireFreshMfa().RequireSampleAntiforgery();
        app.MapDelete("/api/passkeys/{credentialId:guid}", RevokeAsync).RequireAuthorization().RequireFreshMfa().RequireSampleAntiforgery();
    }

    private static async Task<IResult> StartRegistrationAsync(PasskeyDisplayNameRequest request, IPasskeyService passkeys, IAccountSecurityService accountSecurity, StepUpAuthenticationService stepUp, ClaimsPrincipal user, HttpContext httpContext, CancellationToken cancellationToken)
    {
        var registrationRequest = await CreateStartRegistrationRequestAsync(request.DisplayName, accountSecurity, stepUp, user, httpContext, cancellationToken);
        if (registrationRequest == null) return Results.Forbid();

        var result = await passkeys.StartRegistrationAsync(registrationRequest, cancellationToken);
        return Results.Json(new { result.ChallengeId, result.ExpiresAt, options = JsonDocument.Parse(result.OptionsJson).RootElement });
    }

    private static async Task<IResult> CompleteRegistrationAsync(PasskeyCompleteRegistrationSampleRequest request, IPasskeyService passkeys, IAccountSecurityService accountSecurity, StepUpAuthenticationService stepUp, ClaimsPrincipal user, HttpContext httpContext, CancellationToken cancellationToken)
    {
        var registrationRequest = await CreateCompleteRegistrationRequestAsync(request, accountSecurity, stepUp, user, httpContext, cancellationToken);
        if (registrationRequest == null) return Results.Forbid();

        var result = await passkeys.CompleteRegistrationAsync(registrationRequest, cancellationToken);
        return result.Succeeded ? Results.Ok() : Results.BadRequest(SampleResultErrors.From(result));
    }

    private static async Task<StartPasskeyRegistrationRequest?> CreateStartRegistrationRequestAsync(string? displayName, IAccountSecurityService accountSecurity, StepUpAuthenticationService stepUp, ClaimsPrincipal user, HttpContext httpContext, CancellationToken cancellationToken)
    {
        var userId = user.GetAshlarUserId();
        if (!httpContext.TryGetAshlarSessionContext(out _, out var sessionId, out _)) return null;

        var request = new StartPasskeyRegistrationRequest(userId, displayName ?? "Passkey")
        {
            CurrentSessionId = sessionId,
            Tenant = httpContext.ToTenantContext(),
            Audit = httpContext.ToAuditContext()
        };

        var proof = await CreateRegistrationProofAsync(accountSecurity, stepUp, userId, httpContext, cancellationToken);
        if (proof == null) return null;

        return proof.FreshMfaProof != null
            ? request with { FreshMfaProof = proof.FreshMfaProof }
            : request with { FreshPrimaryAuthenticationProof = proof.FreshPrimaryAuthenticationProof };
    }

    private static async Task<CompletePasskeyRegistrationRequest?> CreateCompleteRegistrationRequestAsync(PasskeyCompleteRegistrationSampleRequest input, IAccountSecurityService accountSecurity, StepUpAuthenticationService stepUp, ClaimsPrincipal user, HttpContext httpContext, CancellationToken cancellationToken)
    {
        var userId = user.GetAshlarUserId();
        if (!httpContext.TryGetAshlarSessionContext(out _, out var sessionId, out _)) return null;

        var request = new CompletePasskeyRegistrationRequest(input.ChallengeId, input.CredentialResponse, input.DisplayName, userId)
        {
            CurrentSessionId = sessionId,
            Tenant = httpContext.ToTenantContext(),
            Audit = httpContext.ToAuditContext()
        };

        var proof = await CreateRegistrationProofAsync(accountSecurity, stepUp, userId, httpContext, cancellationToken);
        if (proof == null) return null;

        return proof.FreshMfaProof != null
            ? request with { FreshMfaProof = proof.FreshMfaProof }
            : request with { FreshPrimaryAuthenticationProof = proof.FreshPrimaryAuthenticationProof };
    }

    private static async Task<PasskeyRegistrationProof?> CreateRegistrationProofAsync(IAccountSecurityService accountSecurity, StepUpAuthenticationService stepUp, Guid userId, HttpContext httpContext, CancellationToken cancellationToken)
    {
        var posture = await accountSecurity.GetUserSecurityPostureAsync(userId, new AccountSecurityPostureRequest(httpContext.ToTenantContext()), cancellationToken);
        if (!posture.Succeeded || posture.Value == null) return null;

        if (posture.Value.AdditionalVerificationFactors.Any(factor => factor.IsUsable))
        {
            var proof = httpContext.CreateFreshMfaProof(stepUp, SelfServicePasskeyRegistrationRequirement);
            return proof.Succeeded ? new PasskeyRegistrationProof(proof.Value, null) : null;
        }

        var primaryProof = httpContext.CreateFreshPrimaryAuthenticationProof(stepUp, SelfServicePasskeyRegistrationRequirement.FreshnessWindow, SelfServicePasskeyRegistrationRequirement.Purpose);
        return primaryProof.Succeeded ? new PasskeyRegistrationProof(null, primaryProof.Value) : null;
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

    private static async Task<IResult> CompleteFactorAsync(PasskeyCompleteFactorSampleRequest request, IPasskeyService passkeys, IAshlarSignInManager signIn, IAuthenticationSessionService sessions, HttpContext httpContext, CancellationToken cancellationToken)
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

        var markResult = await httpContext.SignInAndMarkStepUpVerifiedAsync(
            signIn,
            sessions,
            result.AuthenticationResult,
            AuthenticationProviderKey.Passkey,
            request.FactorType ?? AuthenticationFactorTypes.Passkey,
            cancellationToken);

        return markResult.Succeeded
            ? Results.Ok(new { status = "signed_in" })
            : Results.BadRequest(SampleResultErrors.From(markResult));
    }


    private static async Task<IResult> ListAsync(IPasskeyService passkeys, ClaimsPrincipal user, HttpContext httpContext, CancellationToken cancellationToken)
    {
        return Results.Ok(await passkeys.ListAsync(new ListPasskeysRequest(user.GetAshlarUserId(), httpContext.ToTenantContext()), cancellationToken));
    }

    private static async Task<IResult> RenameAsync(Guid credentialId, PasskeyDisplayNameRequest request, IPasskeyService passkeys, ClaimsPrincipal user, HttpContext httpContext, CancellationToken cancellationToken)
    {
        if (!httpContext.TryGetAshlarSessionContext(out _, out var sessionId, out _)) return Results.Forbid();
        var proof = httpContext.CreateFreshMfaProof(httpContext.RequestServices.GetRequiredService<StepUpAuthenticationService>(), SelfServicePasskeyManagementRequirement);
        if (!proof.Succeeded || proof.Value == null) return Results.Forbid();

        var result = await passkeys.RenameAsync(new RenamePasskeyRequest(user.GetAshlarUserId(), httpContext.ToTenantContext(), sessionId, proof.Value, credentialId, request.DisplayName ?? "Passkey", httpContext.ToAuditContext()), cancellationToken);
        return result.Succeeded ? Results.Ok() : Results.BadRequest(SampleResultErrors.From(result));
    }

    private static async Task<IResult> RevokeAsync(Guid credentialId, IPasskeyService passkeys, ClaimsPrincipal user, HttpContext httpContext, CancellationToken cancellationToken)
    {
        if (!httpContext.TryGetAshlarSessionContext(out _, out var sessionId, out _)) return Results.Forbid();
        var proof = httpContext.CreateFreshMfaProof(httpContext.RequestServices.GetRequiredService<StepUpAuthenticationService>(), SelfServicePasskeyManagementRequirement);
        if (!proof.Succeeded || proof.Value == null) return Results.Forbid();

        var result = await passkeys.RevokeAsync(new RevokePasskeyRequest(user.GetAshlarUserId(), httpContext.ToTenantContext(), sessionId, proof.Value, credentialId, httpContext.ToAuditContext()), cancellationToken);
        return result.Succeeded ? Results.NoContent() : Results.BadRequest(SampleResultErrors.From(result));
    }

    private sealed record PasskeyDisplayNameRequest(string? DisplayName);
    private sealed record PasskeyRegistrationProof(FreshMfaVerificationProof? FreshMfaProof, FreshPrimaryAuthenticationProof? FreshPrimaryAuthenticationProof);
    private sealed record PasskeyStartFactorSampleRequest(string HandshakeToken, string? FactorType);
    private sealed record PasskeyCompleteRegistrationSampleRequest(Guid ChallengeId, JsonElement CredentialResponse, string? DisplayName);
    private sealed record PasskeyCompleteAuthenticationSampleRequest(Guid ChallengeId, JsonElement AssertionResponse);
    private sealed record PasskeyCompleteFactorSampleRequest(Guid ChallengeId, JsonElement AssertionResponse, string HandshakeToken, string? FactorType);
}
