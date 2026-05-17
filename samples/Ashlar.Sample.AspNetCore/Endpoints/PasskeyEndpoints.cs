using System.Security.Claims;
using System.Text.Json;
using Ashlar.AspNetCore.Sessions;
using Ashlar.Identity.Models;
using Ashlar.Passkeys;
using Ashlar.Sample.AspNetCore.Extensions;

namespace Ashlar.Sample.AspNetCore.Endpoints;

internal static class PasskeyEndpoints
{
    public static void MapPasskeyEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapPost("/api/passkeys/registration/options", StartRegistrationAsync).RequireAuthorization();
        app.MapPost("/api/passkeys/registration/complete", CompleteRegistrationAsync).RequireAuthorization();
        app.MapPost("/api/passkeys/authentication/options", StartAuthenticationAsync);
        app.MapPost("/api/passkeys/authentication/complete", CompleteAuthenticationAsync);
        app.MapPost("/api/passkeys/factor/options", StartFactorAsync);
        app.MapPost("/api/passkeys/factor/complete", CompleteFactorAsync);
        app.MapGet("/api/passkeys", ListAsync).RequireAuthorization();
        app.MapPost("/api/passkeys/{credentialId:guid}/rename", RenameAsync).RequireAuthorization();
        app.MapDelete("/api/passkeys/{credentialId:guid}", RevokeAsync).RequireAuthorization();
    }

    private static async Task<IResult> StartRegistrationAsync(PasskeyDisplayNameRequest request, IPasskeyService passkeys, ClaimsPrincipal user, HttpContext httpContext, CancellationToken cancellationToken)
    {
        var result = await passkeys.StartRegistrationAsync(new StartPasskeyRegistrationRequest(user.GetAshlarUserId(), request.DisplayName ?? "Passkey", httpContext.ToAuditContext()), cancellationToken);
        return Results.Json(new { result.ChallengeId, result.ExpiresAt, options = JsonDocument.Parse(result.OptionsJson).RootElement });
    }

    private static async Task<IResult> CompleteRegistrationAsync(PasskeyCompleteRegistrationSampleRequest request, IPasskeyService passkeys, ClaimsPrincipal user, HttpContext httpContext, CancellationToken cancellationToken)
    {
        var result = await passkeys.CompleteRegistrationAsync(new CompletePasskeyRegistrationRequest(request.ChallengeId, request.CredentialResponse, request.DisplayName, user.GetAshlarUserId(), httpContext.ToAuditContext()), cancellationToken);
        return result.Succeeded ? Results.Ok() : Results.BadRequest(SampleResultErrors.From(result));
    }

    private static async Task<IResult> StartAuthenticationAsync(IPasskeyService passkeys, HttpContext httpContext, CancellationToken cancellationToken)
    {
        var result = await passkeys.StartAuthenticationAsync(new StartPasskeyAuthenticationRequest(Audit: httpContext.ToAuditContext()), cancellationToken);
        return Results.Json(new { result.ChallengeId, result.ExpiresAt, options = JsonDocument.Parse(result.OptionsJson).RootElement });
    }

    private static async Task<IResult> CompleteAuthenticationAsync(PasskeyCompleteAuthenticationSampleRequest request, IPasskeyService passkeys, IAshlarSignInManager signIn, HttpContext httpContext, CancellationToken cancellationToken)
    {
        var result = await passkeys.CompleteAuthenticationAsync(new CompletePasskeyAuthenticationRequest(request.ChallengeId, request.AssertionResponse, httpContext.ToAuditContext()), cancellationToken);
        if (result.Status == MfaAuthenticationStatus.MfaRequired)
        {
            return Results.Ok(new
            {
                status = "mfa_required",
                handshakeToken = result.HandshakeToken,
                requiredFactors = result.RequiredFactors
            });
        }

        if (!result.Succeeded || result.User == null)
        {
            return Results.BadRequest(new { error = result.FailureCode?.Value ?? "passkey_validation_failed" });
        }

        await signIn.SignInAsync(httpContext, result.User.Id, httpContext.ToSessionRequest(), cancellationToken);
        return Results.Ok(new { status = "signed_in" });
    }

    private static async Task<IResult> StartFactorAsync(PasskeyStartFactorSampleRequest request, IPasskeyService passkeys, HttpContext httpContext, CancellationToken cancellationToken)
    {
        var result = await passkeys.StartFactorAsync(new StartPasskeyFactorRequest(request.HandshakeToken, request.FactorType ?? "passkey", httpContext.ToAuditContext()), cancellationToken);
        return result.Succeeded && result.Value != null
            ? Results.Json(new { result.Value.ChallengeId, result.Value.ExpiresAt, options = JsonDocument.Parse(result.Value.OptionsJson).RootElement })
            : Results.BadRequest(SampleResultErrors.From(result));
    }

    private static async Task<IResult> CompleteFactorAsync(PasskeyCompleteFactorSampleRequest request, IPasskeyService passkeys, IAshlarSignInManager signIn, HttpContext httpContext, CancellationToken cancellationToken)
    {
        var result = await passkeys.CompleteFactorAsync(new CompletePasskeyFactorRequest(request.ChallengeId, request.AssertionResponse, request.HandshakeToken, request.FactorType ?? "passkey", httpContext.ToAuditContext()), cancellationToken);
        if (result.Status == MfaAuthenticationStatus.HandshakeIncomplete)
        {
            return Results.Ok(new
            {
                status = "mfa_required",
                handshakeToken = result.HandshakeToken,
                requiredFactors = result.RequiredFactors
            });
        }

        if (!result.Succeeded || result.User == null)
        {
            return Results.BadRequest(new { error = result.FailureCode?.Value ?? "passkey_validation_failed" });
        }

        await signIn.SignInAsync(httpContext, result.User.Id, httpContext.ToSessionRequest(), cancellationToken);
        return Results.Ok(new { status = "signed_in" });
    }


    private static async Task<IResult> ListAsync(IPasskeyService passkeys, ClaimsPrincipal user, CancellationToken cancellationToken)
    {
        return Results.Ok(await passkeys.ListAsync(user.GetAshlarUserId(), cancellationToken));
    }

    private static async Task<IResult> RenameAsync(Guid credentialId, PasskeyDisplayNameRequest request, IPasskeyService passkeys, ClaimsPrincipal user, HttpContext httpContext, CancellationToken cancellationToken)
    {
        var result = await passkeys.RenameAsync(new RenamePasskeyRequest(user.GetAshlarUserId(), credentialId, request.DisplayName ?? "Passkey", httpContext.ToAuditContext()), cancellationToken);
        return result.Succeeded ? Results.Ok() : Results.BadRequest(SampleResultErrors.From(result));
    }

    private static async Task<IResult> RevokeAsync(Guid credentialId, IPasskeyService passkeys, ClaimsPrincipal user, HttpContext httpContext, CancellationToken cancellationToken)
    {
        var result = await passkeys.RevokeAsync(new RevokePasskeyRequest(user.GetAshlarUserId(), credentialId, httpContext.ToAuditContext()), cancellationToken);
        return result.Succeeded ? Results.NoContent() : Results.BadRequest(SampleResultErrors.From(result));
    }

    private sealed record PasskeyDisplayNameRequest(string? DisplayName);
    private sealed record PasskeyStartFactorSampleRequest(string HandshakeToken, string? FactorType);
    private sealed record PasskeyCompleteRegistrationSampleRequest(Guid ChallengeId, JsonElement CredentialResponse, string? DisplayName);
    private sealed record PasskeyCompleteAuthenticationSampleRequest(Guid ChallengeId, JsonElement AssertionResponse);
    private sealed record PasskeyCompleteFactorSampleRequest(Guid ChallengeId, JsonElement AssertionResponse, string HandshakeToken, string? FactorType);
}
