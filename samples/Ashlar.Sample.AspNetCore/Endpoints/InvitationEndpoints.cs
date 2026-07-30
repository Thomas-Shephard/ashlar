using Ashlar.AspNetCore.Sessions;
using Ashlar.AspNetCore.Mfa;
using Ashlar.Identity.Features.Mfa;
using Ashlar.Identity.Models.Administration;
using Ashlar.Sample.AspNetCore.Extensions;
using Ashlar.Sample.AspNetCore.Views;
using Microsoft.Extensions.Options;

namespace Ashlar.Sample.AspNetCore.Endpoints;

internal static class InvitationEndpoints
{
    private static readonly StepUpRequirement InvitationCreationRequirement = new(TimeSpan.FromMinutes(5));

    public static void MapInvitationEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapPost("/api/invitations", async (
            CreateInvitationRequest request,
            IInvitationAdministrationService invitations,
            StepUpAuthenticationService stepUp,
            IOptions<SampleAshlarOptions> options,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            if (!httpContext.TryGetAshlarSessionContext(out var actorUserId, out var sessionId, out var actorTenant) || actorTenant == null)
                return Results.Forbid();
            var proof = httpContext.CreateFreshMfaProof(stepUp, InvitationCreationRequirement, IInvitationAdministrationService.CreateProofPurpose);
            if (!proof.TryGetValue(out var freshProof))
                return Results.Forbid();

            var callback = new Uri(new Uri(options.Value.PublicAppUrl), "/invitations/accept");
            var tenant = new TenantContext(httpContext.GetDemoTenantIdFromUntrustedHeader());
            var invitation = new CreateInvitationRequest
            {
                Email = request.Email,
                TenantId = tenant.TenantId,
                Expiry = request.Expiry,
                Metadata = request.Metadata
            };
            var actor = new AccountSecurityActorContext(actorUserId, actorTenant, sessionId, freshProof, httpContext.ToAuditContext());
            var result = await invitations.CreateInvitationAsync(actor,
                new CreateInvitationAdministrationRequest(invitation, callback, tenant), cancellationToken);
            return result.Succeeded ? Results.Accepted() : Results.BadRequest(SampleResultErrors.From(result));
        }).RequireAuthorization("admin").RequireFreshMfa().RequireSampleAntiforgery();

        app.MapPost("/api/invitations/accept", async Task<IResult> (
            AcceptInvitationRequest request,
            IInvitationService invitations,
            IAshlarSignInManager signInManager,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            var result = await invitations.AcceptInvitationAsync(request, httpContext.ToAuthenticationContext(), cancellationToken);
            if (!result.Succeeded || result.Value is not { } value)
            {
                return Results.BadRequest(SampleResultErrors.From(result));
            }

            await signInManager.SignInAsync(httpContext, value.AuthenticationResult, httpContext.ToSessionRequest(value.AuthenticationResult.User), cancellationToken);

            return Results.Ok(new { userId = value.UserId });
        });

        app.MapGet("/invitations/accept", (string t, IConfiguration configuration) => AppViews.RenderInvitationAccept(t, SampleGoogleOidc.IsConfigured(configuration)));
    }
}
