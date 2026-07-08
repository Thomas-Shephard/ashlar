using Ashlar.AspNetCore.Sessions;
using Ashlar.Sample.AspNetCore.Extensions;
using Ashlar.Sample.AspNetCore.Views;
using Microsoft.Extensions.Options;

namespace Ashlar.Sample.AspNetCore.Endpoints;

internal static class InvitationEndpoints
{
    public static void MapInvitationEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapPost("/api/invitations", async (
            CreateInvitationRequest request,
            IInvitationService invitations,
            IOptions<SampleAshlarOptions> options,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            var callback = new Uri(new Uri(options.Value.PublicAppUrl), "/invitations/accept");
            var invitation = new CreateInvitationRequest
            {
                Email = request.Email,
                TenantId = httpContext.GetDemoTenantIdFromUntrustedHeader(),
                Expiry = request.Expiry,
                Metadata = request.Metadata
            };
            var result = await invitations.CreateInvitationAsync(invitation, callback, httpContext.ToAuthenticationContext(), cancellationToken);
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
