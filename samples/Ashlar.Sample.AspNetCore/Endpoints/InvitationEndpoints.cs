using Ashlar.AspNetCore.Sessions;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Sample.AspNetCore.Extensions;
using Ashlar.Sample.AspNetCore.Views;
using Microsoft.Extensions.Options;

namespace Ashlar.Sample.AspNetCore.Endpoints;

internal static class InvitationEndpoints
{
    public static void MapInvitationEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapPost("/invitations", async (
            CreateInvitationRequest request,
            IInvitationService invitations,
            IOptions<SampleAshlarOptions> options,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            var callback = new Uri(new Uri(options.Value.PublicAppUrl), "/invitations/accept");
            await invitations.CreateInvitationAsync(request, callback, httpContext.ToAuthenticationContext(), cancellationToken);
            return Results.Accepted();
        }).RequireAuthorization("admin");

        app.MapPost("/invitations/accept", async Task<IResult> (
            AcceptInvitationRequest request,
            IInvitationService invitations,
            IAshlarSignInManager signInManager,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            var result = await invitations.AcceptInvitationAsync(request, httpContext.ToAuthenticationContext(), cancellationToken);
            if (!result.Succeeded)
            {
                return Results.BadRequest(new { error = result.FailureReason });
            }

            await signInManager.SignInAsync(httpContext, result.Value, cancellationToken: cancellationToken);

            return Results.Ok(new { userId = result.Value });
        });

        app.MapGet("/invitations/accept", (string t) => AppViews.RenderInvitationAccept(t));
    }
}
