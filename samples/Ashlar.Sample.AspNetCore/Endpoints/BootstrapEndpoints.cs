using Ashlar.AspNetCore.Sessions;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Sample.AspNetCore.Extensions;

namespace Ashlar.Sample.AspNetCore.Endpoints;

internal static class BootstrapEndpoints
{
    public static void MapBootstrapEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/bootstrap/status", async (IBootstrapService bootstrap, CancellationToken cancellationToken) =>
        {
            var status = await bootstrap.GetStatusAsync(cancellationToken);
            return Results.Ok(new { status = status.ToString() });
        });

        app.MapPost("/api/bootstrap/invitations", async Task<IResult> (
            HttpRequest httpRequest,
            IBootstrapService bootstrap,
            IAshlarSignInManager signInManager,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            var request = await BootstrapInvitationRequest.ReadAsync(httpRequest, cancellationToken);
            var email = string.IsNullOrWhiteSpace(request?.Email) ? "admin@example.com" : request.Email;
            var userName = string.IsNullOrWhiteSpace(request?.UserName) ? "Admin" : request.UserName;

            var createResult = await bootstrap.CreateBootstrapInvitationAsync(new CreateBootstrapInvitationRequest
            {
                Email = email,
                UserName = userName
            }, cancellationToken);

            if (!createResult.Succeeded || createResult.Token == null)
            {
                return Results.BadRequest(new { error = createResult.FailureReason });
            }

            var acceptResult = await bootstrap.AcceptBootstrapInvitationAsync(
                new AcceptInvitationRequest { Token = createResult.Token, UserName = userName },
                httpContext.ToAuthenticationContext(),
                cancellationToken);

            if (!acceptResult.Succeeded || acceptResult.UserId == null)
            {
                return Results.BadRequest(new { error = acceptResult.FailureReason });
            }

            await signInManager.SignInAsync(httpContext, acceptResult.UserId.Value, cancellationToken: cancellationToken);

            return Results.Ok(new { userId = acceptResult.UserId });
        });
    }
}
