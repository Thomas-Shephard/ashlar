using Ashlar.AspNetCore.Sessions;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Sample.AspNetCore.Extensions;

namespace Ashlar.Sample.AspNetCore.Endpoints;

internal static class BootstrapEndpoints
{
    public static void MapBootstrapEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/bootstrap/status", async (IBootstrapService bootstrap, CancellationToken cancellationToken) =>
        {
            var status = await bootstrap.GetStatusAsync(cancellationToken);
            return Results.Ok(new { status = status.ToString() });
        });

        app.MapPost("/bootstrap/invitations", async Task<IResult> (
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

            if (!createResult.Succeeded || createResult.Value == null)
            {
                return Results.BadRequest(new { error = createResult.FailureReason });
            }

            var acceptResult = await bootstrap.AcceptBootstrapInvitationAsync(
                new AcceptInvitationRequest { Token = createResult.Value, UserName = userName },
                httpContext.ToAuthenticationContext(),
                cancellationToken);

            if (!acceptResult.Succeeded || acceptResult.Value == Guid.Empty)
            {
                return Results.BadRequest(new { error = acceptResult.FailureReason });
            }

            await signInManager.SignInAsync(httpContext, acceptResult.Value, cancellationToken: cancellationToken);

            return Results.Ok(new { userId = acceptResult.Value });
        });
    }
}
