using Ashlar.AspNetCore.Sessions;
using Ashlar.Sample.AspNetCore.Extensions;

namespace Ashlar.Sample.AspNetCore.Endpoints;

internal static class BootstrapEndpoints
{
    public static void MapBootstrapEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapPost("/api/bootstrap/first-admin", async Task<IResult> (
            HttpRequest httpRequest,
            IBootstrapService bootstrap,
            IAshlarSignInManager signInManager,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            var request = await BootstrapFirstAdminEndpointRequest.ReadAsync(httpRequest, cancellationToken);
            if (request == null
                || string.IsNullOrWhiteSpace(request.Email)
                || string.IsNullOrWhiteSpace(request.UserName)
                || string.IsNullOrWhiteSpace(request.SetupSecret))
            {
                return Results.BadRequest(new { error = "bootstrap_request_failed" });
            }

            var result = await bootstrap.BootstrapFirstAdminAsync(new BootstrapFirstAdminRequest
            {
                Email = request.Email,
                UserName = request.UserName,
                TenantId = httpContext.GetDemoTenantIdFromUntrustedHeader(),
                Audit = httpContext.ToAuditContext(),
                SetupSecret = request.SetupSecret
            }, httpContext.ToAuthenticationContext(), cancellationToken);

            if (!result.Succeeded || result.Value is not { } value)
            {
                return Results.BadRequest(new { error = "bootstrap_request_failed" });
            }

            await signInManager.SignInAsync(httpContext, value.AuthenticationResult, httpContext.ToSessionRequest(value.AuthenticationResult.User), cancellationToken);

            return Results.Ok(new { userId = value.UserId });
        });
    }
}
