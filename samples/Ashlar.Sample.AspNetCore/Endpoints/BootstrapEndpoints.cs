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
            IUserRepository users,
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
                TenantId = httpContext.GetAshlarTenantId(),
                Audit = httpContext.ToAuditContext(),
                SetupSecret = request.SetupSecret
            }, httpContext.ToAuthenticationContext(), cancellationToken);

            if (!result.Succeeded)
            {
                return Results.BadRequest(new { error = "bootstrap_request_failed" });
            }

            var user = await users.GetUserByIdAsync(result.Value, cancellationToken);
            await signInManager.SignInAsync(httpContext, result.Value, httpContext.ToSessionRequest(user), cancellationToken);

            return Results.Ok(new { userId = result.Value });
        });
    }
}
