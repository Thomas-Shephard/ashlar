using Microsoft.AspNetCore.Antiforgery;

namespace Ashlar.Sample.AspNetCore.Extensions;

internal static class AntiforgeryExtensions
{
    public const string HeaderName = "X-CSRF-TOKEN";

    public static RouteHandlerBuilder RequireSampleAntiforgery(this RouteHandlerBuilder builder)
    {
        return builder.AddEndpointFilter(async (context, next) =>
        {
            var antiforgery = context.HttpContext.RequestServices.GetRequiredService<IAntiforgery>();
            try
            {
                await antiforgery.ValidateRequestAsync(context.HttpContext);
            }
            catch (AntiforgeryValidationException)
            {
                return Results.BadRequest(new { error = "invalid_csrf_token" });
            }

            return await next(context);
        });
    }

    public static IResult GetSampleAntiforgeryToken(HttpContext httpContext, IAntiforgery antiforgery)
    {
        var tokens = antiforgery.GetAndStoreTokens(httpContext);
        return Results.Ok(new { token = tokens.RequestToken });
    }
}
