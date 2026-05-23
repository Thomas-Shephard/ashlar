using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Ashlar.OAuth;

internal static class AshlarExternalTicket
{
    public static async Task<AuthenticateResult> AuthenticateAndClearAsync(HttpContext httpContext, string scheme)
    {
        try
        {
            return await httpContext.AuthenticateAsync(scheme);
        }
        finally
        {
            await TryClearAsync(httpContext, scheme);
        }
    }

    public static async Task TryClearAsync(HttpContext httpContext, string scheme)
    {
        try
        {
            await httpContext.SignOutAsync(scheme);
        }
        catch
        {
            // Best-effort cleanup must not mask the original callback failure.
        }
    }
}
