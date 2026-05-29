using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Ashlar.OAuth;

internal static class AshlarExternalTicket
{
    public static async Task<AuthenticateResult> AuthenticateAndClearAsync(HttpContext httpContext, string scheme, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var result = await httpContext.AuthenticateAsync(scheme);
            cancellationToken.ThrowIfCancellationRequested();
            return result;
        }
        finally
        {
            await TryClearAsync(httpContext, scheme, CancellationToken.None);
        }
    }

    public static async Task TryClearAsync(HttpContext httpContext, string scheme, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
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
