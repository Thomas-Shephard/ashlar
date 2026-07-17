using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Ashlar.OAuth;

internal static class AshlarExternalTicket
{
    internal static async Task<AuthenticateResult> AuthenticateAndClearAsync(HttpContext httpContext, string scheme, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        AuthenticateResult result;
        try
        {
            result = await httpContext.AuthenticateAsync(scheme);
            cancellationToken.ThrowIfCancellationRequested();
        }
        catch
        {
            await TryClearAsync(httpContext, scheme, CancellationToken.None);
            throw;
        }

        if (!result.Succeeded)
        {
            await TryClearAsync(httpContext, scheme, CancellationToken.None);
            return result;
        }

        try
        {
            await httpContext.SignOutAsync(scheme);
            return result;
        }
        catch (Exception exception)
        {
            return AuthenticateResult.Fail(exception);
        }
    }

    internal static async Task TryClearAsync(HttpContext httpContext, string scheme, CancellationToken cancellationToken = default)
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
