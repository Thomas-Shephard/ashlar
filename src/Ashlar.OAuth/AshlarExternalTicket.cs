using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Ashlar.OAuth;

/// <summary>
/// Reads and clears ASP.NET Core's temporary external authentication ticket after a remote provider callback.
/// </summary>
public static class AshlarExternalTicket
{
    /// <summary>
    /// Authenticates the temporary external ticket and clears it before returning control to callback handling.
    /// </summary>
    /// <param name="httpContext">The current HTTP context.</param>
    /// <param name="scheme">The temporary external authentication scheme configured for remote provider sign-in.</param>
    /// <param name="cancellationToken">A token that cancels ticket authentication, but not best-effort ticket cleanup.</param>
    /// <returns>The result produced by the temporary external authentication scheme.</returns>
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

    /// <summary>
    /// Attempts to clear the temporary external ticket without masking the callback failure being handled.
    /// </summary>
    /// <param name="httpContext">The current HTTP context.</param>
    /// <param name="scheme">The temporary external authentication scheme configured for remote provider sign-in.</param>
    /// <param name="cancellationToken">A token that cancels the cleanup attempt before sign-out begins.</param>
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
