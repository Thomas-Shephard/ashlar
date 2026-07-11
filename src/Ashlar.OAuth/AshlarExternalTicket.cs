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
    /// <returns>The authentication result, or a failed result when a successful ticket cannot be cleared.</returns>
    public static async Task<AuthenticateResult> AuthenticateAndClearAsync(HttpContext httpContext, string scheme, CancellationToken cancellationToken = default)
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
