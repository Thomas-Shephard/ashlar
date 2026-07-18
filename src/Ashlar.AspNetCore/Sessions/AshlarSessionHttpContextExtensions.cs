using Ashlar.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Ashlar.AspNetCore.Sessions;

/// <summary>Provides access to Ashlar-validated session capabilities.</summary>
public static class AshlarSessionHttpContextExtensions
{
    /// <summary>Gets the Ashlar-issued capability for the current validated request.</summary>
    /// <param name="httpContext">Current request context populated by Ashlar session authentication.</param>
    /// <returns>The validated capability, or <see langword="null" /> when Ashlar did not validate an active session.</returns>
    public static ValidatedAuthenticationSession? GetValidatedAuthenticationSession(this HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        return httpContext.Items[AshlarHttpContextItems.ValidatedAuthenticationSession] as ValidatedAuthenticationSession;
    }
}
