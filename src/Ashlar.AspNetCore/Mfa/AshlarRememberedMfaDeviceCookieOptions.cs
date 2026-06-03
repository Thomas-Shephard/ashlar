using Microsoft.AspNetCore.Http;

namespace Ashlar.AspNetCore.Mfa;

/// <summary>
/// Configures Ashlar's ASP.NET Core remembered MFA device cookie transport.
/// </summary>
public sealed class AshlarRememberedMfaDeviceCookieOptions
{
    /// <summary>
    /// Gets or sets the cookie name used to transport remembered MFA device tokens.
    /// </summary>
    public string CookieName { get; set; } = AshlarRememberedMfaDeviceCookieDefaults.CookieName;

    /// <summary>
    /// Gets the secure cookie settings used by Ashlar.
    /// </summary>
    public CookieBuilder Cookie { get; } = new()
    {
        HttpOnly = true,
        SecurePolicy = CookieSecurePolicy.Always,
        SameSite = SameSiteMode.Lax,
        Path = "/"
    };
}
