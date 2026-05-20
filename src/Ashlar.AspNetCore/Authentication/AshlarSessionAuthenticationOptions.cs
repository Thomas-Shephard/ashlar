using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Ashlar.AspNetCore.Authentication;

/// <summary>
/// Configures Ashlar's ASP.NET Core session authentication scheme.
/// </summary>
public sealed class AshlarSessionAuthenticationOptions : AuthenticationSchemeOptions
{
    /// <summary>
    /// Gets or sets the authentication scheme registered for Ashlar sessions.
    /// </summary>
    public string SchemeName { get; set; } = AshlarSessionAuthenticationDefaults.AuthenticationScheme;

    /// <summary>
    /// Gets or sets the cookie name used to transport Ashlar session tokens.
    /// </summary>
    public string CookieName { get; set; } = AshlarSessionAuthenticationDefaults.CookieName;

    /// <summary>
    /// Gets or sets the issuer used for claims created by the authentication handler.
    /// </summary>
    public new string ClaimsIssuer
    {
        get => base.ClaimsIssuer ?? AshlarSessionAuthenticationDefaults.ClaimsIssuer;
        set => base.ClaimsIssuer = value;
    }

    /// <summary>
    /// Reserved for future cookie lifetime renewal support.
    /// </summary>
    public bool SlidingCookieExpiration { get; set; }

    /// <summary>
    /// Optional path used when a challenge should redirect to a login endpoint.
    /// </summary>
    public PathString LoginPath { get; set; }

    /// <summary>
    /// Optional path used when a forbidden result should redirect to an access-denied endpoint.
    /// </summary>
    public PathString AccessDeniedPath { get; set; }

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


