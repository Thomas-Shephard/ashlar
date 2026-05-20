namespace Ashlar.AspNetCore.Authentication;

/// <summary>
/// Defaults for Ashlar session authentication.
/// </summary>
public static class AshlarSessionAuthenticationDefaults
{
    /// <summary>
    /// Defines the authentication scheme value.
    /// </summary>
    public const string AuthenticationScheme = "Ashlar";
    /// <summary>
    /// Defines the cookie name value.
    /// </summary>
    public const string CookieName = "__Host-Ashlar.Session";
    /// <summary>
    /// Defines the claims issuer value.
    /// </summary>
    public const string ClaimsIssuer = "Ashlar";
}


