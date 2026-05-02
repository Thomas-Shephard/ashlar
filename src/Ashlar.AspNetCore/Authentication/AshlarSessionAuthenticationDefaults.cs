namespace Ashlar.AspNetCore.Authentication;

/// <summary>
/// Defaults for Ashlar session authentication.
/// </summary>
public static class AshlarSessionAuthenticationDefaults
{
    public const string AuthenticationScheme = "Ashlar";
    public const string CookieName = "__Host-Ashlar.Session";
    public const string ClaimsIssuer = "Ashlar";
}
