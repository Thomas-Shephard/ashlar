namespace Ashlar.OAuth.Providers.Microsoft;

/// <summary>
/// Defines Microsoft Entra ID OpenID Connect defaults used by Ashlar.
/// </summary>
public static class MicrosoftOidcDefaults
{
    /// <summary>
    /// Gets the Ashlar provider name for Microsoft OpenID Connect.
    /// </summary>
    public const string ProviderName = "Microsoft";

    /// <summary>
    /// Builds the Microsoft Entra ID OpenID Connect authority for an explicit tenant segment.
    /// </summary>
    /// <param name="tenantIdOrName">The explicit tenant ID, domain, or supported tenant segment.</param>
    /// <returns>The Microsoft identity platform v2 authority.</returns>
    public static string BuildAuthority(string tenantIdOrName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantIdOrName);
        return $"https://login.microsoftonline.com/{tenantIdOrName.Trim()}/v2.0";
    }
}
