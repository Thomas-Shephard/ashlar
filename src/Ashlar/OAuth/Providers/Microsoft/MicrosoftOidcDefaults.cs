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
    /// Gets the Microsoft personal accounts authority segment.
    /// </summary>
    public const string PersonalAccountsTenant = "consumers";

    /// <summary>
    /// Gets the Microsoft work, school, and personal accounts authority segment.
    /// </summary>
    public const string AnyAccountTenant = "common";

    /// <summary>
    /// Builds the Microsoft Entra ID OpenID Connect authority for an explicit tenant.
    /// </summary>
    /// <param name="tenantIdOrName">The explicit tenant ID or domain.</param>
    /// <returns>The Microsoft identity platform v2 authority.</returns>
    public static string BuildAuthority(string tenantIdOrName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantIdOrName);
        var tenant = tenantIdOrName.Trim();
        if (IsSharedTenantSegment(tenant))
        {
            throw new ArgumentException("Microsoft OIDC invitation registration requires a tenant-specific authority, not common, organizations, or consumers.", nameof(tenantIdOrName));
        }

        return $"https://login.microsoftonline.com/{tenant}/v2.0";
    }

    /// <summary>
    /// Builds a Microsoft Entra ID OpenID Connect authority for sign-in and account linking without invitation email matching.
    /// </summary>
    /// <param name="tenantSegment">The Microsoft authority tenant segment.</param>
    /// <returns>The Microsoft identity platform v2 authority.</returns>
    public static string BuildSignInAuthority(string tenantSegment)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantSegment);
        return $"https://login.microsoftonline.com/{tenantSegment.Trim()}/v2.0";
    }

    private static bool IsSharedTenantSegment(string tenant)
    {
        return string.Equals(tenant, "common", StringComparison.OrdinalIgnoreCase)
            || string.Equals(tenant, "organizations", StringComparison.OrdinalIgnoreCase)
            || string.Equals(tenant, "consumers", StringComparison.OrdinalIgnoreCase);
    }
}
