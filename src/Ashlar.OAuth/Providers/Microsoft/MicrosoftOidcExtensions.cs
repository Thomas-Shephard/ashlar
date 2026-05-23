using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace Ashlar.OAuth.Providers.Microsoft;

/// <summary>
/// Provides Microsoft Entra ID OpenID Connect registration helpers.
/// </summary>
public static class MicrosoftOidcExtensions
{
    /// <summary>
    /// Adds a Microsoft Entra ID OpenID Connect provider preset for an explicit tenant.
    /// </summary>
    /// <param name="options">The Ashlar OAuth options.</param>
    /// <param name="tenantIdOrName">The explicit tenant ID, domain, or supported tenant segment.</param>
    /// <param name="configure">Additional OpenID Connect handler configuration.</param>
    /// <returns>The options instance.</returns>
    public static AshlarOAuthOptions AddMicrosoft(
        this AshlarOAuthOptions options,
        string tenantIdOrName,
        Action<OpenIdConnectOptions>? configure)
    {
        return options.AddMicrosoft(tenantIdOrName, MicrosoftOidcDefaults.ProviderName, configure);
    }

    /// <summary>
    /// Adds a Microsoft Entra ID OpenID Connect provider preset for an explicit tenant.
    /// </summary>
    /// <param name="options">The Ashlar OAuth options.</param>
    /// <param name="tenantIdOrName">The explicit tenant ID, domain, or supported tenant segment.</param>
    /// <param name="providerName">The Ashlar provider name to register.</param>
    /// <param name="configure">Additional OpenID Connect handler configuration.</param>
    /// <returns>The options instance.</returns>
    public static AshlarOAuthOptions AddMicrosoft(
        this AshlarOAuthOptions options,
        string tenantIdOrName,
        string providerName = MicrosoftOidcDefaults.ProviderName,
        Action<OpenIdConnectOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        var authority = MicrosoftOidcDefaults.BuildAuthority(tenantIdOrName);

        return options.AddOidcProvider(providerName, oidcOptions =>
        {
            oidcOptions.Authority = authority;
            oidcOptions.ResponseType = "code";
            oidcOptions.AddIfMissing("openid");
            oidcOptions.AddIfMissing("profile");
            oidcOptions.AddIfMissing("email");
            configure?.Invoke(oidcOptions);
        });
    }
}
