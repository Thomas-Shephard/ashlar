using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace Ashlar.OAuth.Providers.Apple;

/// <summary>
/// Provides Apple OpenID Connect registration helpers.
/// </summary>
public static class AppleOidcExtensions
{
    /// <summary>
    /// Adds the Apple OpenID Connect provider preset.
    /// </summary>
    /// <param name="options">The Ashlar OAuth options.</param>
    /// <param name="configure">Additional OpenID Connect handler configuration.</param>
    /// <returns>The options instance.</returns>
    public static AshlarOAuthOptions AddApple(this AshlarOAuthOptions options, Action<OpenIdConnectOptions>? configure)
    {
        return options.AddApple(AppleOidcDefaults.ProviderName, configure);
    }

    /// <summary>
    /// Adds the Apple OpenID Connect provider preset.
    /// </summary>
    /// <param name="options">The Ashlar OAuth options.</param>
    /// <param name="providerName">The Ashlar provider name to register.</param>
    /// <param name="configure">Additional OpenID Connect handler configuration.</param>
    /// <returns>The options instance.</returns>
    public static AshlarOAuthOptions AddApple(
        this AshlarOAuthOptions options,
        string providerName = AppleOidcDefaults.ProviderName,
        Action<OpenIdConnectOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(options);

        return options.AddOidcProvider(providerName, oidcOptions =>
        {
            oidcOptions.Authority = AppleOidcDefaults.Authority;
            oidcOptions.ResponseType = "code";
            oidcOptions.Scope.Remove("profile");
            oidcOptions.AddIfMissing("openid");
            oidcOptions.AddIfMissing("email");
            oidcOptions.AddIfMissing("name");
            configure?.Invoke(oidcOptions);
        });
    }
}
