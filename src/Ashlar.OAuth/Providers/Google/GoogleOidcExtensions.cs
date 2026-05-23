using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace Ashlar.OAuth.Providers.Google;

/// <summary>
/// Provides Google OpenID Connect registration helpers.
/// </summary>
public static class GoogleOidcExtensions
{
    /// <summary>
    /// Adds the Google OpenID Connect provider preset.
    /// </summary>
    /// <param name="options">The Ashlar OAuth options.</param>
    /// <param name="configure">Additional OpenID Connect handler configuration.</param>
    /// <returns>The options instance.</returns>
    public static AshlarOAuthOptions AddGoogle(this AshlarOAuthOptions options, Action<OpenIdConnectOptions>? configure)
    {
        return options.AddGoogle(hostedDomains: null, configure);
    }

    /// <summary>
    /// Adds the Google OpenID Connect provider preset.
    /// </summary>
    /// <param name="options">The Ashlar OAuth options.</param>
    /// <param name="hostedDomains">The Google Workspace hosted domains allowed to sign in.</param>
    /// <param name="configure">Additional OpenID Connect handler configuration.</param>
    /// <returns>The options instance.</returns>
    public static AshlarOAuthOptions AddGoogle(
        this AshlarOAuthOptions options,
        IEnumerable<string>? hostedDomains,
        Action<OpenIdConnectOptions>? configure)
    {
        return options.AddGoogle(hostedDomains, GoogleOidcDefaults.ProviderName, configure);
    }

    /// <summary>
    /// Adds the Google OpenID Connect provider preset.
    /// </summary>
    /// <param name="options">The Ashlar OAuth options.</param>
    /// <param name="hostedDomains">The Google Workspace hosted domains allowed to sign in.</param>
    /// <param name="providerName">The Ashlar provider name to register.</param>
    /// <param name="configure">Additional OpenID Connect handler configuration.</param>
    /// <returns>The options instance.</returns>
    public static AshlarOAuthOptions AddGoogle(
        this AshlarOAuthOptions options,
        IEnumerable<string>? hostedDomains = null,
        string providerName = GoogleOidcDefaults.ProviderName,
        Action<OpenIdConnectOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        var normalizedHostedDomains = NormalizeHostedDomains(hostedDomains);

        return options.AddOidcProvider(providerName, oidcOptions =>
        {
            oidcOptions.Authority = GoogleOidcDefaults.Authority;
            oidcOptions.ResponseType = "code";
            oidcOptions.AddIfMissing("openid");
            oidcOptions.AddIfMissing("profile");
            oidcOptions.AddIfMissing("email");
            configure?.Invoke(oidcOptions);
            if (normalizedHostedDomains.Length > 0)
            {
                ConfigureHostedDomainRestriction(oidcOptions, normalizedHostedDomains);
            }
        });
    }

    private static void ConfigureHostedDomainRestriction(OpenIdConnectOptions options, string[] hostedDomains)
    {
        var onRedirectToIdentityProvider = options.Events.OnRedirectToIdentityProvider;
        options.Events.OnRedirectToIdentityProvider = async context =>
        {
            context.ProtocolMessage.SetParameter("hd", hostedDomains.Length == 1 ? hostedDomains[0] : "*");
            if (onRedirectToIdentityProvider != null)
            {
                await onRedirectToIdentityProvider(context);
            }
        };

        var onTokenValidated = options.Events.OnTokenValidated;
        options.Events.OnTokenValidated = async context =>
        {
            var hostedDomain = context.Principal?.FindFirstValue("hd");
            if (string.IsNullOrWhiteSpace(hostedDomain) || !hostedDomains.Contains(hostedDomain.Trim(), StringComparer.OrdinalIgnoreCase))
            {
                context.Fail("Google hosted domain is not allowed.");
                return;
            }

            if (onTokenValidated != null)
            {
                await onTokenValidated(context);
            }
        };
    }

    private static string[] NormalizeHostedDomains(IEnumerable<string>? hostedDomains)
    {
        if (hostedDomains == null)
        {
            return [];
        }

        return hostedDomains
            .Where(domain => !string.IsNullOrWhiteSpace(domain))
            .Select(domain => domain.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }
}
