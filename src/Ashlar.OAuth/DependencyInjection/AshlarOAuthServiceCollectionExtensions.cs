// ReSharper disable CheckNamespace

using Ashlar.OAuth;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection.Extensions;

#pragma warning disable IDE0130
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130

/// <summary>
/// Provides dependency injection registration helpers for Ashlar OAuth and OpenID Connect integration.
/// </summary>
public static class AshlarOAuthServiceCollectionExtensions
{
    /// <summary>
    /// Adds Ashlar OAuth and OpenID Connect sign-in integration.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">The OAuth options configuration callback.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddAshlarOAuth(this IServiceCollection services, Action<AshlarOAuthOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddAshlarInvitations();

        var options = new AshlarOAuthOptions();
        configure(options);

        if (options.OidcProviders.Count == 0 && options.OAuth2Providers.Count == 0)
        {
            throw new ArgumentException("At least one external OAuth or OpenID Connect provider must be configured.", nameof(configure));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(options.ExternalSignInScheme);

        services.Configure(configure);
        services.TryAddScoped<AshlarExternalCredentialAuthenticationService>();
        services.TryAddScoped<AshlarExternalAccountLinkService>();
        services.TryAddScoped<AshlarOidcInvitationRegistrationService>();
        services.TryAddScoped<IOidcInvitationEmailMatchPolicy>(_ =>
        {
            IOidcInvitationEmailMatchPolicy policy = new StandardOidcVerifiedEmailMatchPolicy();
            foreach (var decorator in options.InvitationEmailMatchPolicyDecorators)
            {
                policy = decorator(policy);
            }

            return policy;
        });

        var authenticationBuilder = services.AddAuthentication();
        authenticationBuilder.AddCookie(options.ExternalSignInScheme, cookieOptions =>
        {
            cookieOptions.Cookie.HttpOnly = true;
            cookieOptions.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            cookieOptions.Cookie.SameSite = SameSiteMode.Lax;
            cookieOptions.ExpireTimeSpan = TimeSpan.FromMinutes(5);
            cookieOptions.SlidingExpiration = false;
        });

        foreach (var provider in options.OidcProviders.Values)
        {
            services.AddAuthenticationProvider(_ => new OidcAuthenticationProvider(provider.ProviderName));
            authenticationBuilder.AddOpenIdConnect(provider.SchemeName, oidcOptions =>
            {
                provider.Configure(oidcOptions);
                ConfigureDefaults(oidcOptions, options.ExternalSignInScheme, provider);
            });
        }

        foreach (var provider in options.OAuth2Providers.Values)
        {
            services.AddAuthenticationProvider(_ => new OAuthAuthenticationProvider(provider.ProviderName));
            authenticationBuilder.AddOAuth(provider.SchemeName, oauthOptions =>
            {
                provider.Configure(oauthOptions);
                ConfigureDefaults(oauthOptions, options.ExternalSignInScheme, provider);
            });
        }

        return services;
    }

    private static void ConfigureDefaults(OpenIdConnectOptions options, string externalSignInScheme, AshlarOidcProviderOptions provider)
    {
        options.SignInScheme = externalSignInScheme;
        options.SaveTokens = false;
        options.GetClaimsFromUserInfoEndpoint = provider.GetClaimsFromUserInfoEndpoint;
        options.MapInboundClaims = false;

        if (!options.CallbackPath.HasValue || string.Equals(options.CallbackPath.Value, "/signin-oidc", StringComparison.Ordinal))
        {
            options.CallbackPath = $"/signin-oidc/{provider.SchemeName}";
        }

        var onTicketReceived = options.Events.OnTicketReceived;
        options.Events.OnTicketReceived = async context =>
        {
            if (context.Properties != null)
            {
                context.Properties.Items[AshlarOAuthAuthenticationProperties.ProviderName] = provider.ProviderName;
                context.Properties.Items[AshlarOAuthAuthenticationProperties.SchemeName] = provider.SchemeName;
                context.Properties.Items[AshlarOAuthAuthenticationProperties.ProviderType] = ProviderType.Oidc.Value;
            }

            if (onTicketReceived != null)
            {
                await onTicketReceived(context);
            }
        };
    }

    private static void ConfigureDefaults(OAuthOptions options, string externalSignInScheme, AshlarOAuth2ProviderOptions provider)
    {
        options.SignInScheme = externalSignInScheme;
        options.SaveTokens = false;

        if (!options.CallbackPath.HasValue || string.Equals(options.CallbackPath.Value, "/signin-oauth", StringComparison.Ordinal))
        {
            options.CallbackPath = $"/signin-oauth/{provider.SchemeName}";
        }

        var onTicketReceived = options.Events.OnTicketReceived;
        options.Events.OnTicketReceived = async context =>
        {
            if (context.Properties != null)
            {
                context.Properties.Items[AshlarOAuthAuthenticationProperties.ProviderName] = provider.ProviderName;
                context.Properties.Items[AshlarOAuthAuthenticationProperties.SchemeName] = provider.SchemeName;
                context.Properties.Items[AshlarOAuthAuthenticationProperties.ProviderType] = ProviderType.OAuth.Value;
            }

            if (onTicketReceived != null)
            {
                await onTicketReceived(context);
            }
        };
    }
}
