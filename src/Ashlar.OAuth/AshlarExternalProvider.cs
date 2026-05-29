using Microsoft.AspNetCore.Authentication;

namespace Ashlar.OAuth;

internal sealed record AshlarExternalProvider(
    ProviderType Type,
    string ProviderName,
    string SchemeName,
    AshlarOidcProviderKeyMode OidcProviderKeyMode = AshlarOidcProviderKeyMode.Subject,
    string OAuth2ProviderKeyClaimType = "id");

internal static class AshlarExternalProviderResolver
{
    public static AshlarExternalProvider? GetProvider(AshlarOAuthOptions options, string providerName)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(providerName))
        {
            return null;
        }

        var normalizedProviderName = AshlarOAuthOptions.NormalizeProviderName(providerName);
        if (options.OidcProviders.TryGetValue(normalizedProviderName, out var oidcProvider))
        {
            return new AshlarExternalProvider(
                ProviderType.Oidc,
                oidcProvider.ProviderName,
                oidcProvider.SchemeName,
                oidcProvider.ProviderKeyMode);
        }

        return options.OAuth2Providers.TryGetValue(normalizedProviderName, out var oauthProvider)
            ? new AshlarExternalProvider(
                ProviderType.OAuth,
                oauthProvider.ProviderName,
                oauthProvider.SchemeName,
                OAuth2ProviderKeyClaimType: oauthProvider.ProviderKeyClaimType)
            : null;
    }

    public static ExternalIdentityAssertion MapAssertion(AshlarExternalProvider provider, System.Security.Claims.ClaimsPrincipal principal)
    {
        return provider.Type == ProviderType.Oidc
            ? OidcExternalIdentityAssertionMapper.Map(provider.ProviderName, principal, provider.OidcProviderKeyMode)
            : OAuth2ExternalIdentityAssertionMapper.Map(provider.ProviderName, principal, provider.OAuth2ProviderKeyClaimType);
    }

    public static bool MatchesProvider(AuthenticateResult result, AshlarExternalProvider provider)
    {
        return result.Properties is { } properties
            && properties.Items.TryGetValue(AshlarOAuthAuthenticationProperties.ProviderName, out var providerName)
            && properties.Items.TryGetValue(AshlarOAuthAuthenticationProperties.SchemeName, out var schemeName)
            && string.Equals(provider.ProviderName, providerName, StringComparison.OrdinalIgnoreCase)
            && string.Equals(provider.SchemeName, schemeName, StringComparison.Ordinal)
            && MatchesProviderType(properties, provider);
    }

    public static IAuthenticationProvider CreateAuthenticationProvider(AshlarExternalProvider provider)
    {
        return provider.Type == ProviderType.Oidc
            ? new OidcAuthenticationProvider(provider.ProviderName)
            : new OAuthAuthenticationProvider(provider.ProviderName);
    }

    private static bool MatchesProviderType(AuthenticationProperties properties, AshlarExternalProvider provider)
    {
        if (!properties.Items.TryGetValue(AshlarOAuthAuthenticationProperties.ProviderType, out var providerType))
        {
            return false;
        }

        return string.Equals(provider.Type.Value, providerType, StringComparison.Ordinal);
    }
}
