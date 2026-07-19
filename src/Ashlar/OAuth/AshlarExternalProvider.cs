using Microsoft.AspNetCore.Authentication;
using Ashlar.Identity.Providers.External;
using System.Diagnostics.CodeAnalysis;

namespace Ashlar.OAuth;

internal sealed record AshlarExternalProvider(
    ProviderType Type,
    string ProviderName,
    string SchemeName,
    string OAuth2ProviderKeyClaimType = "id",
    bool AllowUnsafeOAuth2ProviderKeyClaimType = false);

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
                oidcProvider.SchemeName);
        }

        return options.OAuth2Providers.TryGetValue(normalizedProviderName, out var oauthProvider)
            ? new AshlarExternalProvider(
                ProviderType.OAuth,
                oauthProvider.ProviderName,
                oauthProvider.SchemeName,
                OAuth2ProviderKeyClaimType: oauthProvider.ProviderKeyClaimType,
                AllowUnsafeOAuth2ProviderKeyClaimType: oauthProvider.AllowUnsafeProviderKeyClaimType)
            : null;
    }

    public static bool TryMapAssertion(
        AshlarExternalProvider provider,
        System.Security.Claims.ClaimsPrincipal principal,
        [NotNullWhen(true)] out ExternalIdentityAssertion? assertion)
    {
        try
        {
            assertion = provider.Type == ProviderType.Oidc
                ? OidcExternalIdentityAssertionMapper.Map(provider.ProviderName, principal)
                : OAuth2ExternalIdentityAssertionMapper.Map(
                    provider.ProviderName,
                    principal,
                    provider.OAuth2ProviderKeyClaimType,
                    provider.AllowUnsafeOAuth2ProviderKeyClaimType);
            return true;
        }
        catch (InvalidOperationException)
        {
            assertion = null;
            return false;
        }
        catch (ArgumentException)
        {
            assertion = null;
            return false;
        }
    }

    public static bool MatchesProvider(AuthenticateResult result, AshlarExternalProvider provider)
    {
        return MatchProvider(result, provider).Matched;
    }

    public static (bool Matched, AuthenticationProperties? Properties) MatchProvider(
        AuthenticateResult result,
        AshlarExternalProvider provider)
    {
        if (result.Properties is { } properties
            && properties.Items.TryGetValue(AshlarOAuthAuthenticationProperties.ProviderName, out var providerName)
            && properties.Items.TryGetValue(AshlarOAuthAuthenticationProperties.SchemeName, out var schemeName)
            && string.Equals(provider.ProviderName, providerName, StringComparison.OrdinalIgnoreCase)
            && string.Equals(provider.SchemeName, schemeName, StringComparison.Ordinal)
            && MatchesProviderType(properties, provider))
        {
            return (true, properties);
        }

        return (false, null);
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
