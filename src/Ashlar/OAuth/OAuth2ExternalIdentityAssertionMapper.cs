using System.Security.Claims;
using Ashlar.Identity.Providers.External;

namespace Ashlar.OAuth;

internal static class OAuth2ExternalIdentityAssertionMapper
{
    internal static ExternalIdentityAssertion Map(
        string providerName,
        ClaimsPrincipal principal,
        string idClaimType = "id",
        bool allowUnsafeProviderKeyClaimType = false)
    {
        var normalizedProviderName = AshlarOAuthOptions.NormalizeProviderName(providerName);
        ArgumentNullException.ThrowIfNull(principal);
        var normalizedIdClaimType = AshlarOAuthOptions.NormalizeProviderKeyClaimType(idClaimType);
        AshlarOAuthOptions.ValidateOAuth2ProviderKeyClaimType(normalizedIdClaimType, allowUnsafeProviderKeyClaimType);

        var providerKey = principal.FindFirstValue(normalizedIdClaimType)?.Trim();
        if (string.IsNullOrWhiteSpace(providerKey))
        {
            throw new InvalidOperationException("The external OAuth2 principal did not contain a stable provider key claim.");
        }

        return new ExternalIdentityAssertion(
            ProviderType.OAuth,
            normalizedProviderName,
            providerKey,
            ExternalIdentityClaimFilter.CreateSafeClaimsDictionary(principal));
    }
}
