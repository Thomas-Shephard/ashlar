using System.Security.Claims;
using Ashlar.Identity.Providers.External;

namespace Ashlar.OAuth;

/// <summary>
/// Maps a validated ASP.NET Core OAuth2 principal into an Ashlar external identity assertion.
/// </summary>
public static class OAuth2ExternalIdentityAssertionMapper
{
    /// <summary>
    /// Maps the principal to an Ashlar assertion backed by the provider's stable user id claim.
    /// </summary>
    /// <param name="providerName">The configured Ashlar provider name.</param>
    /// <param name="principal">The validated external principal.</param>
    /// <param name="idClaimType">The claim type containing the stable provider user id.</param>
    /// <param name="allowUnsafeProviderKeyClaimType">Whether the caller explicitly accepts responsibility for using a claim type that Ashlar normally rejects as mutable or non-unique.</param>
    /// <returns>An Ashlar OAuth assertion.</returns>
    public static ExternalIdentityAssertion Map(
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
