using System.Security.Claims;

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
    /// <returns>An Ashlar OAuth assertion.</returns>
    public static ExternalIdentityAssertion Map(string providerName, ClaimsPrincipal principal, string idClaimType = "id")
    {
        var normalizedProviderName = AshlarOAuthOptions.NormalizeProviderName(providerName);
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentException.ThrowIfNullOrWhiteSpace(idClaimType);

        var providerKey = principal.FindFirstValue(idClaimType)?.Trim();
        if (string.IsNullOrWhiteSpace(providerKey))
        {
            throw new InvalidOperationException("The external OAuth2 principal did not contain a stable id claim.");
        }

        return new ExternalIdentityAssertion(
            ProviderType.OAuth,
            normalizedProviderName,
            providerKey,
            ExternalIdentityClaimFilter.CreateSafeClaimsDictionary(principal));
    }
}
