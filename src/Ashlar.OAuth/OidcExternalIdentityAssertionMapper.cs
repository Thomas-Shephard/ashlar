using System.Security.Claims;

namespace Ashlar.OAuth;

/// <summary>
/// Maps a validated ASP.NET Core OpenID Connect principal into an Ashlar external identity assertion.
/// </summary>
public static class OidcExternalIdentityAssertionMapper
{
    /// <summary>
    /// Maps the principal to an Ashlar external identity assertion.
    /// </summary>
    /// <param name="providerName">The configured Ashlar provider name.</param>
    /// <param name="principal">The validated external principal.</param>
    /// <returns>An Ashlar assertion backed by the principal's stable OIDC subject claim.</returns>
    public static ExternalIdentityAssertion Map(string providerName, ClaimsPrincipal principal)
    {
        var normalizedProviderName = AshlarOAuthOptions.NormalizeProviderName(providerName);
        ArgumentNullException.ThrowIfNull(principal);

        var subject = principal.FindFirstValue("sub");
        if (string.IsNullOrWhiteSpace(subject))
        {
            throw new InvalidOperationException("The external OpenID Connect principal did not contain a subject claim.");
        }

        return new ExternalIdentityAssertion(
            ProviderType.Oidc,
            normalizedProviderName,
            subject,
            CreateSafeClaimsDictionary(principal));
    }

    private static Dictionary<string, string> CreateSafeClaimsDictionary(ClaimsPrincipal principal)
    {
        var claims = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var claim in principal.Claims)
        {
            if (string.IsNullOrWhiteSpace(claim.Type) || string.IsNullOrWhiteSpace(claim.Value))
            {
                continue;
            }

            if (claims.TryGetValue(claim.Type, out var existingValue))
            {
                claims[claim.Type] = string.Concat(existingValue, ",", claim.Value);
            }
            else
            {
                claims.Add(claim.Type, claim.Value);
            }
        }

        return claims;
    }
}
