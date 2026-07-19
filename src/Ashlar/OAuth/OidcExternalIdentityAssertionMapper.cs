using System.Security.Claims;
using Ashlar.Identity.Providers.External;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

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
    /// <returns>An Ashlar assertion backed by the principal's stable OIDC issuer and subject claims.</returns>
    public static ExternalIdentityAssertion Map(string providerName, ClaimsPrincipal principal)
    {
        var normalizedProviderName = AshlarOAuthOptions.NormalizeProviderName(providerName);
        ArgumentNullException.ThrowIfNull(principal);

        var subject = principal.FindFirstValue("sub");
        if (string.IsNullOrWhiteSpace(subject))
        {
            throw new InvalidOperationException("The external OpenID Connect principal did not contain a subject claim.");
        }

        var providerKey = CreateProviderKey(principal, subject);

        return new ExternalIdentityAssertion(
            ProviderType.Oidc,
            normalizedProviderName,
            providerKey,
            ExternalIdentityClaimFilter.CreateSafeClaimsDictionary(principal));
    }

    private static string CreateProviderKey(ClaimsPrincipal principal, string subject)
    {
        var issuer = principal.FindAll(AshlarOAuthAuthenticationProperties.OidcIssuerClaim).LastOrDefault()?.Value ?? principal.FindFirstValue("iss");
        if (string.IsNullOrWhiteSpace(issuer))
        {
            throw new InvalidOperationException("The external OpenID Connect principal did not contain an issuer claim.");
        }

        var payload = JsonSerializer.Serialize(new OidcProviderKey(issuer, subject));
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(payload));
        return string.Concat("oidc-sha256:", Convert.ToHexString(hash));
    }

    private sealed record OidcProviderKey(string Issuer, string Subject);
}
