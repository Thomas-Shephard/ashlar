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
    /// <param name="providerKeyMode">How Ashlar composes the stable provider key from validated OIDC claims.</param>
    /// <returns>An Ashlar assertion backed by the principal's stable OIDC issuer and subject claims by default.</returns>
    public static ExternalIdentityAssertion Map(string providerName, ClaimsPrincipal principal, AshlarOidcProviderKeyMode providerKeyMode = AshlarOidcProviderKeyMode.IssuerAndSubject)
    {
        var normalizedProviderName = AshlarOAuthOptions.NormalizeProviderName(providerName);
        ArgumentNullException.ThrowIfNull(principal);

        var subject = principal.FindFirstValue("sub")?.Trim();
        if (string.IsNullOrWhiteSpace(subject))
        {
            throw new InvalidOperationException("The external OpenID Connect principal did not contain a subject claim.");
        }

        var providerKey = CreateProviderKey(principal, subject, providerKeyMode);

        return new ExternalIdentityAssertion(
            ProviderType.Oidc,
            normalizedProviderName,
            providerKey,
            ExternalIdentityClaimFilter.CreateSafeClaimsDictionary(principal));
    }

    private static string CreateProviderKey(ClaimsPrincipal principal, string subject, AshlarOidcProviderKeyMode providerKeyMode)
    {
        return providerKeyMode switch
        {
            AshlarOidcProviderKeyMode.Subject => subject,
            AshlarOidcProviderKeyMode.IssuerAndSubject => CreateIssuerQualifiedProviderKey(principal, subject),
            _ => throw new InvalidOperationException("The configured OpenID Connect provider key mode is not supported.")
        };
    }

    private static string CreateIssuerQualifiedProviderKey(ClaimsPrincipal principal, string subject)
    {
        var issuer = principal.FindFirstValue("iss")?.Trim();
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
