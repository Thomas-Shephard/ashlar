using System.Collections.ObjectModel;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Ashlar.OAuth;

/// <summary>
/// Maps a validated ASP.NET Core OpenID Connect principal into an Ashlar external identity assertion.
/// </summary>
public static class OidcExternalIdentityAssertionMapper
{
    private static readonly HashSet<string> SensitiveClaimTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "access_token",
        "refresh_token",
        "id_token",
        "authorization_code",
        "code",
        "cookie"
    };

    /// <summary>
    /// Maps the principal to an Ashlar external identity assertion.
    /// </summary>
    /// <param name="providerName">The configured Ashlar provider name.</param>
    /// <param name="principal">The validated external principal.</param>
    /// <param name="providerKeyMode">How Ashlar composes the stable provider key from validated OIDC claims.</param>
    /// <returns>An Ashlar assertion backed by the principal's stable OIDC subject claim.</returns>
    public static ExternalIdentityAssertion Map(string providerName, ClaimsPrincipal principal, AshlarOidcProviderKeyMode providerKeyMode = AshlarOidcProviderKeyMode.Subject)
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
            CreateSafeClaimsDictionary(principal));
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

    private static ReadOnlyDictionary<string, IReadOnlyList<string>> CreateSafeClaimsDictionary(ClaimsPrincipal principal)
    {
        var claims = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var claim in principal.Claims)
        {
            if (string.IsNullOrWhiteSpace(claim.Type) || string.IsNullOrWhiteSpace(claim.Value) || SensitiveClaimTypes.Contains(claim.Type))
            {
                continue;
            }

            if (claims.TryGetValue(claim.Type, out var values))
            {
                values.Add(claim.Value);
            }
            else
            {
                claims.Add(claim.Type, [claim.Value]);
            }
        }

        var safeClaims = new Dictionary<string, IReadOnlyList<string>>(claims.Count, StringComparer.Ordinal);
        foreach (var claim in claims)
        {
            safeClaims.Add(claim.Key, claim.Value.ToArray());
        }

        return safeClaims.AsReadOnly();
    }

    private sealed record OidcProviderKey(string Issuer, string Subject);
}
