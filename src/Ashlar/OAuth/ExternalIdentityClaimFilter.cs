using System.Collections.ObjectModel;
using System.Security.Claims;

namespace Ashlar.OAuth;

internal static class ExternalIdentityClaimFilter
{
    private static readonly HashSet<string> SensitiveClaimTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "access_token",
        "refresh_token",
        "id_token",
        "authorization_code",
        "code",
        "cookie",
        "client_secret",
        "password"
    };

    public static ReadOnlyDictionary<string, IReadOnlyList<string>> CreateSafeClaimsDictionary(ClaimsPrincipal principal)
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
}
