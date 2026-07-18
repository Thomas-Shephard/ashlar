using System.Security.Claims;

namespace Ashlar.OAuth;

/// <summary>
/// Maps display-oriented profile hints from an already validated OpenID Connect principal.
/// </summary>
public static class AshlarOidcProfileMapper
{
    /// <summary>
    /// Maps safe profile hints from the principal.
    /// </summary>
    /// <param name="principal">The validated OpenID Connect principal.</param>
    /// <returns>The mapped profile hints.</returns>
    public static AshlarOidcProfile Map(ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        var givenName = FindFirstTrimmedValue(principal, "given_name", ClaimTypes.GivenName);
        var familyName = FindFirstTrimmedValue(principal, "family_name", ClaimTypes.Surname);

        return new AshlarOidcProfile(
            CreateDisplayName(principal, givenName, familyName),
            givenName,
            familyName,
            FindFirstTrimmedValue(principal, "email", ClaimTypes.Email),
            ParseEmailVerified(FindFirstTrimmedValue(principal, "email_verified")));
    }

    /// <summary>
    /// Gets the suggested display name from the principal, when one is available.
    /// </summary>
    /// <param name="principal">The validated OpenID Connect principal.</param>
    /// <returns>The suggested display name, or <see langword="null" /> when no conservative suggestion is available.</returns>
    public static string? GetSuggestedDisplayName(ClaimsPrincipal principal)
    {
        return Map(principal).DisplayName;
    }

    private static string? CreateDisplayName(ClaimsPrincipal principal, string? givenName, string? familyName)
    {
        var name = FindFirstTrimmedValue(principal, "name", ClaimTypes.Name);
        if (name != null)
        {
            return name;
        }

        if (givenName != null && familyName != null)
        {
            return string.Concat(givenName, " ", familyName);
        }

        return givenName ?? familyName;
    }

    private static string? FindFirstTrimmedValue(ClaimsPrincipal principal, string claimType, string? mappedClaimType = null)
    {
        foreach (var claim in principal.Claims)
        {
            if (!MatchesClaimType(claim.Type, claimType, mappedClaimType))
            {
                continue;
            }

            var value = claim.Value.Trim();
            if (value.Length > 0)
            {
                return value;
            }
        }

        return null;
    }

    private static bool MatchesClaimType(string candidateClaimType, string claimType, string? mappedClaimType)
    {
        return string.Equals(candidateClaimType, claimType, StringComparison.Ordinal)
            || (mappedClaimType != null && string.Equals(candidateClaimType, mappedClaimType, StringComparison.Ordinal));
    }

    private static bool? ParseEmailVerified(string? value)
    {
        return value switch
        {
            "true" or "True" or "1" => true,
            "false" or "False" or "0" => false,
            _ => null
        };
    }
}
