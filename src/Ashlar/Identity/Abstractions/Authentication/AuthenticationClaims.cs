namespace Ashlar.Identity.Abstractions.Authentication;

/// <summary>
/// Provides helpers for authentication provider claims.
/// </summary>
public static class AuthenticationClaims
{
    /// <summary>
    /// Creates multi-value authentication claims from single-value claim entries.
    /// </summary>
    /// <param name="claims">The single-value claims.</param>
    /// <returns>The multi-value claims.</returns>
    public static IReadOnlyDictionary<string, IReadOnlyList<string>> FromSingleValues(IDictionary<string, string>? claims)
    {
        if (claims == null)
        {
            return new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal).AsReadOnly();
        }

        return claims.ToDictionary(
            claim => claim.Key,
            claim => (IReadOnlyList<string>)[claim.Value],
            StringComparer.Ordinal).AsReadOnly();
    }

    /// <summary>
    /// Creates a read-only copy of multi-value authentication claims.
    /// </summary>
    /// <param name="claims">The multi-value claims.</param>
    /// <returns>The read-only multi-value claims.</returns>
    public static IReadOnlyDictionary<string, IReadOnlyList<string>> Copy(IReadOnlyDictionary<string, IReadOnlyList<string>>? claims)
    {
        if (claims == null)
        {
            return new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal).AsReadOnly();
        }

        return claims.ToDictionary(
            claim => claim.Key,
            claim => (IReadOnlyList<string>)claim.Value.ToArray(),
            StringComparer.Ordinal).AsReadOnly();
    }

    /// <summary>
    /// Gets the first claim entry, or <see langword="null" /> when the claim is missing or empty.
    /// </summary>
    /// <param name="claims">The claims.</param>
    /// <param name="claimType">Claim key to read from the provider claims collection.</param>
    /// <returns>The first claim entry, or <see langword="null" />.</returns>
    public static string? FirstValueOrDefault(IReadOnlyDictionary<string, IReadOnlyList<string>>? claims, string claimType)
    {
        return claims != null &&
            claims.TryGetValue(claimType, out var values) &&
            values.Count > 0
            ? values[0]
            : null;
    }
}
