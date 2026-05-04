namespace Ashlar.Identity;

/// <summary>
/// Provides centralized normalization logic for identity-related strings.
/// </summary>
public static class IdentityNormalization
{
    /// <summary>
    /// Normalizes an email address for consistent storage and lookup.
    /// </summary>
    /// <param name="email">The email address to normalize.</param>
    /// <returns>A normalized, upper-case version of the email address.</returns>
    /// <exception cref="ArgumentException">Thrown if the email is null or whitespace.</exception>
    public static string NormalizeEmail(string email)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);
        return email.Trim().ToUpperInvariant();
    }
}
