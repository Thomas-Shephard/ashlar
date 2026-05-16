namespace Ashlar.Identity;

/// <summary>
/// Provides centralized normalization logic for identity-related strings.
/// </summary>
public static class IdentityNormalization
{
    /// <summary>
    /// Normalizes an email address for consistent storage and lookup.
    /// </summary>
    /// <param name="email">The email value.</param>
    /// <returns>The operation result.</returns>
    /// <exception cref="ArgumentException">Thrown if the email is <see langword="null" /> or whitespace.</exception>
    public static string NormalizeEmail(string email)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);
        return email.Trim().ToUpperInvariant();
    }

    /// <summary>
    /// Trims an email address and rejects values that could escape email headers.
    /// </summary>
    /// <param name="email">The email value.</param>
    /// <returns>The operation result.</returns>
    /// <exception cref="ArgumentException">Thrown if the email is <see langword="null" />, whitespace, or contains line breaks.</exception>
    public static string SanitizeEmailForDelivery(string email)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);

        if (email.Contains('\r') || email.Contains('\n'))
        {
            throw new ArgumentException("Email address cannot contain line breaks.", nameof(email));
        }

        var sanitized = email.Trim();
        _ = NormalizeEmail(sanitized);
        return sanitized;
    }
}
