namespace Ashlar.Identity.Features.Infrastructure;

/// <summary>
/// Provides centralized normalization logic for identity-related strings.
/// </summary>
public static class IdentityNormalization
{
    /// <summary>
    /// Normalizes an email address for lookup keys, uniqueness checks, rate-limit buckets, and security comparisons.
    /// </summary>
    /// <param name="email">Email address to normalize.</param>
    /// <returns>The normalized lookup form of the email address.</returns>
    /// <exception cref="ArgumentException">Thrown if the email is <see langword="null" /> or whitespace.</exception>
    public static string NormalizeEmail(string email)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);
        return email.Trim().ToUpperInvariant();
    }

    /// <summary>
    /// Trims an email address for display/delivery while preserving user-provided casing, and rejects values that could escape email headers.
    /// </summary>
    /// <param name="email">Email address to prepare for outbound delivery.</param>
    /// <returns>The sanitized display/delivery email address.</returns>
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
