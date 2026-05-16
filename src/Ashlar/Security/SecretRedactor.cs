namespace Ashlar.Security;

/// <summary>
/// Utility for redacting sensitive information from strings and exceptions.
/// </summary>
public static class SecretRedactor
{
    /// <summary>
    /// The placeholder used for redacted content.
    /// </summary>
    public const string RedactedPlaceholder = "***REDACTED***";

    /// <summary>
    /// Checks if a secret is present in the provided exception's message or stack trace.
    /// </summary>
    /// <param name="exception">The exception value.</param>
    /// <param name="secret">The secret value.</param>
    /// <returns>The operation result.</returns>
    public static bool ContainsSecret(Exception? exception, string? secret)
    {
        if (exception == null || string.IsNullOrEmpty(secret))
        {
            return false;
        }

        return exception.ToString().Contains(secret, StringComparison.Ordinal);
    }

    /// <summary>
    /// Redacts secrets from the string representation of an exception.
    /// </summary>
    /// <param name="exception">The exception value.</param>
    /// <param name="secrets">The secrets value.</param>
    /// <returns>The operation result.</returns>
    public static string Redact(Exception exception, params string?[] secrets)
    {
        ArgumentNullException.ThrowIfNull(exception);
        return Redact(exception.ToString(), secrets);
    }

    /// <summary>
    /// Redacts secrets from a string.
    /// </summary>
    /// <param name="value">The contained result value.</param>
    /// <param name="secrets">The secrets value.</param>
    /// <returns>The operation result.</returns>
    public static string Redact(string? value, params string?[] secrets)
    {
        if (string.IsNullOrEmpty(value) || secrets.Length == 0)
        {
            return value ?? string.Empty;
        }

        var result = value;
        foreach (var secret in secrets)
        {
            if (string.IsNullOrEmpty(secret))
            {
                continue;
            }

            result = result.Replace(secret, RedactedPlaceholder, StringComparison.Ordinal);
        }

        return result;
    }
}
