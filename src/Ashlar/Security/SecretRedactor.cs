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
    /// <param name="exception">The exception to check.</param>
    /// <param name="secret">The secret to look for.</param>
    /// <returns>True if the secret is found and is of sufficient length; otherwise, false.</returns>
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
    /// <param name="exception">The exception to redact.</param>
    /// <param name="secrets">The secrets to redact.</param>
    /// <returns>A string representation of the exception with secrets redacted.</returns>
    public static string Redact(Exception exception, params string?[] secrets)
    {
        ArgumentNullException.ThrowIfNull(exception);
        return Redact(exception.ToString(), secrets);
    }

    /// <summary>
    /// Redacts secrets from a string.
    /// </summary>
    /// <param name="value">The string to redact.</param>
    /// <param name="secrets">The secrets to redact.</param>
    /// <returns>The string with secrets redacted.</returns>
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
