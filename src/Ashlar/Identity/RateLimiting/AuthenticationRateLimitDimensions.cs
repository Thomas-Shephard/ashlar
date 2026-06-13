namespace Ashlar.Identity.RateLimiting;

/// <summary>
/// Builds common authentication rate-limit bucket keys and dimension names.
/// </summary>
public static class AuthenticationRateLimitDimensions
{
    private const string EmailRateLimitPrefix = "email:";
    private const string TokenRateLimitPrefix = "token:";
    private const string SourceIpRateLimitPrefix = "source:ip:";
    private const string AnonymousSourceRateLimitKey = "source:anonymous";

    /// <summary>
    /// Builds an email bucket key.
    /// </summary>
    /// <param name="normalizedEmail">The normalized email address.</param>
    /// <returns>The email bucket key.</returns>
    public static string Email(string normalizedEmail)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(normalizedEmail);
        return $"{EmailRateLimitPrefix}{normalizedEmail}";
    }

    /// <summary>
    /// Builds a token-hash bucket key.
    /// </summary>
    /// <param name="tokenHash">The already-safe token hash.</param>
    /// <returns>The token-hash bucket key.</returns>
    public static string TokenHash(string tokenHash)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenHash);
        return $"{TokenRateLimitPrefix}{tokenHash}";
    }

    /// <summary>
    /// Builds a source bucket key from the authentication context.
    /// </summary>
    /// <param name="context">Authentication context containing the client source captured by the host application.</param>
    /// <returns>The source bucket key.</returns>
    public static string Source(AuthenticationContext? context)
    {
        return string.IsNullOrWhiteSpace(context?.IpAddress)
            ? AnonymousSourceRateLimitKey
            : $"{SourceIpRateLimitPrefix}{NormalizeIpAddress(context.IpAddress)}";
    }

    /// <summary>
    /// Builds a user bucket key.
    /// </summary>
    /// <param name="userId">User identifier used to build a rate-limit bucket value.</param>
    /// <returns>The user bucket key.</returns>
    public static string User(Guid userId)
    {
        return userId.ToString("D");
    }

    /// <summary>
    /// Resolves the metric-safe dimension name for a bucket key.
    /// </summary>
    /// <param name="key">Rate-limit bucket key to classify for metrics.</param>
    /// <returns>Metric-safe dimension name derived from the bucket key.</returns>
    public static string DimensionName(string key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);

        if (key.StartsWith(EmailRateLimitPrefix, StringComparison.Ordinal))
        {
            return "email";
        }

        if (key.StartsWith(TokenRateLimitPrefix, StringComparison.Ordinal))
        {
            return "token-hash";
        }

        if (key.StartsWith(SourceIpRateLimitPrefix, StringComparison.Ordinal) || key == AnonymousSourceRateLimitKey)
        {
            return "source";
        }

        return "user";
    }

    internal static string NormalizeIpAddress(string ipAddress)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ipAddress);

        var trimmed = ipAddress.Trim();
        return System.Net.IPAddress.TryParse(trimmed, out var parsed)
            ? parsed.ToString()
            : trimmed;
    }
}
