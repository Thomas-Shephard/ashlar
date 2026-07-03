namespace Ashlar.Redis.RateLimiting;

/// <summary>
/// Options for the Redis-backed authentication rate limiter.
/// </summary>
public sealed class RedisAuthenticationRateLimiterOptions
{
    internal const string SharedDefaultKeyPrefix = "ashlar:rate-limits";

    /// <summary>
    /// The Redis database number. Defaults to the connection multiplexer default database.
    /// </summary>
    public int? Database { get; set; }

    /// <summary>
    /// Application-specific namespace prefix used for Ashlar rate-limit keys.
    /// </summary>
    /// <remarks>
    /// This value is required and must identify the owning application, for example
    /// <c>my-app:ashlar:rate-limits</c>. Allowed characters are ASCII letters, digits,
    /// colon, period, underscore, and hyphen. Trailing colons are ignored when Redis keys
    /// are built. Do not use the shared package prefix <c>ashlar:rate-limits</c>.
    /// </remarks>
    public string KeyPrefix { get; set; } = string.Empty;

    /// <summary>
    /// Extra time added to each Redis key TTL to tolerate small clock and network delays.
    /// </summary>
    public TimeSpan ExpirationSkew { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Whether Redis persistence should be reported as enabled by diagnostics.
    /// </summary>
    public bool Persistent { get; set; }

    internal static bool Validate(RedisAuthenticationRateLimiterOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (string.IsNullOrWhiteSpace(options.KeyPrefix))
        {
            return false;
        }

        var normalizedPrefix = RedisRateLimitKeyBuilder.NormalizePrefix(options.KeyPrefix);
        if (normalizedPrefix.Length == 0)
        {
            return false;
        }

        if (options.KeyPrefix.Any(static character => !IsValidPrefixCharacter(character)))
        {
            return false;
        }

        if (string.Equals(normalizedPrefix, SharedDefaultKeyPrefix, StringComparison.Ordinal))
        {
            return false;
        }

        if (options.Database < 0)
        {
            return false;
        }

        if (options.ExpirationSkew < TimeSpan.Zero)
        {
            return false;
        }

        return true;
    }

    private static bool IsValidPrefixCharacter(char character)
    {
        return char.IsAsciiLetterOrDigit(character)
            || character is ':' or '.' or '_' or '-';
    }
}
