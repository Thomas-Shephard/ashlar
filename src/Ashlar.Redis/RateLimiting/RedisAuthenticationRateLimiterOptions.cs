namespace Ashlar.Redis.RateLimiting;

/// <summary>
/// Options for the Redis-backed authentication rate limiter.
/// </summary>
public sealed class RedisAuthenticationRateLimiterOptions
{
    /// <summary>
    /// The Redis database number. Defaults to the connection multiplexer default database.
    /// </summary>
    public int? Database { get; set; }

    /// <summary>
    /// Namespace prefix used for Ashlar rate-limit keys.
    /// </summary>
    public string KeyPrefix { get; set; } = "ashlar:rate-limits";

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

        if (options.KeyPrefix.Any(char.IsWhiteSpace))
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
}
