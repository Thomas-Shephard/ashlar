namespace Ashlar.Postgres.RateLimiting;

/// <summary>
/// Options for the PostgreSQL-backed authentication rate limiter.
/// </summary>
public sealed class PostgresAuthenticationRateLimiterOptions
{
    /// <summary>
    /// The interval at which expired rate limit entries are cleaned up.
    /// Defaults to 5 minutes.
    /// </summary>
    public TimeSpan CleanupInterval { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// The maximum number of rows to clean up in a single pass.
    /// Defaults to 1000.
    /// </summary>
    public int MaxCleanupRows { get; set; } = 1000;
}
