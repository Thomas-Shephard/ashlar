namespace Ashlar.AspNetCore.Diagnostics;

/// <summary>
/// Defines stable Ashlar health check registration names.
/// </summary>
public static class AshlarHealthCheckNames
{
    /// <summary>
    /// The Ashlar schema health check name.
    /// </summary>
    public const string Schema = "ashlar_schema";

    /// <summary>
    /// The Ashlar email outbox health check name.
    /// </summary>
    public const string EmailOutbox = "ashlar_email_outbox";

    /// <summary>
    /// The Ashlar security event webhook outbox health check name.
    /// </summary>
    public const string SecurityEventWebhookOutbox = "ashlar_security_event_webhook_outbox";

    /// <summary>
    /// The Ashlar cleanup health check name.
    /// </summary>
    public const string Cleanup = "ashlar_cleanup";

    /// <summary>
    /// The Ashlar rate limiter health check name.
    /// </summary>
    public const string RateLimiter = "ashlar_rate_limiter";
}
