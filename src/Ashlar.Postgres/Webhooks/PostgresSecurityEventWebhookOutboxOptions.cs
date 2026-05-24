namespace Ashlar.Postgres.Webhooks;

/// <summary>
/// Options for the PostgreSQL-backed security event webhook outbox.
/// </summary>
public sealed record PostgresSecurityEventWebhookOutboxOptions
{
    /// <summary>
    /// Gets or sets the duration for which a webhook delivery is locked for dispatch.
    /// Default is 5 minutes.
    /// </summary>
    public TimeSpan LockDuration { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets or sets the maximum number of attempts to send a webhook delivery.
    /// Default is 5.
    /// </summary>
    public int MaxAttempts { get; set; } = 5;

    /// <summary>
    /// Gets or sets the initial delay before retrying a failed send operation.
    /// Default is 30 seconds.
    /// </summary>
    public TimeSpan InitialRetryDelay { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Gets or sets the maximum number of webhook deliveries to process in a single batch.
    /// Default is 50.
    /// </summary>
    public int BatchSize { get; set; } = 50;

    /// <summary>
    /// Gets or sets the interval at which the background dispatcher polls for pending deliveries.
    /// Default is 10 seconds.
    /// </summary>
    public TimeSpan PollingInterval { get; set; } = TimeSpan.FromSeconds(10);

    internal static bool Validate(PostgresSecurityEventWebhookOutboxOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return options.LockDuration > TimeSpan.Zero
            && options.MaxAttempts > 0
            && options.InitialRetryDelay > TimeSpan.Zero
            && options.BatchSize > 0
            && options.PollingInterval > TimeSpan.Zero;
    }
}
