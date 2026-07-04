using Ashlar.Webhooks.SecurityEvents;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Ashlar.Sqlite.Webhooks;

internal sealed class SqliteSecurityEventWebhookOutboxDispatcher(
    IServiceProvider serviceProvider,
    TimeProvider timeProvider,
    IOptions<SqliteSecurityEventWebhookOutboxOptions> options,
    IOptions<AshlarSecurityEventWebhookOptions> webhookOptions,
    IHttpClientFactory httpClientFactory,
    AshlarSecurityEventWebhookDestinationValidator destinationValidator,
    ILogger<SqliteSecurityEventWebhookOutboxDispatcher>? logger = null,
    IAshlarSecurityEventWebhookDeliveryObserver? deliveryObserver = null)
{
    public const string HttpClientName = "Ashlar.Sqlite.SecurityEventWebhookOutbox";

    private const string LockedByParameter = "$lockedBy";
    private const string ClaimSql = """
        UPDATE ashlar_security_event_webhook_outbox
        SET locked_until = $lockedUntil,
            locked_by = $lockedBy
        WHERE id IN (
            SELECT id
            FROM ashlar_security_event_webhook_outbox
            WHERE sent_at IS NULL
              AND failed_at IS NULL
              AND discarded_at IS NULL
              AND available_at <= $now
              AND (locked_until IS NULL OR locked_until < $now)
            ORDER BY available_at, id
            LIMIT $batchSize
        )
        """;
    private const string MarkAsSentSql = """
        UPDATE ashlar_security_event_webhook_outbox
        SET sent_at = $now,
            locked_until = NULL,
            locked_by = NULL,
            last_attempt_at = $now,
            attempt_count = attempt_count + 1
        WHERE id = $id
          AND locked_by = $lockedBy
          AND sent_at IS NULL
          AND failed_at IS NULL
          AND discarded_at IS NULL
        """;
    private const string MarkAsFailedSql = """
        UPDATE ashlar_security_event_webhook_outbox
        SET failed_at = $failedAt,
            last_error = $lastError,
            available_at = $availableAt,
            locked_until = NULL,
            locked_by = NULL,
            last_attempt_at = $now,
            attempt_count = $attemptCount
        WHERE id = $id
          AND locked_by = $lockedBy
          AND sent_at IS NULL
          AND failed_at IS NULL
          AND discarded_at IS NULL
        """;
    private readonly IServiceProvider _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    private readonly SqliteSecurityEventWebhookOutboxOptions _options = (options ?? throw new ArgumentNullException(nameof(options))).Value;
    private readonly AshlarSecurityEventWebhookOptions _webhookOptions = (webhookOptions ?? throw new ArgumentNullException(nameof(webhookOptions))).Value;
    private readonly IHttpClientFactory _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
    private readonly ILogger<SqliteSecurityEventWebhookOutboxDispatcher> _logger = logger ?? NullLogger<SqliteSecurityEventWebhookOutboxDispatcher>.Instance;
    private readonly IAshlarSecurityEventWebhookDeliveryObserver _deliveryObserver = deliveryObserver ?? NoOpAshlarSecurityEventWebhookDeliveryObserver.Instance;
    private readonly AshlarSecurityEventWebhookDestinationValidator _destinationValidator = destinationValidator ?? throw new ArgumentNullException(nameof(destinationValidator));

    public async Task<int> ProcessBatchAsync(CancellationToken cancellationToken = default)
    {
        if (!SqliteSecurityEventWebhookOutboxOptions.Validate(_options))
        {
            throw new InvalidOperationException("Security event webhook outbox options are invalid.");
        }

        var lockId = Guid.NewGuid().ToString("D");
        return await SqliteOutboxDispatch.ProcessBatchAsync(
            new SqliteOutboxProcessContext<AshlarSecurityEventWebhookOutboxEntry>(
                _serviceProvider,
                ClaimSql,
                lockId,
                _timeProvider,
                _options.LockDuration,
                _options.BatchSize,
                LoadClaimedEntriesAsync,
                (entry, provider, token) => ProcessEntryAsync(entry, provider, lockId, token)),
            cancellationToken);
    }

    private static async Task<List<AshlarSecurityEventWebhookOutboxEntry>> LoadClaimedEntriesAsync(
        IServiceProvider provider,
        string lockId,
        CancellationToken cancellationToken)
    {
        var connectionProvider = provider.GetRequiredService<ISqliteConnectionProvider>();
        await using var connectionHandle = await connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = connectionHandle.Connection.CreateCommand();
        command.Transaction = connectionHandle.Transaction;
        command.CommandText = """
            SELECT id, endpoint_name, uri, event_id, event_type, outcome, occurred_at, body, headers, timeout_ms, attempt_count
            FROM ashlar_security_event_webhook_outbox
            WHERE locked_by = $lockedBy
              AND sent_at IS NULL
              AND failed_at IS NULL
              AND discarded_at IS NULL
            ORDER BY available_at, id
            """;
        command.AddParameter(LockedByParameter, lockId);

        var entries = new List<AshlarSecurityEventWebhookOutboxEntry>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            entries.Add(new AshlarSecurityEventWebhookOutboxEntry
            {
                Id = reader.GetGuidFromText("id"),
                EndpointName = reader.GetString(reader.GetOrdinal("endpoint_name")),
                Uri = reader.GetString(reader.GetOrdinal("uri")),
                EventId = reader.GetGuidFromText("event_id"),
                EventType = reader.GetString(reader.GetOrdinal("event_type")),
                Outcome = reader.GetString(reader.GetOrdinal("outcome")),
                OccurredAt = reader.GetDateTimeOffsetFromText("occurred_at"),
                Body = (byte[])reader["body"],
                Headers = reader.GetString(reader.GetOrdinal("headers")),
                TimeoutMs = reader.GetInt64(reader.GetOrdinal("timeout_ms")),
                AttemptCount = reader.GetInt32ByName("attempt_count")
            });
        }

        return entries;
    }

    private async Task ProcessEntryAsync(AshlarSecurityEventWebhookOutboxEntry entry, IServiceProvider provider, string lockId, CancellationToken cancellationToken)
    {
        await AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(
            entry,
            new AshlarSecurityEventWebhookOutboxDispatchContext(
                _httpClientFactory,
                HttpClientName,
                _options.MaxAttempts,
                (id, token) => MarkAsSentAsync(id, provider, lockId, token),
                (failedEntry, exception, token) => MarkAsFailedAsync(failedEntry, exception, provider, lockId, token),
                (id, attemptCount, finalFailure, exception) => SqliteSecurityEventWebhookOutboxDispatcherLog.WebhookDeliveryFailed(_logger, id, attemptCount, finalFailure, exception),
                _destinationValidator,
                _webhookOptions,
                _timeProvider,
                _deliveryObserver),
            cancellationToken);
    }

    private async Task<bool> MarkAsSentAsync(Guid id, IServiceProvider provider, string lockId, CancellationToken cancellationToken)
    {
        return await SqliteOutboxDispatch.MarkAsSentAsync(
            new SqliteOutboxSentUpdateContext(provider, MarkAsSentSql, lockId, _timeProvider.GetUtcNow()),
            id,
            cancellationToken);
    }

    private async Task MarkAsFailedAsync(AshlarSecurityEventWebhookOutboxEntry entry, Exception exception, IServiceProvider provider, string lockId, CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();
        var failure = AshlarSecurityEventWebhookOutboxDispatch.CreateFailureUpdate(
            entry.AttemptCount,
            _options.MaxAttempts,
            _options.InitialRetryDelay,
            now,
            exception);

        await SqliteOutboxDispatch.MarkAsFailedAsync(
            new SqliteOutboxFailedUpdateContext(provider, MarkAsFailedSql, lockId, now),
            entry.Id,
            new SqliteOutboxFailureUpdate(failure.AttemptCount, failure.FailedAt, failure.AvailableAt, failure.LastError),
            cancellationToken);
    }
}

internal static class SqliteSecurityEventWebhookOutboxDispatcherLog
{
    public static readonly Action<ILogger, Guid, int, bool, Exception?> WebhookDeliveryFailed =
        LoggerMessage.Define<Guid, int, bool>(
            LogLevel.Warning,
            new EventId(2000, nameof(WebhookDeliveryFailed)),
            "SQLite security event webhook outbox delivery failed. DeliveryId={DeliveryId} AttemptCount={AttemptCount} FinalFailure={FinalFailure}");
}
