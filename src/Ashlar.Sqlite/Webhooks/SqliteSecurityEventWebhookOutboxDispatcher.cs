using Ashlar.Webhooks.SecurityEvents;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Ashlar.Sqlite.Webhooks;

/// <summary>
/// SQLite-backed dispatcher for durable security event webhook deliveries.
/// </summary>
public sealed class SqliteSecurityEventWebhookOutboxDispatcher
{
    /// <summary>
    /// Defines the named HTTP client used by the SQLite webhook outbox dispatcher.
    /// </summary>
    public const string HttpClientName = "Ashlar.Sqlite.SecurityEventWebhookOutbox";

    private const string IdParameter = "$id";
    private const string LockedByParameter = "$lockedBy";
    private const string NowParameter = "$now";
    private const string AttemptCountParameter = "$attemptCount";
    private readonly IServiceProvider _serviceProvider;
    private readonly TimeProvider _timeProvider;
    private readonly SqliteSecurityEventWebhookOutboxOptions _options;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<SqliteSecurityEventWebhookOutboxDispatcher> _logger;
    private readonly string _lockId = Guid.NewGuid().ToString("D");

    /// <summary>
    /// Initializes a new instance of the dispatcher class.
    /// </summary>
    /// <param name="serviceProvider">The service provider value.</param>
    /// <param name="timeProvider">The time provider value.</param>
    /// <param name="options">The options value.</param>
    /// <param name="httpClientFactory">The HTTP client factory value.</param>
    /// <param name="logger">The logger value.</param>
    public SqliteSecurityEventWebhookOutboxDispatcher(
        IServiceProvider serviceProvider,
        TimeProvider timeProvider,
        IOptions<SqliteSecurityEventWebhookOutboxOptions> options,
        IHttpClientFactory httpClientFactory,
        ILogger<SqliteSecurityEventWebhookOutboxDispatcher>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(serviceProvider);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(httpClientFactory);

        _serviceProvider = serviceProvider;
        _timeProvider = timeProvider;
        _options = options.Value;
        _httpClientFactory = httpClientFactory;
        _logger = logger ?? NullLogger<SqliteSecurityEventWebhookOutboxDispatcher>.Instance;
    }

    /// <summary>
    /// Processes a single batch of pending webhook deliveries.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The number of claimed deliveries.</returns>
    public async Task<int> ProcessBatchAsync(CancellationToken cancellationToken = default)
    {
        if (!SqliteSecurityEventWebhookOutboxOptions.Validate(_options))
        {
            throw new InvalidOperationException("Security event webhook outbox options are invalid.");
        }

        var now = _timeProvider.GetUtcNow();
        var lockedUntil = now.Add(_options.LockDuration);

        await using var scope = _serviceProvider.CreateAsyncScope();
        var connectionProvider = scope.ServiceProvider.GetRequiredService<ISqliteConnectionProvider>();
        await using (var connectionHandle = await connectionProvider.GetConnectionAsync(cancellationToken))
        {
            await using var command = connectionHandle.Connection.CreateCommand();
            command.Transaction = connectionHandle.Transaction;
            command.CommandText = """
                UPDATE ashlar_security_event_webhook_outbox
                SET locked_until = $lockedUntil,
                    locked_by = $lockedBy
                WHERE id IN (
                    SELECT id
                    FROM ashlar_security_event_webhook_outbox
                    WHERE sent_at IS NULL
                      AND failed_at IS NULL
                      AND available_at <= $now
                      AND (locked_until IS NULL OR locked_until < $now)
                    ORDER BY available_at, id
                    LIMIT $batchSize
                )
                """;
            command.AddDateTimeOffsetParameter("$lockedUntil", lockedUntil);
            command.AddParameter(LockedByParameter, _lockId);
            command.AddDateTimeOffsetParameter(NowParameter, now);
            command.AddParameter("$batchSize", _options.BatchSize);

            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        var entries = await LoadClaimedEntriesAsync(scope.ServiceProvider, _lockId, cancellationToken);
        if (entries.Count == 0)
        {
            return 0;
        }

        foreach (var entry in entries)
        {
            await using var entryScope = _serviceProvider.CreateAsyncScope();
            await ProcessEntryAsync(entry, entryScope.ServiceProvider, cancellationToken);
        }

        return entries.Count;
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
            SELECT id, uri, body, headers, timeout_ms, attempt_count
            FROM ashlar_security_event_webhook_outbox
            WHERE locked_by = $lockedBy
              AND sent_at IS NULL
              AND failed_at IS NULL
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
                Uri = reader.GetString(reader.GetOrdinal("uri")),
                Body = (byte[])reader["body"],
                Headers = reader.GetString(reader.GetOrdinal("headers")),
                TimeoutMs = reader.GetInt64(reader.GetOrdinal("timeout_ms")),
                AttemptCount = reader.GetInt32ByName("attempt_count")
            });
        }

        return entries;
    }

    private async Task ProcessEntryAsync(AshlarSecurityEventWebhookOutboxEntry entry, IServiceProvider provider, CancellationToken cancellationToken)
    {
        try
        {
            using var request = AshlarSecurityEventWebhookOutboxDispatch.MapToHttpRequest(entry);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromMilliseconds(entry.TimeoutMs));
            var client = _httpClientFactory.CreateClient(HttpClientName);
            using var response = await client.SendAsync(request, timeout.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException($"Webhook endpoint returned HTTP {(int)response.StatusCode}.");
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            var attemptCount = entry.AttemptCount + 1;
            SqliteSecurityEventWebhookOutboxDispatcherLog.WebhookDeliveryFailed(_logger, entry.Id, attemptCount, attemptCount >= _options.MaxAttempts, exception);
            await MarkAsFailedAsync(entry, exception, provider, CancellationToken.None);
            return;
        }

        await MarkAsSentAsync(entry.Id, provider, CancellationToken.None);
    }

    private async Task MarkAsSentAsync(Guid id, IServiceProvider provider, CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();
        var connectionProvider = provider.GetRequiredService<ISqliteConnectionProvider>();
        await using var connectionHandle = await connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = connectionHandle.Connection.CreateCommand();
        command.Transaction = connectionHandle.Transaction;
        command.CommandText = """
            UPDATE ashlar_security_event_webhook_outbox
            SET sent_at = $now,
                locked_until = NULL,
                locked_by = NULL,
                last_attempt_at = $now,
                attempt_count = attempt_count + 1
            WHERE id = $id AND locked_by = $lockedBy
            """;
        command.AddDateTimeOffsetParameter(NowParameter, now);
        command.AddGuidParameter(IdParameter, id);
        command.AddParameter(LockedByParameter, _lockId);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private async Task MarkAsFailedAsync(AshlarSecurityEventWebhookOutboxEntry entry, Exception exception, IServiceProvider provider, CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();
        var failure = AshlarSecurityEventWebhookOutboxDispatch.CreateFailureUpdate(
            entry.AttemptCount,
            _options.MaxAttempts,
            _options.InitialRetryDelay,
            now,
            exception);

        var connectionProvider = provider.GetRequiredService<ISqliteConnectionProvider>();
        await using var connectionHandle = await connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = connectionHandle.Connection.CreateCommand();
        command.Transaction = connectionHandle.Transaction;
        command.CommandText = """
            UPDATE ashlar_security_event_webhook_outbox
            SET failed_at = $failedAt,
                last_error = $lastError,
                available_at = $availableAt,
                locked_until = NULL,
                locked_by = NULL,
                last_attempt_at = $now,
                attempt_count = $attemptCount
            WHERE id = $id AND locked_by = $lockedBy
            """;
        command.AddNullableDateTimeOffsetParameter("$failedAt", failure.FailedAt);
        command.AddParameter("$lastError", failure.LastError);
        command.AddDateTimeOffsetParameter("$availableAt", failure.AvailableAt);
        command.AddDateTimeOffsetParameter(NowParameter, now);
        command.AddParameter(AttemptCountParameter, failure.AttemptCount);
        command.AddGuidParameter(IdParameter, entry.Id);
        command.AddParameter(LockedByParameter, _lockId);

        await command.ExecuteNonQueryAsync(cancellationToken);
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
