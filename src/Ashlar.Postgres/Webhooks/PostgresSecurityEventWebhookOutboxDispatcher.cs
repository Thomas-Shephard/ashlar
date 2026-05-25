using Ashlar.Webhooks.SecurityEvents;
using Dapper;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Ashlar.Postgres.Webhooks;

/// <summary>
/// PostgreSQL-backed dispatcher for durable security event webhook deliveries.
/// </summary>
public sealed class PostgresSecurityEventWebhookOutboxDispatcher
{
    /// <summary>
    /// Defines the named HTTP client used by the PostgreSQL webhook outbox dispatcher.
    /// </summary>
    public const string HttpClientName = "Ashlar.Postgres.SecurityEventWebhookOutbox";

    private readonly IServiceProvider _serviceProvider;
    private readonly TimeProvider _timeProvider;
    private readonly PostgresSecurityEventWebhookOutboxOptions _options;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<PostgresSecurityEventWebhookOutboxDispatcher> _logger;
    private readonly string _lockId = Guid.NewGuid().ToString();

    /// <summary>
    /// Initializes a new instance of the dispatcher class.
    /// </summary>
    /// <param name="serviceProvider">The service provider value.</param>
    /// <param name="timeProvider">The time provider value.</param>
    /// <param name="options">The options value.</param>
    /// <param name="httpClientFactory">The HTTP client factory value.</param>
    /// <param name="logger">The logger value.</param>
    public PostgresSecurityEventWebhookOutboxDispatcher(
        IServiceProvider serviceProvider,
        TimeProvider timeProvider,
        IOptions<PostgresSecurityEventWebhookOutboxOptions> options,
        IHttpClientFactory httpClientFactory,
        ILogger<PostgresSecurityEventWebhookOutboxDispatcher>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(serviceProvider);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(httpClientFactory);

        _serviceProvider = serviceProvider;
        _timeProvider = timeProvider;
        _options = options.Value;
        _httpClientFactory = httpClientFactory;
        _logger = logger ?? NullLogger<PostgresSecurityEventWebhookOutboxDispatcher>.Instance;
    }

    /// <summary>
    /// Processes a single batch of pending webhook deliveries.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The number of claimed deliveries.</returns>
    public async Task<int> ProcessBatchAsync(CancellationToken cancellationToken = default)
    {
        if (!PostgresSecurityEventWebhookOutboxOptions.Validate(_options))
        {
            throw new InvalidOperationException("Security event webhook outbox options are invalid.");
        }

        const string claimSql = """
            UPDATE ashlar_security_event_webhook_outbox
            SET locked_until = @LockedUntil,
                locked_by = @LockedBy
            WHERE id IN (
                SELECT id
                FROM ashlar_security_event_webhook_outbox
                WHERE sent_at IS NULL
                  AND failed_at IS NULL
                  AND available_at <= @Now
                  AND (locked_until IS NULL OR locked_until < @Now)
                ORDER BY available_at, id
                LIMIT @BatchSize
                FOR UPDATE SKIP LOCKED
            )
            RETURNING id AS Id, uri AS Uri, body AS Body, headers::text AS Headers,
                      timeout_ms AS TimeoutMs, attempt_count AS AttemptCount
            """;

        var now = _timeProvider.GetUtcNow();
        var lockedUntil = now.Add(_options.LockDuration);

        List<AshlarSecurityEventWebhookOutboxEntry> entries;
        await using (var scope = _serviceProvider.CreateAsyncScope())
        {
            var connectionProvider = scope.ServiceProvider.GetRequiredService<IPostgresConnectionProvider>();
            var connectionHandle = await connectionProvider.GetConnectionAsync(cancellationToken).ConfigureAwait(false);
            await using (connectionHandle)
            {
                var command = new CommandDefinition(claimSql, new
                {
                    Now = now,
                    LockedUntil = lockedUntil,
                    LockedBy = _lockId,
                    _options.BatchSize
                }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);

                entries = (await connectionHandle.Connection.QueryAsync<AshlarSecurityEventWebhookOutboxEntry>(command).ConfigureAwait(false)).ToList();
            }
        }

        foreach (var entry in entries)
        {
            await using var entryScope = _serviceProvider.CreateAsyncScope();
            await ProcessEntryAsync(entry, entryScope.ServiceProvider, cancellationToken).ConfigureAwait(false);
        }

        return entries.Count;
    }

    private async Task ProcessEntryAsync(AshlarSecurityEventWebhookOutboxEntry entry, IServiceProvider provider, CancellationToken cancellationToken)
    {
        await AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(
            entry,
            _httpClientFactory,
            HttpClientName,
            _options.MaxAttempts,
            (id, token) => MarkAsSentAsync(id, provider, token),
            (failedEntry, exception, token) => MarkAsFailedAsync(failedEntry, exception, provider, token),
            (id, attemptCount, finalFailure, exception) => PostgresSecurityEventWebhookOutboxDispatcherLog.WebhookDeliveryFailed(_logger, id, attemptCount, finalFailure, exception),
            cancellationToken).ConfigureAwait(false);
    }

    private async Task MarkAsSentAsync(Guid id, IServiceProvider provider, CancellationToken cancellationToken)
    {
        const string sql = """
            UPDATE ashlar_security_event_webhook_outbox
            SET sent_at = @Now,
                locked_until = NULL,
                locked_by = NULL,
                last_attempt_at = @Now,
                attempt_count = attempt_count + 1
            WHERE id = @Id AND locked_by = @LockedBy
            """;

        var now = _timeProvider.GetUtcNow();
        var connectionProvider = provider.GetRequiredService<IPostgresConnectionProvider>();
        var connectionHandle = await connectionProvider.GetConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new { Id = id, LockedBy = _lockId, Now = now }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            await connectionHandle.Connection.ExecuteAsync(command).ConfigureAwait(false);
        }
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

        const string sql = """
            UPDATE ashlar_security_event_webhook_outbox
            SET failed_at = @FailedAt,
                last_error = @LastError,
                available_at = @AvailableAt,
                locked_until = NULL,
                locked_by = NULL,
                last_attempt_at = @Now,
                attempt_count = @AttemptCount
            WHERE id = @Id AND locked_by = @LockedBy
            """;

        var connectionProvider = provider.GetRequiredService<IPostgresConnectionProvider>();
        var connectionHandle = await connectionProvider.GetConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new
            {
                entry.Id,
                LockedBy = _lockId,
                failure.FailedAt,
                failure.LastError,
                failure.AvailableAt,
                Now = now,
                failure.AttemptCount
            }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);

            await connectionHandle.Connection.ExecuteAsync(command).ConfigureAwait(false);
        }
    }
}

internal static class PostgresSecurityEventWebhookOutboxDispatcherLog
{
    public static readonly Action<ILogger, Guid, int, bool, Exception?> WebhookDeliveryFailed =
        LoggerMessage.Define<Guid, int, bool>(
            LogLevel.Warning,
            new EventId(2000, nameof(WebhookDeliveryFailed)),
            "Security event webhook outbox delivery failed. DeliveryId={DeliveryId} AttemptCount={AttemptCount} FinalFailure={FinalFailure}");
}
