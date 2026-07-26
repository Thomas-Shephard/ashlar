using Ashlar.Webhooks.SecurityEvents;
using Dapper;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Ashlar.Postgres.Webhooks;

internal sealed class PostgresSecurityEventWebhookOutboxDispatcher(
    IServiceProvider serviceProvider,
    TimeProvider timeProvider,
    IOptions<PostgresSecurityEventWebhookOutboxOptions> options,
    IOptions<AshlarSecurityEventWebhookOptions> webhookOptions,
    AshlarSecurityEventWebhookTransport transport,
    AshlarSecurityEventWebhookDestinationValidator destinationValidator)
{
    private readonly IServiceProvider _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    private readonly PostgresSecurityEventWebhookOutboxOptions _options = (options ?? throw new ArgumentNullException(nameof(options))).Value;
    private readonly AshlarSecurityEventWebhookOptions _webhookOptions = (webhookOptions ?? throw new ArgumentNullException(nameof(webhookOptions))).Value;
    private readonly AshlarSecurityEventWebhookTransport _transport = transport ?? throw new ArgumentNullException(nameof(transport));
    private readonly ILogger<PostgresSecurityEventWebhookOutboxDispatcher> _logger = serviceProvider.GetService<ILogger<PostgresSecurityEventWebhookOutboxDispatcher>>() ?? NullLogger<PostgresSecurityEventWebhookOutboxDispatcher>.Instance;
    private readonly IAshlarSecurityEventWebhookDeliveryObserver _deliveryObserver = serviceProvider.GetService<IAshlarSecurityEventWebhookDeliveryObserver>() ?? NoOpAshlarSecurityEventWebhookDeliveryObserver.Instance;
    private readonly AshlarSecurityEventWebhookDestinationValidator _destinationValidator = destinationValidator ?? throw new ArgumentNullException(nameof(destinationValidator));

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
                  AND discarded_at IS NULL
                  AND available_at <= @Now
                  AND (locked_until IS NULL OR locked_until <= @Now)
                ORDER BY available_at, id
                LIMIT @BatchSize
                FOR UPDATE SKIP LOCKED
            )
            RETURNING id AS Id, endpoint_name AS EndpointName, uri AS Uri, event_id AS EventId,
                      event_type AS EventType, outcome AS Outcome, occurred_at AS OccurredAt, body AS Body, headers::text AS Headers,
                      timeout_ms AS TimeoutMs, attempt_count AS AttemptCount
            """;

        var now = _timeProvider.GetUtcNow();
        var lockedUntil = now.Add(_options.LockDuration);
        var lockId = Guid.NewGuid().ToString();

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
                    LockedBy = lockId,
                    _options.BatchSize
                }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);

                entries = (await connectionHandle.Connection.QueryAsync<AshlarSecurityEventWebhookOutboxEntry>(command).ConfigureAwait(false)).ToList();
            }
        }

        foreach (var entry in entries)
        {
            await using var entryScope = _serviceProvider.CreateAsyncScope();
            await ProcessEntryAsync(entry, lockId, entryScope.ServiceProvider, cancellationToken).ConfigureAwait(false);
        }

        return entries.Count;
    }

    private async Task ProcessEntryAsync(AshlarSecurityEventWebhookOutboxEntry entry, string lockId, IServiceProvider provider, CancellationToken cancellationToken)
    {
        await AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(
            entry,
            new AshlarSecurityEventWebhookOutboxDispatchContext(
                _transport,
                _options.MaxAttempts,
                (id, token) => MarkAsSentAsync(id, lockId, provider, token),
                (failedEntry, exception, token) => MarkAsFailedAsync(failedEntry, exception, lockId, provider, token),
                (id, attemptCount, finalFailure, exception) => PostgresSecurityEventWebhookOutboxDispatcherLog.WebhookDeliveryFailed(_logger, id, attemptCount, finalFailure, exception),
                _destinationValidator,
                _webhookOptions,
                _timeProvider,
                _deliveryObserver,
                (id, token) => RenewLockAsync(id, lockId, TimeSpan.FromMilliseconds(entry.TimeoutMs), provider, token)),
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<bool> RenewLockAsync(Guid id, string lockId, TimeSpan sendTimeout, IServiceProvider provider, CancellationToken cancellationToken)
    {
        const string sql = """
            UPDATE ashlar_security_event_webhook_outbox
            SET locked_until = @LockedUntil
            WHERE id = @Id
              AND locked_by = @LockedBy
              AND locked_until > @Now
              AND sent_at IS NULL
              AND failed_at IS NULL
              AND discarded_at IS NULL
            """;
        var now = _timeProvider.GetUtcNow();
        var connectionProvider = provider.GetRequiredService<IPostgresConnectionProvider>();
        await using var connectionHandle = await connectionProvider.GetConnectionAsync(cancellationToken).ConfigureAwait(false);
        var command = new CommandDefinition(sql, new { Id = id, LockedBy = lockId, Now = now, LockedUntil = now.Add(sendTimeout).Add(_options.LockDuration) }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
        return await connectionHandle.Connection.ExecuteAsync(command).ConfigureAwait(false) > 0;
    }

    private async Task<bool> MarkAsSentAsync(Guid id, string lockId, IServiceProvider provider, CancellationToken cancellationToken)
    {
        const string sql = """
            UPDATE ashlar_security_event_webhook_outbox
            SET sent_at = @Now,
                locked_until = NULL,
                locked_by = NULL,
                last_attempt_at = @Now,
                attempt_count = attempt_count + 1
            WHERE id = @Id
              AND locked_by = @LockedBy
              AND sent_at IS NULL
              AND failed_at IS NULL
              AND discarded_at IS NULL
            """;

        var now = _timeProvider.GetUtcNow();
        var connectionProvider = provider.GetRequiredService<IPostgresConnectionProvider>();
        var connectionHandle = await connectionProvider.GetConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new { Id = id, LockedBy = lockId, Now = now }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            return await connectionHandle.Connection.ExecuteAsync(command).ConfigureAwait(false) > 0;
        }
    }

    private async Task MarkAsFailedAsync(AshlarSecurityEventWebhookOutboxEntry entry, Exception exception, string lockId, IServiceProvider provider, CancellationToken cancellationToken)
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
            WHERE id = @Id
              AND locked_by = @LockedBy
              AND sent_at IS NULL
              AND failed_at IS NULL
              AND discarded_at IS NULL
            """;

        var connectionProvider = provider.GetRequiredService<IPostgresConnectionProvider>();
        var connectionHandle = await connectionProvider.GetConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new
            {
                entry.Id,
                LockedBy = lockId,
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
