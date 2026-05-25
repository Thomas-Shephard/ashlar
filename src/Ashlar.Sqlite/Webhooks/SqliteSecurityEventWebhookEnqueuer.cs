using Ashlar.Webhooks.SecurityEvents;
using System.Text.Json;

namespace Ashlar.Sqlite.Webhooks;

/// <summary>
/// SQLite-backed durable enqueuer for prepared security event webhook deliveries.
/// </summary>
/// <param name="connectionProvider">The connection provider value.</param>
/// <param name="timeProvider">The time provider value.</param>
public sealed class SqliteSecurityEventWebhookEnqueuer(
    ISqliteConnectionProvider connectionProvider,
    TimeProvider timeProvider) : IAshlarSecurityEventWebhookEnqueuer
{
    private readonly ISqliteConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

    /// <summary>
    /// Stores a prepared webhook delivery in the SQLite outbox.
    /// </summary>
    /// <param name="delivery">The prepared webhook delivery.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>A task that represents the asynchronous enqueue operation.</returns>
    public async Task EnqueueAsync(AshlarSecurityEventWebhookDelivery delivery, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(delivery);

        var now = _timeProvider.GetUtcNow();
        await using var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = connectionHandle.Connection.CreateCommand();
        command.Transaction = connectionHandle.Transaction;
        command.CommandText = """
            INSERT INTO ashlar_security_event_webhook_outbox (
                id, endpoint_name, uri, event_id, event_type, occurred_at, timeout_ms, body, headers, created_at, available_at
            ) VALUES (
                $id, $endpointName, $uri, $eventId, $eventType, $occurredAt, $timeoutMs, $body, $headers, $createdAt, $availableAt
            )
            """;
        command.AddGuidParameter("$id", Guid.NewGuid());
        command.AddParameter("$endpointName", delivery.EndpointName);
        command.AddParameter("$uri", delivery.Uri.ToString());
        command.AddGuidParameter("$eventId", delivery.Payload.Id);
        command.AddParameter("$eventType", delivery.Payload.EventType);
        command.AddDateTimeOffsetParameter("$occurredAt", delivery.Payload.OccurredAt);
        command.AddParameter("$timeoutMs", checked((long)delivery.Timeout.TotalMilliseconds));
        command.AddParameter("$body", delivery.Body.ToArray());
        command.AddParameter("$headers", JsonSerializer.Serialize(delivery.Headers));
        command.AddDateTimeOffsetParameter("$createdAt", now);
        command.AddDateTimeOffsetParameter("$availableAt", now);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
