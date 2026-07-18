using Ashlar.Webhooks.SecurityEvents;
using Dapper;
using System.Text.Json;

namespace Ashlar.Postgres.Webhooks;

internal sealed class PostgresSecurityEventWebhookEnqueuer : IAshlarSecurityEventWebhookEnqueuer, IDurableSecurityEventFanOutHandler
{
    private readonly IPostgresConnectionProvider _connectionProvider;
    private readonly TimeProvider _timeProvider;
    private readonly AshlarSecurityEventWebhookOutboxHandler _handler;

    public PostgresSecurityEventWebhookEnqueuer(
        IPostgresConnectionProvider connectionProvider,
        TimeProvider timeProvider,
        AshlarSecurityEventWebhookDeliveryFactory deliveryFactory)
    {
        _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _handler = new AshlarSecurityEventWebhookOutboxHandler(deliveryFactory, this);
    }

    public Task HandleAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default) =>
        _handler.HandleAsync(securityEvent, cancellationToken);

    public async Task EnqueueAsync(AshlarSecurityEventWebhookDelivery delivery, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(delivery);

        const string sql = """
            INSERT INTO ashlar_security_event_webhook_outbox (
                id, endpoint_name, uri, event_id, event_type, outcome, occurred_at, timeout_ms, body, headers, created_at, available_at
            ) VALUES (
                @Id, @EndpointName, @Uri, @EventId, @EventType, @Outcome, @OccurredAt, @TimeoutMs, @Body, @Headers::jsonb, @CreatedAt, @AvailableAt
            )
            """;

        var now = _timeProvider.GetUtcNow();
        var headers = JsonSerializer.Serialize(delivery.Headers);
        var parameters = new
        {
            Id = Guid.NewGuid(),
            delivery.EndpointName,
            Uri = delivery.Uri.ToString(),
            EventId = delivery.Payload.Id,
            delivery.Payload.EventType,
            delivery.Payload.Outcome,
            delivery.Payload.OccurredAt,
            TimeoutMs = checked((long)delivery.Timeout.TotalMilliseconds),
            Body = delivery.Body.ToArray(),
            Headers = headers,
            CreatedAt = now,
            AvailableAt = now
        };

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, parameters, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            await connectionHandle.Connection.ExecuteAsync(command).ConfigureAwait(false);
        }
    }
}
