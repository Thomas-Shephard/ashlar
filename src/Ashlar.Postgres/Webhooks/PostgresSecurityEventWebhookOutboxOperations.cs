using Ashlar.Webhooks.SecurityEvents;

namespace Ashlar.Postgres.Webhooks;

internal sealed class PostgresSecurityEventWebhookOutboxOperations(
    IPostgresConnectionProvider connectionProvider,
    TimeProvider timeProvider,
    ISecurityEventSink? securityEventSink = null) : AshlarSecurityEventWebhookOutboxOperationsBase(timeProvider, securityEventSink)
{
    private const string RetrySql = """
        UPDATE ashlar_security_event_webhook_outbox
        SET failed_at = NULL,
            last_error = NULL,
            locked_until = NULL,
            locked_by = NULL,
            available_at = @Now
        WHERE id = @DeliveryId
          AND sent_at IS NULL
          AND failed_at IS NOT NULL
          AND discarded_at IS NULL
        RETURNING id AS DeliveryId, endpoint_name AS EndpointName, event_id AS EventId,
                  event_type AS EventType, outcome AS Outcome, discarded_at AS DiscardedAt
        """;

    private const string DiscardSql = """
        UPDATE ashlar_security_event_webhook_outbox
        SET discarded_at = @Now,
            locked_until = NULL,
            locked_by = NULL
        WHERE id = @DeliveryId
          AND sent_at IS NULL
          AND failed_at IS NOT NULL
          AND discarded_at IS NULL
        RETURNING id AS DeliveryId, endpoint_name AS EndpointName, event_id AS EventId,
                  event_type AS EventType, outcome AS Outcome, discarded_at AS DiscardedAt
        """;

    private const string LoadSql = """
        SELECT id AS DeliveryId, endpoint_name AS EndpointName, event_id AS EventId,
               event_type AS EventType, outcome AS Outcome, discarded_at AS DiscardedAt
        FROM ashlar_security_event_webhook_outbox
        WHERE id = @DeliveryId
        """;

    private readonly IPostgresConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));

    protected override async Task<AshlarSecurityEventWebhookOutboxOperationState?> RetryFailedAsync(
        Guid deliveryId,
        CancellationToken cancellationToken)
    {
        return await ExecuteOperationAsync(RetrySql, deliveryId, cancellationToken).ConfigureAwait(false);
    }

    protected override async Task<AshlarSecurityEventWebhookOutboxOperationState?> DiscardFailedAsync(
        Guid deliveryId,
        CancellationToken cancellationToken)
    {
        return await ExecuteOperationAsync(DiscardSql, deliveryId, cancellationToken).ConfigureAwait(false);
    }

    private async Task<AshlarSecurityEventWebhookOutboxOperationState?> ExecuteOperationAsync(string sql, Guid deliveryId, CancellationToken cancellationToken)
    {
        var row = await PostgresAdminQuery.QuerySingleAsync<OperationRow>(
            _connectionProvider,
            sql,
            new { DeliveryId = deliveryId, Now = TimeProvider.GetUtcNow() },
            cancellationToken).ConfigureAwait(false);
        return row?.ToState();
    }

    protected override async Task<AshlarSecurityEventWebhookOutboxOperationState?> LoadAsync(Guid deliveryId, CancellationToken cancellationToken)
    {
        var row = await PostgresAdminQuery.QuerySingleAsync<OperationRow>(
            _connectionProvider,
            LoadSql,
            new { DeliveryId = deliveryId },
            cancellationToken).ConfigureAwait(false);
        return row?.ToState();
    }

    private sealed record OperationRow(
        Guid DeliveryId,
        string? EndpointName,
        Guid EventId,
        string? EventType,
        string? Outcome,
        DateTime? DiscardedAt)
    {
        public AshlarSecurityEventWebhookOutboxOperationState ToState()
        {
            return new AshlarSecurityEventWebhookOutboxOperationState(
                DeliveryId,
                EndpointName,
                EventId,
                EventType,
                Outcome,
                DiscardedAt.HasValue);
        }
    }
}
