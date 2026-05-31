using Ashlar.Webhooks.SecurityEvents;
using Microsoft.Data.Sqlite;

namespace Ashlar.Sqlite.Webhooks;

/// <summary>
/// SQLite-backed manual operations for failed durable security event webhook deliveries.
/// </summary>
/// <param name="connectionProvider">The connection provider value.</param>
/// <param name="timeProvider">The time provider value.</param>
/// <param name="securityEventSink">The security event sink value.</param>
public sealed class SqliteSecurityEventWebhookOutboxOperations(
    ISqliteConnectionProvider connectionProvider,
    TimeProvider timeProvider,
    ISecurityEventSink? securityEventSink = null) : IAshlarSecurityEventWebhookOutboxOperations
{
    private const string RetrySql = """
        UPDATE ashlar_security_event_webhook_outbox
        SET failed_at = NULL,
            last_error = NULL,
            locked_until = NULL,
            locked_by = NULL,
            available_at = $now
        WHERE id = $deliveryId
          AND sent_at IS NULL
          AND failed_at IS NOT NULL
          AND discarded_at IS NULL
        RETURNING id, endpoint_name, event_id, event_type, outcome, discarded_at;
        """;

    private const string DiscardSql = """
        UPDATE ashlar_security_event_webhook_outbox
        SET discarded_at = $now,
            locked_until = NULL,
            locked_by = NULL
        WHERE id = $deliveryId
          AND sent_at IS NULL
          AND failed_at IS NOT NULL
          AND discarded_at IS NULL
        RETURNING id, endpoint_name, event_id, event_type, outcome, discarded_at;
        """;

    private const string LoadSql = """
        SELECT id, endpoint_name, event_id, event_type, outcome, discarded_at
        FROM ashlar_security_event_webhook_outbox
        WHERE id = $deliveryId;
        """;

    private readonly ISqliteConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    private readonly ISecurityEventSink _securityEventSink = securityEventSink ?? new NullSecurityEventSink();

    /// <summary>
    /// Makes a terminal failed delivery dispatchable immediately.
    /// </summary>
    /// <param name="request">The retry request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<AshlarSecurityEventWebhookOutboxOperationResult> RetryAsync(
        AshlarSecurityEventWebhookOutboxOperationRequest request,
        CancellationToken cancellationToken = default)
    {
        return await ExecuteAsync(
            RetrySql,
            AshlarSecurityEventWebhookOutboxOperationStatus.Retried,
            AshlarSecurityEventTypes.SecurityEventWebhookOutboxDeliveryRetried,
            request,
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Marks a terminal failed delivery as discarded.
    /// </summary>
    /// <param name="request">The discard request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<AshlarSecurityEventWebhookOutboxOperationResult> DiscardAsync(
        AshlarSecurityEventWebhookOutboxOperationRequest request,
        CancellationToken cancellationToken = default)
    {
        return await ExecuteAsync(
            DiscardSql,
            AshlarSecurityEventWebhookOutboxOperationStatus.Discarded,
            AshlarSecurityEventTypes.SecurityEventWebhookOutboxDeliveryDiscarded,
            request,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<AshlarSecurityEventWebhookOutboxOperationResult> ExecuteAsync(
        string sql,
        AshlarSecurityEventWebhookOutboxOperationStatus successStatus,
        string auditEventType,
        AshlarSecurityEventWebhookOutboxOperationRequest request,
        CancellationToken cancellationToken)
    {
        return await AshlarSecurityEventWebhookOutboxOperations.ExecuteStateChangeAsync(
            request,
            new AshlarSecurityEventWebhookOutboxOperationContext(
                successStatus,
                auditEventType,
                (deliveryId, token) => ExecuteOperationAsync(sql, deliveryId, token),
                LoadAsync,
                _securityEventSink,
                _timeProvider),
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<AshlarSecurityEventWebhookOutboxOperationState?> ExecuteOperationAsync(string sql, Guid deliveryId, CancellationToken cancellationToken)
    {
        var row = await QuerySingleAsync(
            command =>
            {
                command.CommandText = sql;
                command.AddGuidParameter("$deliveryId", deliveryId);
                command.AddDateTimeOffsetParameter("$now", _timeProvider.GetUtcNow());
            },
            cancellationToken).ConfigureAwait(false);
        return row?.ToState();
    }

    private async Task<AshlarSecurityEventWebhookOutboxOperationState?> LoadAsync(Guid deliveryId, CancellationToken cancellationToken)
    {
        var row = await QuerySingleAsync(
            command =>
            {
                command.CommandText = LoadSql;
                command.AddGuidParameter("$deliveryId", deliveryId);
            },
            cancellationToken).ConfigureAwait(false);
        return row?.ToState();
    }

    private async Task<OperationRow?> QuerySingleAsync(Action<SqliteCommand> buildCommand, CancellationToken cancellationToken)
    {
        await using var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = connectionHandle.Connection.CreateCommand();
        command.Transaction = connectionHandle.Transaction;
        buildCommand(command);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadRow(reader) : null;
    }

    private static OperationRow ReadRow(SqliteDataReader reader)
    {
        return new OperationRow(
            reader.GetGuidFromText("id"),
            reader.GetNullableString("endpoint_name"),
            reader.GetGuidFromText("event_id"),
            reader.GetNullableString("event_type"),
            reader.GetNullableString("outcome"),
            reader.GetNullableDateTimeOffsetFromText("discarded_at"));
    }

    private sealed record OperationRow(
        Guid DeliveryId,
        string? EndpointName,
        Guid EventId,
        string? EventType,
        string? Outcome,
        DateTimeOffset? DiscardedAt = null)
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
