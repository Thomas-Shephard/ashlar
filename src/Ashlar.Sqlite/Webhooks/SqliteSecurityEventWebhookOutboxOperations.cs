using Ashlar.Webhooks.SecurityEvents;
using Microsoft.Data.Sqlite;

namespace Ashlar.Sqlite.Webhooks;

internal sealed class SqliteSecurityEventWebhookOutboxOperations(
    ISqliteConnectionProvider connectionProvider,
    TimeProvider timeProvider,
    ISecurityEventSink securityEventSink,
    AshlarDurableTransactionProvider transactionProvider,
    IAuthenticationSessionRepository sessions,
    IAccountSecurityOperationAuthorizer authorizer,
    IPersistentSecurityEventSink auditSink) : AshlarSecurityEventWebhookOutboxOperationsBase(
        timeProvider, securityEventSink, transactionProvider, sessions, authorizer, auditSink)
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
        var row = await QuerySingleAsync(
            command =>
            {
                command.CommandText = sql;
                command.AddGuidParameter("$deliveryId", deliveryId);
                command.AddDateTimeOffsetParameter("$now", TimeProvider.GetUtcNow());
            },
            cancellationToken).ConfigureAwait(false);
        return row?.ToState();
    }

    protected override async Task<AshlarSecurityEventWebhookOutboxOperationState?> LoadAsync(Guid deliveryId, CancellationToken cancellationToken)
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
