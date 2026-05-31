using Ashlar.Webhooks.SecurityEvents;

namespace Ashlar.Postgres.Webhooks;

/// <summary>
/// PostgreSQL-backed manual operations for failed durable security event webhook deliveries.
/// </summary>
/// <param name="connectionProvider">The connection provider value.</param>
/// <param name="timeProvider">The time provider value.</param>
/// <param name="securityEventSink">The security event sink value.</param>
public sealed class PostgresSecurityEventWebhookOutboxOperations(
    IPostgresConnectionProvider connectionProvider,
    TimeProvider timeProvider,
    ISecurityEventSink? securityEventSink = null) : IAshlarSecurityEventWebhookOutboxOperations
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
        var row = await PostgresAdminQuery.QuerySingleAsync<OperationRow>(
            _connectionProvider,
            sql,
            new { DeliveryId = deliveryId, Now = _timeProvider.GetUtcNow() },
            cancellationToken).ConfigureAwait(false);
        return row?.ToState();
    }

    private async Task<AshlarSecurityEventWebhookOutboxOperationState?> LoadAsync(Guid deliveryId, CancellationToken cancellationToken)
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
