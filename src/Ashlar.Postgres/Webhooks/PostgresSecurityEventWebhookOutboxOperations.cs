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
        AshlarSecurityEventWebhookOutboxOperations.ValidateRequest(request);

        const string sql = """
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
                      event_type AS EventType, outcome AS Outcome
            """;

        var row = await ExecuteOperationAsync(sql, request.DeliveryId, cancellationToken).ConfigureAwait(false);
        if (row is null)
        {
            return await ClassifyNoOpAsync(request.DeliveryId, cancellationToken).ConfigureAwait(false);
        }

        var result = row.ToResult(AshlarSecurityEventWebhookOutboxOperationStatus.Retried);
        await AshlarSecurityEventWebhookOutboxOperations.RecordSuccessfulOperationAsync(
            _securityEventSink,
            _timeProvider,
            AshlarSecurityEventTypes.SecurityEventWebhookOutboxDeliveryRetried,
            request,
            result,
            cancellationToken).ConfigureAwait(false);
        return result;
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
        AshlarSecurityEventWebhookOutboxOperations.ValidateRequest(request);

        const string sql = """
            UPDATE ashlar_security_event_webhook_outbox
            SET discarded_at = @Now,
                locked_until = NULL,
                locked_by = NULL
            WHERE id = @DeliveryId
              AND sent_at IS NULL
              AND failed_at IS NOT NULL
              AND discarded_at IS NULL
            RETURNING id AS DeliveryId, endpoint_name AS EndpointName, event_id AS EventId,
                      event_type AS EventType, outcome AS Outcome
            """;

        var row = await ExecuteOperationAsync(sql, request.DeliveryId, cancellationToken).ConfigureAwait(false);
        if (row is null)
        {
            return await ClassifyNoOpAsync(request.DeliveryId, cancellationToken).ConfigureAwait(false);
        }

        var result = row.ToResult(AshlarSecurityEventWebhookOutboxOperationStatus.Discarded);
        await AshlarSecurityEventWebhookOutboxOperations.RecordSuccessfulOperationAsync(
            _securityEventSink,
            _timeProvider,
            AshlarSecurityEventTypes.SecurityEventWebhookOutboxDeliveryDiscarded,
            request,
            result,
            cancellationToken).ConfigureAwait(false);
        return result;
    }

    private async Task<OperationRow?> ExecuteOperationAsync(string sql, Guid deliveryId, CancellationToken cancellationToken)
    {
        return await PostgresAdminQuery.QuerySingleAsync<OperationRow>(
            _connectionProvider,
            sql,
            new { DeliveryId = deliveryId, Now = _timeProvider.GetUtcNow() },
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<AshlarSecurityEventWebhookOutboxOperationResult> ClassifyNoOpAsync(Guid deliveryId, CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT id AS DeliveryId, endpoint_name AS EndpointName, event_id AS EventId,
                   event_type AS EventType, outcome AS Outcome, sent_at AS SentAt,
                   failed_at AS FailedAt, discarded_at AS DiscardedAt
            FROM ashlar_security_event_webhook_outbox
            WHERE id = @DeliveryId
            """;

        var row = await PostgresAdminQuery.QuerySingleAsync<OperationRow>(
            _connectionProvider,
            sql,
            new { DeliveryId = deliveryId },
            cancellationToken).ConfigureAwait(false);
        if (row is null)
        {
            return AshlarSecurityEventWebhookOutboxOperations.CreateResult(
                AshlarSecurityEventWebhookOutboxOperationStatus.NotFound,
                deliveryId);
        }

        var status = row.DiscardedAt.HasValue
            ? AshlarSecurityEventWebhookOutboxOperationStatus.AlreadyDiscarded
            : AshlarSecurityEventWebhookOutboxOperationStatus.NotFailed;
        return row.ToResult(status);
    }

    private sealed class OperationRow
    {
        public Guid DeliveryId { get; init; }
        public string? EndpointName { get; init; }
        public Guid EventId { get; init; }
        public string? EventType { get; init; }
        public string? Outcome { get; init; }
        public DateTime? SentAt { get; init; }
        public DateTime? FailedAt { get; init; }
        public DateTime? DiscardedAt { get; init; }

        public AshlarSecurityEventWebhookOutboxOperationResult ToResult(AshlarSecurityEventWebhookOutboxOperationStatus status)
        {
            return AshlarSecurityEventWebhookOutboxOperations.CreateResult(
                status,
                DeliveryId,
                EndpointName,
                EventId,
                EventType,
                Outcome);
        }
    }
}
