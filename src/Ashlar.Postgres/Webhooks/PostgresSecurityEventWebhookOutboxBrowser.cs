using Ashlar.Webhooks.SecurityEvents;

namespace Ashlar.Postgres.Webhooks;

internal sealed class PostgresSecurityEventWebhookOutboxBrowser(
    IPostgresConnectionProvider connectionProvider,
    TimeProvider timeProvider,
    IAuthenticationSessionRepository sessions,
    IAccountSecurityOperationAuthorizer authorizer,
    IPersistentSecurityEventSink auditSink) : AshlarSecurityEventWebhookOutboxBrowserBase(
        sessions, authorizer, auditSink, timeProvider)
{
    private readonly IPostgresConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

    protected override async Task<IReadOnlyList<AshlarSecurityEventWebhookOutboxDeliverySummary>> LoadAsync(
        AshlarSecurityEventWebhookOutboxBrowseRequest request,
        CancellationToken cancellationToken)
    {
        const string sql = """
            WITH browseable AS (
                SELECT id, endpoint_name, event_id, event_type, outcome, attempt_count, created_at, available_at,
                       last_attempt_at, failed_at, last_error,
                       CASE
                           WHEN failed_at IS NOT NULL THEN 'Failed'
                           WHEN sent_at IS NULL AND locked_until > @Now THEN 'Locked'
                           WHEN sent_at IS NULL AND locked_until IS NOT NULL AND locked_until <= @Now THEN 'ExpiredLock'
                           WHEN sent_at IS NULL AND available_at > @Now THEN 'Scheduled'
                           ELSE 'Pending'
                       END AS status
                FROM ashlar_security_event_webhook_outbox
                WHERE sent_at IS NULL
                  AND discarded_at IS NULL
            )
            SELECT id AS DeliveryId, endpoint_name AS EndpointName, event_id AS EventId,
                   event_type AS EventType, outcome AS Outcome, status AS Status,
                   attempt_count AS AttemptCount, created_at AS CreatedAt, available_at AS AvailableAt,
                   last_attempt_at AS LastAttemptAt, failed_at AS FailedAt, last_error AS LastError
            FROM browseable
            WHERE status = ANY(@Statuses)
            ORDER BY created_at, id
            LIMIT @Limit OFFSET @Offset
            """;

        var limitWithSentinel = request.Limit + 1;
        var parameters = new
        {
            Now = _timeProvider.GetUtcNow(),
            Statuses = AshlarSecurityEventWebhookOutboxBrowser.GetStatuses(request).Select(static status => status.ToString()).ToArray(),
            Limit = limitWithSentinel,
            request.Offset
        };
        var rows = await PostgresAdminQuery.QueryAsync<OutboxBrowseRow>(_connectionProvider, sql, parameters, cancellationToken).ConfigureAwait(false);
        return rows.Select(static row => row.ToSummary()).ToList().AsReadOnly();
    }

    private sealed record OutboxBrowseRow(
        Guid DeliveryId,
        string? EndpointName,
        Guid EventId,
        string? EventType,
        string? Outcome,
        string? Status,
        int AttemptCount,
        DateTime CreatedAt,
        DateTime AvailableAt,
        DateTime? LastAttemptAt,
        DateTime? FailedAt,
        string? LastError)
    {
        public AshlarSecurityEventWebhookOutboxDeliverySummary ToSummary()
        {
            return new AshlarSecurityEventWebhookOutboxDeliverySummary(
                DeliveryId,
                AshlarSecurityEventWebhookOutboxBrowser.SanitizeSafeText(EndpointName),
                EventId,
                AshlarSecurityEventWebhookOutboxBrowser.SanitizeSafeText(EventType),
                AshlarSecurityEventWebhookOutboxBrowser.SanitizeSafeText(Outcome),
                AshlarSecurityEventWebhookOutboxBrowser.ParseStatus(Status),
                AttemptCount,
                PostgresAdminQuery.ToDateTimeOffset(CreatedAt),
                PostgresAdminQuery.ToDateTimeOffset(AvailableAt),
                PostgresAdminQuery.ToNullableDateTimeOffset(LastAttemptAt),
                PostgresAdminQuery.ToNullableDateTimeOffset(FailedAt),
                AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary(LastError));
        }
    }
}
