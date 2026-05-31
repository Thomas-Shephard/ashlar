using Ashlar.Webhooks.SecurityEvents;
using Microsoft.Data.Sqlite;

namespace Ashlar.Sqlite.Webhooks;

/// <summary>
/// SQLite-backed safe browser for durable security event webhook outbox deliveries.
/// </summary>
/// <param name="connectionProvider">The connection provider value.</param>
/// <param name="timeProvider">The time provider value.</param>
public sealed class SqliteSecurityEventWebhookOutboxBrowser(
    ISqliteConnectionProvider connectionProvider,
    TimeProvider timeProvider) : IAshlarSecurityEventWebhookOutboxBrowser
{
    private readonly ISqliteConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

    /// <summary>
    /// Lists safe security event webhook outbox delivery summaries.
    /// </summary>
    /// <param name="request">The browse request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The matching outbox delivery summaries.</returns>
    public async Task<AshlarSecurityEventWebhookOutboxBrowseResult> ListAsync(
        AshlarSecurityEventWebhookOutboxBrowseRequest request,
        CancellationToken cancellationToken = default)
    {
        AshlarSecurityEventWebhookOutboxBrowser.ValidateRequest(request);

        var rows = await SqliteQuery.QueryAsync(
            _connectionProvider,
            command => BuildSql(command, request),
            ReadRow,
            cancellationToken).ConfigureAwait(false);
        var hasMore = rows.Count > request.Limit;
        var deliveries = rows.Take(request.Limit).Select(static row => row.ToSummary()).ToList().AsReadOnly();
        return new AshlarSecurityEventWebhookOutboxBrowseResult(deliveries, request.Limit, request.Offset, hasMore);
    }

    private string BuildSql(SqliteCommand command, AshlarSecurityEventWebhookOutboxBrowseRequest request)
    {
        command.AddDateTimeOffsetParameter("$now", _timeProvider.GetUtcNow());
        command.AddParameter("$limit", request.Limit + 1);
        command.AddParameter("$offset", request.Offset);

        var statusParameters = AddStatusParameters(command, request);
        return """
            WITH browseable AS (
                SELECT id, endpoint_name, event_id, event_type, outcome, attempt_count, created_at, available_at,
                       last_attempt_at, failed_at, last_error,
                       CASE
                           WHEN failed_at IS NOT NULL THEN 'Failed'
                           WHEN sent_at IS NULL AND locked_until > $now THEN 'Locked'
                           WHEN sent_at IS NULL AND locked_until IS NOT NULL AND locked_until <= $now THEN 'ExpiredLock'
                           WHEN sent_at IS NULL AND available_at > $now THEN 'Scheduled'
                           ELSE 'Pending'
                       END AS status
                FROM ashlar_security_event_webhook_outbox
                WHERE sent_at IS NULL
                  AND discarded_at IS NULL
            )
            SELECT id, endpoint_name, event_id, event_type, outcome, status, attempt_count, created_at, available_at,
                   last_attempt_at, failed_at, last_error
            FROM browseable
            WHERE status IN (
            """ + statusParameters + """
            )
            ORDER BY created_at, id
            LIMIT $limit OFFSET $offset;
            """;
    }

    private static string AddStatusParameters(SqliteCommand command, AshlarSecurityEventWebhookOutboxBrowseRequest request)
    {
        var statuses = AshlarSecurityEventWebhookOutboxBrowser.GetStatuses(request).ToArray();
        var names = new string[statuses.Length];
        for (var i = 0; i < statuses.Length; i++)
        {
            var name = "$status" + i.ToString(System.Globalization.CultureInfo.InvariantCulture);
            command.AddParameter(name, statuses[i].ToString());
            names[i] = name;
        }

        return string.Join(", ", names);
    }

    private static OutboxBrowseRow ReadRow(SqliteDataReader reader)
    {
        return new OutboxBrowseRow(
            reader.GetGuidFromText("id"),
            reader.GetNullableString("endpoint_name"),
            reader.GetGuidFromText("event_id"),
            reader.GetNullableString("event_type"),
            reader.GetNullableString("outcome"),
            reader.GetNullableString("status"),
            reader.GetInt32ByName("attempt_count"),
            reader.GetDateTimeOffsetFromText("created_at"),
            reader.GetDateTimeOffsetFromText("available_at"),
            reader.GetNullableDateTimeOffsetFromText("last_attempt_at"),
            reader.GetNullableDateTimeOffsetFromText("failed_at"),
            reader.GetNullableString("last_error"));
    }

    private sealed record OutboxBrowseRow(
        Guid DeliveryId,
        string? EndpointName,
        Guid EventId,
        string? EventType,
        string? Outcome,
        string? Status,
        int AttemptCount,
        DateTimeOffset CreatedAt,
        DateTimeOffset AvailableAt,
        DateTimeOffset? LastAttemptAt,
        DateTimeOffset? FailedAt,
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
                CreatedAt,
                AvailableAt,
                LastAttemptAt,
                FailedAt,
                AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary(LastError));
        }
    }
}
