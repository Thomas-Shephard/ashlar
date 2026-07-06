using Ashlar.Messaging;
using Dapper;

namespace Ashlar.Postgres.Messaging;

internal sealed class PostgresEmailOutboxAdministrationService(
    IPostgresConnectionProvider connectionProvider,
    TimeProvider timeProvider,
    ISecurityEventSink? securityEventSink = null,
    IAshlarTransactionProvider? transactionProvider = null) : EmailOutboxAdministrationServiceBase(timeProvider, securityEventSink, transactionProvider)
{
    private readonly IPostgresConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));

    public override async Task<EmailOutboxSearchResult> SearchAsync(EmailOutboxSearchRequest request, CancellationToken cancellationToken = default)
    {
        EmailOutboxAdministrationProvider.ValidateSearchRequest(request);
        var parameters = CreateSearchParameters(request);
        parameters.Add("Now", TimeProvider.GetUtcNow());
        parameters.Add("Limit", request.Limit + 1);
        parameters.Add("Offset", request.Offset);

        var sql = CreateSearchSql("""
            SELECT id AS Id, to_address AS ToAddress, subject AS Subject, sensitivity AS Sensitivity,
                   body_protection AS BodyProtection, status AS Status, attempt_count AS AttemptCount,
                   created_at AS CreatedAt, available_at AS AvailableAt, sent_at AS SentAt,
                   last_attempt_at AS LastAttemptAt, failed_at AS FailedAt, discarded_at AS DiscardedAt,
                   last_error AS LastError
            """);

        var rows = await PostgresAdminQuery.QueryAsync<SearchRow>(_connectionProvider, sql, parameters, cancellationToken).ConfigureAwait(false);
        var hasMore = rows.Count > request.Limit;
        return new EmailOutboxSearchResult(
            rows.Take(request.Limit).Select(static row => EmailOutboxAdministrationProvider.CreateSummary(row.ToRecord())).ToList().AsReadOnly(),
            request.Limit,
            request.Offset,
            hasMore);
    }

    public override async Task<EmailOutboxDetail?> GetAsync(Guid id, CancellationToken cancellationToken = default)
    {
        if (id == Guid.Empty)
        {
            throw new ArgumentException("Email outbox row ID cannot be empty.", nameof(id));
        }

        const string sql = """
            WITH browseable AS (
                SELECT id, to_address, from_address, reply_to_address, cc_address, subject, sensitivity, body_protection, attempt_count,
                       created_at, available_at, sent_at, last_attempt_at, failed_at, discarded_at, last_error,
                       text_body IS NOT NULL AS has_text_body, html_body IS NOT NULL AS has_html_body,
                       headers IS NOT NULL AS has_headers, metadata IS NOT NULL AS has_metadata,
                       CASE
                           WHEN discarded_at IS NOT NULL THEN 'Discarded'
                           WHEN sent_at IS NOT NULL THEN 'Sent'
                           WHEN failed_at IS NOT NULL THEN 'Failed'
                           WHEN locked_until > @Now THEN 'Locked'
                           WHEN locked_until IS NOT NULL AND locked_until <= @Now THEN 'ExpiredLock'
                           WHEN available_at > @Now THEN 'Scheduled'
                           ELSE 'Pending'
                       END AS status
                FROM ashlar_email_outbox
                WHERE id = @Id
            )
            SELECT id AS Id, to_address AS ToAddress, from_address AS FromAddress, reply_to_address AS ReplyToAddress,
                   cc_address AS CcAddress, subject AS Subject, sensitivity AS Sensitivity,
                   body_protection AS BodyProtection, status AS Status, attempt_count AS AttemptCount,
                   created_at AS CreatedAt, available_at AS AvailableAt, sent_at AS SentAt,
                   last_attempt_at AS LastAttemptAt, failed_at AS FailedAt, discarded_at AS DiscardedAt,
                   last_error AS LastError, has_text_body AS HasTextBody, has_html_body AS HasHtmlBody,
                   has_headers AS HasHeaders, has_metadata AS HasMetadata
            FROM browseable
            """;

        var row = await PostgresAdminQuery.QuerySingleAsync<DetailRow>(
            _connectionProvider,
            sql,
            new { Id = id, Now = TimeProvider.GetUtcNow() },
            cancellationToken).ConfigureAwait(false);
        return row is null ? null : EmailOutboxAdministrationProvider.CreateDetail(row.ToRecord());
    }

    private const string RetrySql = """
        UPDATE ashlar_email_outbox
        SET failed_at = NULL,
            last_error = NULL,
            locked_until = NULL,
            locked_by = NULL,
            available_at = @Now
        WHERE id = @Id
          AND sent_at IS NULL
          AND failed_at IS NOT NULL
          AND discarded_at IS NULL
        RETURNING id AS Id, to_address AS ToAddress, subject AS Subject, sensitivity AS Sensitivity,
                  body_protection AS BodyProtection, sent_at AS SentAt, discarded_at AS DiscardedAt
        """;

    private const string DiscardSql = """
        UPDATE ashlar_email_outbox
        SET discarded_at = @Now,
            locked_until = NULL,
            locked_by = NULL
        WHERE id = @Id
          AND sent_at IS NULL
          AND failed_at IS NOT NULL
          AND discarded_at IS NULL
        RETURNING id AS Id, to_address AS ToAddress, subject AS Subject, sensitivity AS Sensitivity,
                  body_protection AS BodyProtection, sent_at AS SentAt, discarded_at AS DiscardedAt
        """;

    private const string LoadSql = """
        SELECT id AS Id, to_address AS ToAddress, subject AS Subject, sensitivity AS Sensitivity, body_protection AS BodyProtection,
               sent_at AS SentAt, discarded_at AS DiscardedAt
        FROM ashlar_email_outbox
        WHERE id = @Id
        """;

    protected override async Task<EmailOutboxAdministrationOperationState?> RetryFailedAsync(Guid id, CancellationToken cancellationToken)
    {
        return await QueryOperationStateAsync(RetrySql, new { Id = id, Now = TimeProvider.GetUtcNow() }, cancellationToken).ConfigureAwait(false);
    }

    protected override async Task<EmailOutboxAdministrationOperationState?> DiscardFailedAsync(Guid id, CancellationToken cancellationToken)
    {
        return await QueryOperationStateAsync(DiscardSql, new { Id = id, Now = TimeProvider.GetUtcNow() }, cancellationToken).ConfigureAwait(false);
    }

    protected override async Task<EmailOutboxAdministrationOperationState?> LoadOperationStateAsync(Guid id, CancellationToken cancellationToken)
    {
        return await QueryOperationStateAsync(LoadSql, new { Id = id }, cancellationToken).ConfigureAwait(false);
    }

    private async Task<EmailOutboxAdministrationOperationState?> QueryOperationStateAsync(string sql, object parameters, CancellationToken cancellationToken)
    {
        var row = await PostgresAdminQuery.QuerySingleAsync<OperationRow>(_connectionProvider, sql, parameters, cancellationToken).ConfigureAwait(false);
        return row?.ToState();
    }

    private static string CreateSearchSql(string select)
    {
        return $"""
            WITH browseable AS (
                SELECT *,
                       CASE
                           WHEN discarded_at IS NOT NULL THEN 'Discarded'
                           WHEN sent_at IS NOT NULL THEN 'Sent'
                           WHEN failed_at IS NOT NULL THEN 'Failed'
                           WHEN locked_until > @Now THEN 'Locked'
                           WHEN locked_until IS NOT NULL AND locked_until <= @Now THEN 'ExpiredLock'
                           WHEN available_at > @Now THEN 'Scheduled'
                           ELSE 'Pending'
                       END AS status
                FROM ashlar_email_outbox
            )
            {select}
            FROM browseable
            WHERE status = ANY(@Statuses)
            ORDER BY created_at, id
            LIMIT @Limit OFFSET @Offset
            """;
    }

    private static DynamicParameters CreateSearchParameters(EmailOutboxSearchRequest request)
    {
        var parameters = new DynamicParameters();
        parameters.Add("Statuses", EmailOutboxAdministrationProvider.GetStatuses(request).Select(static status => status.ToString()).ToArray());
        return parameters;
    }

    private record SearchRow(
        Guid Id, string? ToAddress, string? Subject, string? Sensitivity, string? BodyProtection, string? Status,
        int AttemptCount, DateTime CreatedAt, DateTime AvailableAt, DateTime? SentAt, DateTime? LastAttemptAt,
        DateTime? FailedAt, DateTime? DiscardedAt, string? LastError)
    {
        public EmailOutboxAdministrationProjection ToRecord()
        {
            return new EmailOutboxAdministrationProjection(
                Id,
                ToAddress,
                null,
                null,
                null,
                null,
                Subject,
                null,
                null,
                null,
                null,
                EmailOutboxDispatch.ParseSensitivity(Sensitivity),
                EmailOutboxDispatch.ParseBodyProtection(BodyProtection),
                EmailOutboxAdministrationProvider.ParseStatus(Status),
                AttemptCount,
                PostgresAdminQuery.ToDateTimeOffset(CreatedAt),
                PostgresAdminQuery.ToDateTimeOffset(AvailableAt),
                PostgresAdminQuery.ToNullableDateTimeOffset(LastAttemptAt),
                PostgresAdminQuery.ToNullableDateTimeOffset(FailedAt),
                PostgresAdminQuery.ToNullableDateTimeOffset(SentAt),
                PostgresAdminQuery.ToNullableDateTimeOffset(DiscardedAt),
                null,
                null,
                LastError);
        }
    }

    private sealed record DetailRow(
        Guid Id, string? ToAddress, string? FromAddress, string? ReplyToAddress, string? CcAddress, string? Subject, string? Sensitivity, string? BodyProtection, string? Status,
        int AttemptCount, DateTime CreatedAt, DateTime AvailableAt, DateTime? SentAt, DateTime? LastAttemptAt,
        DateTime? FailedAt, DateTime? DiscardedAt, string? LastError, bool HasTextBody, bool HasHtmlBody,
        bool HasHeaders, bool HasMetadata) : SearchRow(Id, ToAddress, Subject, Sensitivity, BodyProtection, Status, AttemptCount, CreatedAt, AvailableAt, SentAt, LastAttemptAt, FailedAt, DiscardedAt, LastError)
    {
        public new EmailOutboxAdministrationProjection ToRecord()
        {
            return base.ToRecord() with
            {
                FromAddress = FromAddress,
                ReplyToAddress = ReplyToAddress,
                CcAddress = CcAddress,
                TextBody = HasTextBody ? string.Empty : null,
                HtmlBody = HasHtmlBody ? string.Empty : null,
                Headers = HasHeaders ? string.Empty : null,
                Metadata = HasMetadata ? string.Empty : null
            };
        }
    }

    private sealed record OperationRow(Guid Id, string? ToAddress, string? Subject, string? Sensitivity, string? BodyProtection, DateTime? SentAt, DateTime? DiscardedAt)
    {
        public EmailOutboxAdministrationOperationState ToState()
        {
            var status = EmailOutboxStatus.Pending;
            if (SentAt.HasValue)
            {
                status = EmailOutboxStatus.Sent;
            }

            if (DiscardedAt.HasValue)
            {
                status = EmailOutboxStatus.Discarded;
            }

            var suppressPublicFields = EmailOutboxDispatch.ParseSensitivity(Sensitivity) == EmailMessageSensitivity.ContainsLiveSecret ||
                EmailOutboxDispatch.ParseBodyProtection(BodyProtection) != EmailOutboxBodyProtection.None;
            return new EmailOutboxAdministrationOperationState(Id, ToAddress, Subject, status, suppressPublicFields);
        }
    }
}
