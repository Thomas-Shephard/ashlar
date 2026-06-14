using Ashlar.Messaging;
using Dapper;

namespace Ashlar.Postgres.Messaging;

/// <summary>
/// PostgreSQL-backed safe administration for durable email outbox rows.
/// </summary>
/// <param name="connectionProvider">Connection provider used for outbox administration queries.</param>
/// <param name="timeProvider">Clock used to derive status buckets and mutation timestamps.</param>
/// <param name="securityEventSink">Optional audit sink for successful mutating operations.</param>
public sealed class PostgresEmailOutboxAdministrationService(
    IPostgresConnectionProvider connectionProvider,
    TimeProvider timeProvider,
    ISecurityEventSink? securityEventSink = null) : IEmailOutboxAdministrationService
{
    private readonly IPostgresConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    private readonly ISecurityEventSink _securityEventSink = securityEventSink ?? new NullSecurityEventSink();

    /// <summary>
    /// Searches durable email outbox rows and returns safe summaries without body, header, metadata, or lock-owner values.
    /// </summary>
    /// <param name="request">Paging and status criteria for the read-only search.</param>
    /// <param name="cancellationToken">Token used to cancel the query.</param>
    /// <returns>Matching safe outbox summaries.</returns>
    public async Task<EmailOutboxSearchResult> SearchAsync(EmailOutboxSearchRequest request, CancellationToken cancellationToken = default)
    {
        EmailOutboxAdministration.ValidateSearchRequest(request);
        var parameters = CreateSearchParameters(request);
        parameters.Add("Now", _timeProvider.GetUtcNow());
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
            rows.Take(request.Limit).Select(static row => EmailOutboxAdministration.CreateSummary(row.ToRecord())).ToList().AsReadOnly(),
            request.Limit,
            request.Offset,
            hasMore);
    }

    /// <summary>
    /// Gets one durable email outbox row without unprotecting or returning message bodies.
    /// </summary>
    /// <param name="id">The outbox row id to inspect.</param>
    /// <param name="cancellationToken">Token used to cancel the query.</param>
    /// <returns>The safe detail, or <see langword="null" /> when no row exists.</returns>
    public async Task<EmailOutboxDetail?> GetAsync(Guid id, CancellationToken cancellationToken = default)
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
            new { Id = id, Now = _timeProvider.GetUtcNow() },
            cancellationToken).ConfigureAwait(false);
        return row is null ? null : EmailOutboxAdministration.CreateDetail(row.ToRecord());
    }

    /// <summary>
    /// Restores a terminal failed email row to dispatcher eligibility without sending it.
    /// </summary>
    /// <param name="request">Retry request with required audit context.</param>
    /// <param name="cancellationToken">Token used to cancel the mutation.</param>
    /// <returns>A stable retry operation result.</returns>
    public async Task<EmailOutboxOperationResult> RetryAsync(EmailOutboxOperationRequest request, CancellationToken cancellationToken = default)
    {
        return await ExecuteAsync(request, EmailOutboxOperationStatus.Retried, AshlarSecurityEventTypes.EmailOutboxDeliveryRetried, RetrySql, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Marks a terminal failed email row as discarded so dispatchers ignore it.
    /// </summary>
    /// <param name="request">Discard request with required audit context.</param>
    /// <param name="cancellationToken">Token used to cancel the mutation.</param>
    /// <returns>A stable discard operation result.</returns>
    public async Task<EmailOutboxOperationResult> DiscardAsync(EmailOutboxOperationRequest request, CancellationToken cancellationToken = default)
    {
        return await ExecuteAsync(request, EmailOutboxOperationStatus.Discarded, AshlarSecurityEventTypes.EmailOutboxDeliveryDiscarded, DiscardSql, cancellationToken).ConfigureAwait(false);
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

    private async Task<EmailOutboxOperationResult> ExecuteAsync(
        EmailOutboxOperationRequest request,
        EmailOutboxOperationStatus successStatus,
        string eventType,
        string sql,
        CancellationToken cancellationToken)
    {
        EmailOutboxAdministration.ValidateOperationRequest(request);
        var state = await QueryOperationStateAsync(sql, new { request.Id, Now = _timeProvider.GetUtcNow() }, cancellationToken).ConfigureAwait(false);
        if (state is null)
        {
            return await ClassifyNoOpAsync(request.Id, cancellationToken).ConfigureAwait(false);
        }

        var result = EmailOutboxAdministration.CreateOperationResult(successStatus, state.Id, state.ToAddress, state.Subject, state.Status, state.SuppressPublicFields);
        await RecordAuditAsync(eventType, request, result, cancellationToken).ConfigureAwait(false);
        return result;
    }

    private async Task<EmailOutboxOperationResult> ClassifyNoOpAsync(Guid id, CancellationToken cancellationToken)
    {
        var state = await QueryOperationStateAsync(LoadSql, new { Id = id }, cancellationToken).ConfigureAwait(false);
        return EmailOutboxAdministration.CreateNoOpResult(id, state);
    }

    private async Task<EmailOutboxOperationState?> QueryOperationStateAsync(string sql, object parameters, CancellationToken cancellationToken)
    {
        var row = await PostgresAdminQuery.QuerySingleAsync<OperationRow>(_connectionProvider, sql, parameters, cancellationToken).ConfigureAwait(false);
        return row?.ToState();
    }

    private async Task RecordAuditAsync(string eventType, EmailOutboxOperationRequest request, EmailOutboxOperationResult result, CancellationToken cancellationToken)
    {
        try
        {
            await _securityEventSink.RecordAsync(new AshlarSecurityEvent
            {
                Id = Guid.NewGuid(),
                EventType = eventType,
                OccurredAt = _timeProvider.GetUtcNow(),
                ActorUserId = request.Audit.ActorUserId,
                IpAddress = request.Audit.IpAddress,
                UserAgent = request.Audit.UserAgent,
                CorrelationId = request.Audit.CorrelationId,
                Outcome = SecurityEventOutcomes.Success,
                Properties = new Dictionary<string, string> { ["email_outbox_id"] = result.Id.ToString("D") }
            }, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // The outbox mutation has already committed; audit delivery is best-effort and must not change the operator-visible result.
        }
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
        parameters.Add("Statuses", EmailOutboxAdministration.GetStatuses(request).Select(static status => status.ToString()).ToArray());
        return parameters;
    }

    private record SearchRow(
        Guid Id, string? ToAddress, string? Subject, string? Sensitivity, string? BodyProtection, string? Status,
        int AttemptCount, DateTime CreatedAt, DateTime AvailableAt, DateTime? SentAt, DateTime? LastAttemptAt,
        DateTime? FailedAt, DateTime? DiscardedAt, string? LastError)
    {
        public EmailOutboxAdministrationRecord ToRecord()
        {
            return new EmailOutboxAdministrationRecord(
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
                EmailOutboxAdministration.ParseStatus(Status),
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
        public new EmailOutboxAdministrationRecord ToRecord()
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
        public EmailOutboxOperationState ToState()
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
            return new EmailOutboxOperationState(Id, ToAddress, Subject, status, suppressPublicFields);
        }
    }
}
