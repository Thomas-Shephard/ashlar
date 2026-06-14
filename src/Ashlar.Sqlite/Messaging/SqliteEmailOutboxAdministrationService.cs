using Ashlar.Messaging;
using Microsoft.Data.Sqlite;

namespace Ashlar.Sqlite.Messaging;

/// <summary>
/// SQLite-backed safe administration for durable email outbox rows.
/// </summary>
/// <param name="connectionProvider">Connection provider used for outbox administration queries.</param>
/// <param name="timeProvider">Clock used to derive status buckets and mutation timestamps.</param>
/// <param name="securityEventSink">Optional audit sink for successful mutating operations.</param>
public sealed class SqliteEmailOutboxAdministrationService(
    ISqliteConnectionProvider connectionProvider,
    TimeProvider timeProvider,
    ISecurityEventSink? securityEventSink = null) : IEmailOutboxAdministrationService
{
    private readonly ISqliteConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));
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
        var rows = await SqliteQuery.QueryAsync(
            _connectionProvider,
            command => BuildSearchSql(command, request),
            ReadSearchRow,
            cancellationToken).ConfigureAwait(false);
        var hasMore = rows.Count > request.Limit;
        return new EmailOutboxSearchResult(rows.Take(request.Limit).Select(static row => EmailOutboxAdministration.CreateSummary(row.ToRecord())).ToList().AsReadOnly(), request.Limit, request.Offset, hasMore);
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
                           WHEN locked_until > $now THEN 'Locked'
                           WHEN locked_until IS NOT NULL AND locked_until <= $now THEN 'ExpiredLock'
                           WHEN available_at > $now THEN 'Scheduled'
                           ELSE 'Pending'
                       END AS status
                FROM ashlar_email_outbox
                WHERE id = $id
            )
            SELECT id, to_address, from_address, reply_to_address, cc_address, subject, sensitivity, body_protection, status, attempt_count,
                   created_at, available_at, sent_at, last_attempt_at, failed_at, discarded_at, last_error,
                   has_text_body, has_html_body, has_headers, has_metadata
            FROM browseable;
            """;

        var rows = await SqliteQuery.QueryAsync(
            _connectionProvider,
            command =>
            {
                command.AddGuidParameter("$id", id);
                command.AddDateTimeOffsetParameter("$now", _timeProvider.GetUtcNow());
                return sql;
            },
            ReadDetailRow,
            cancellationToken).ConfigureAwait(false);
        var row = rows.SingleOrDefault();
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
            available_at = $now
        WHERE id = $id
          AND sent_at IS NULL
          AND failed_at IS NOT NULL
          AND discarded_at IS NULL
        RETURNING id, to_address, subject, sensitivity, body_protection, sent_at, discarded_at;
        """;

    private const string DiscardSql = """
        UPDATE ashlar_email_outbox
        SET discarded_at = $now,
            locked_until = NULL,
            locked_by = NULL
        WHERE id = $id
          AND sent_at IS NULL
          AND failed_at IS NOT NULL
          AND discarded_at IS NULL
        RETURNING id, to_address, subject, sensitivity, body_protection, sent_at, discarded_at;
        """;

    private const string LoadSql = """
        SELECT id, to_address, subject, sensitivity, body_protection, sent_at, discarded_at
        FROM ashlar_email_outbox
        WHERE id = $id;
        """;

    private async Task<EmailOutboxOperationResult> ExecuteAsync(
        EmailOutboxOperationRequest request,
        EmailOutboxOperationStatus successStatus,
        string eventType,
        string sql,
        CancellationToken cancellationToken)
    {
        EmailOutboxAdministration.ValidateOperationRequest(request);
        var state = await QueryOperationStateAsync(command =>
        {
            command.AddGuidParameter("$id", request.Id);
            command.AddDateTimeOffsetParameter("$now", _timeProvider.GetUtcNow());
            return sql;
        }, cancellationToken).ConfigureAwait(false);

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
        var state = await QueryOperationStateAsync(command =>
        {
            command.AddGuidParameter("$id", id);
            return LoadSql;
        }, cancellationToken).ConfigureAwait(false);
        return EmailOutboxAdministration.CreateNoOpResult(id, state);
    }

    private async Task<EmailOutboxOperationState?> QueryOperationStateAsync(Func<SqliteCommand, string> buildCommand, CancellationToken cancellationToken)
    {
        var rows = await SqliteQuery.QueryAsync(_connectionProvider, buildCommand, ReadOperationRow, cancellationToken).ConfigureAwait(false);
        return rows.SingleOrDefault()?.ToState();
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
        }
    }

    private string BuildSearchSql(SqliteCommand command, EmailOutboxSearchRequest request)
    {
        command.AddDateTimeOffsetParameter("$now", _timeProvider.GetUtcNow());
        command.AddParameter("$limit", request.Limit + 1);
        command.AddParameter("$offset", request.Offset);
        var statuses = AddEnumParameters(command, "$status", EmailOutboxAdministration.GetStatuses(request).Select(static status => status.ToString()).ToArray());
        return $"""
            WITH browseable AS (
                SELECT *,
                       CASE
                           WHEN discarded_at IS NOT NULL THEN 'Discarded'
                           WHEN sent_at IS NOT NULL THEN 'Sent'
                           WHEN failed_at IS NOT NULL THEN 'Failed'
                           WHEN locked_until > $now THEN 'Locked'
                           WHEN locked_until IS NOT NULL AND locked_until <= $now THEN 'ExpiredLock'
                           WHEN available_at > $now THEN 'Scheduled'
                           ELSE 'Pending'
                       END AS status
                FROM ashlar_email_outbox
            )
            SELECT id, to_address, subject, sensitivity, body_protection, status, attempt_count,
                   created_at, available_at, sent_at, last_attempt_at, failed_at, discarded_at, last_error
            FROM browseable
            WHERE status IN ({statuses})
            ORDER BY created_at, id
            LIMIT $limit OFFSET $offset;
            """;
    }

    private static string AddEnumParameters(SqliteCommand command, string prefix, string[] values)
    {
        var names = new string[values.Length];
        for (var i = 0; i < values.Length; i++)
        {
            var name = prefix + i.ToString(System.Globalization.CultureInfo.InvariantCulture);
            command.AddParameter(name, values[i]);
            names[i] = name;
        }

        return string.Join(", ", names);
    }

    private static SearchRow ReadSearchRow(SqliteDataReader reader)
    {
        return new SearchRow(
            reader.GetGuidFromText("id"),
            reader.GetNullableString("to_address"),
            reader.GetNullableString("subject"),
            reader.GetNullableString("sensitivity"),
            reader.GetNullableString("body_protection"),
            reader.GetNullableString("status"),
            reader.GetInt32ByName("attempt_count"),
            reader.GetDateTimeOffsetFromText("created_at"),
            reader.GetDateTimeOffsetFromText("available_at"),
            reader.GetNullableDateTimeOffsetFromText("sent_at"),
            reader.GetNullableDateTimeOffsetFromText("last_attempt_at"),
            reader.GetNullableDateTimeOffsetFromText("failed_at"),
            reader.GetNullableDateTimeOffsetFromText("discarded_at"),
            reader.GetNullableString("last_error"));
    }

    private static DetailRow ReadDetailRow(SqliteDataReader reader)
    {
        var row = ReadSearchRow(reader);
        return new DetailRow(
            row,
            reader.GetNullableString("from_address"),
            reader.GetNullableString("reply_to_address"),
            reader.GetNullableString("cc_address"),
            reader.GetBoolean(reader.GetOrdinal("has_text_body")),
            reader.GetBoolean(reader.GetOrdinal("has_html_body")),
            reader.GetBoolean(reader.GetOrdinal("has_headers")),
            reader.GetBoolean(reader.GetOrdinal("has_metadata")));
    }

    private static OperationRow ReadOperationRow(SqliteDataReader reader)
    {
        return new OperationRow(
            reader.GetGuidFromText("id"),
            reader.GetNullableString("to_address"),
            reader.GetNullableString("subject"),
            reader.GetNullableString("sensitivity"),
            reader.GetNullableString("body_protection"),
            reader.GetNullableDateTimeOffsetFromText("sent_at"),
            reader.GetNullableDateTimeOffsetFromText("discarded_at"));
    }

    private sealed record SearchRow(Guid Id, string? ToAddress, string? Subject, string? Sensitivity, string? BodyProtection, string? Status, int AttemptCount, DateTimeOffset CreatedAt, DateTimeOffset AvailableAt, DateTimeOffset? SentAt, DateTimeOffset? LastAttemptAt, DateTimeOffset? FailedAt, DateTimeOffset? DiscardedAt, string? LastError)
    {
        public EmailOutboxAdministrationRecord ToRecord()
        {
            return new EmailOutboxAdministrationRecord(Id, ToAddress, null, null, null, null, Subject, null, null, null, null, EmailOutboxDispatch.ParseSensitivity(Sensitivity), EmailOutboxDispatch.ParseBodyProtection(BodyProtection), EmailOutboxAdministration.ParseStatus(Status), AttemptCount, CreatedAt, AvailableAt, LastAttemptAt, FailedAt, SentAt, DiscardedAt, null, null, LastError);
        }
    }

    private sealed record DetailRow(SearchRow Row, string? FromAddress, string? ReplyToAddress, string? CcAddress, bool HasTextBody, bool HasHtmlBody, bool HasHeaders, bool HasMetadata)
    {
        public EmailOutboxAdministrationRecord ToRecord()
        {
            return Row.ToRecord() with
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

    private sealed record OperationRow(Guid Id, string? ToAddress, string? Subject, string? Sensitivity, string? BodyProtection, DateTimeOffset? SentAt, DateTimeOffset? DiscardedAt)
    {
        public EmailOutboxOperationState ToState()
        {
            var status = DiscardedAt.HasValue ? EmailOutboxStatus.Discarded : SentAt.HasValue ? EmailOutboxStatus.Sent : EmailOutboxStatus.Pending;
            var suppressPublicFields = EmailOutboxDispatch.ParseSensitivity(Sensitivity) == EmailMessageSensitivity.ContainsLiveSecret ||
                EmailOutboxDispatch.ParseBodyProtection(BodyProtection) != EmailOutboxBodyProtection.None;
            return new EmailOutboxOperationState(Id, ToAddress, Subject, status, suppressPublicFields);
        }
    }
}
