using Ashlar.Messaging;
using Microsoft.Data.Sqlite;

namespace Ashlar.Sqlite.Messaging;

internal sealed class SqliteEmailOutboxAdministrationService(
    ISqliteConnectionProvider connectionProvider,
    TimeProvider timeProvider,
    ISecurityEventSink securityEventSink,
    AshlarDurableTransactionProvider transactionProvider) : EmailOutboxAdministrationServiceBase(timeProvider, securityEventSink, transactionProvider)
{
    private readonly ISqliteConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));

    public override async Task<EmailOutboxSearchResult> SearchAsync(EmailOutboxSearchRequest request, CancellationToken cancellationToken = default)
    {
        EmailOutboxAdministrationProvider.ValidateSearchRequest(request);
        var rows = await SqliteQuery.QueryAsync(
            _connectionProvider,
            command => BuildSearchSql(command, request),
            ReadSearchRow,
            cancellationToken).ConfigureAwait(false);
        var hasMore = rows.Count > request.Limit;
        return new EmailOutboxSearchResult(rows.Take(request.Limit).Select(static row => EmailOutboxAdministrationProvider.CreateSummary(row.ToRecord())).ToList().AsReadOnly(), request.Limit, request.Offset, hasMore);
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
                command.AddDateTimeOffsetParameter("$now", TimeProvider.GetUtcNow());
                return sql;
            },
            ReadDetailRow,
            cancellationToken).ConfigureAwait(false);
        var row = rows.SingleOrDefault();
        return row is null ? null : EmailOutboxAdministrationProvider.CreateDetail(row.ToRecord());
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

    protected override async Task<EmailOutboxAdministrationOperationState?> RetryFailedAsync(Guid id, CancellationToken cancellationToken)
    {
        return await QueryOperationStateAsync(command =>
        {
            command.AddGuidParameter("$id", id);
            command.AddDateTimeOffsetParameter("$now", TimeProvider.GetUtcNow());
            return RetrySql;
        }, cancellationToken).ConfigureAwait(false);
    }

    protected override async Task<EmailOutboxAdministrationOperationState?> DiscardFailedAsync(Guid id, CancellationToken cancellationToken)
    {
        return await QueryOperationStateAsync(command =>
        {
            command.AddGuidParameter("$id", id);
            command.AddDateTimeOffsetParameter("$now", TimeProvider.GetUtcNow());
            return DiscardSql;
        }, cancellationToken).ConfigureAwait(false);
    }

    protected override async Task<EmailOutboxAdministrationOperationState?> LoadOperationStateAsync(Guid id, CancellationToken cancellationToken)
    {
        return await QueryOperationStateAsync(command =>
        {
            command.AddGuidParameter("$id", id);
            return LoadSql;
        }, cancellationToken).ConfigureAwait(false);
    }

    private async Task<EmailOutboxAdministrationOperationState?> QueryOperationStateAsync(Func<SqliteCommand, string> buildCommand, CancellationToken cancellationToken)
    {
        var rows = await SqliteQuery.QueryAsync(_connectionProvider, buildCommand, ReadOperationRow, cancellationToken).ConfigureAwait(false);
        return rows.SingleOrDefault()?.ToState();
    }

    private string BuildSearchSql(SqliteCommand command, EmailOutboxSearchRequest request)
    {
        command.AddDateTimeOffsetParameter("$now", TimeProvider.GetUtcNow());
        command.AddParameter("$limit", request.Limit + 1);
        command.AddParameter("$offset", request.Offset);
        var statuses = AddEnumParameters(command, "$status", EmailOutboxAdministrationProvider.GetStatuses(request).Select(static status => status.ToString()).ToArray());
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
            ReadIdentityFields(reader),
            ReadDeliveryFields(reader),
            ReadFailureFields(reader));
    }

    private static SearchRowIdentity ReadIdentityFields(SqliteDataReader reader)
    {
        return new SearchRowIdentity(
            reader.GetGuidFromText("id"),
            reader.GetNullableString("to_address"),
            reader.GetNullableString("subject"),
            reader.GetNullableString("sensitivity"),
            reader.GetNullableString("body_protection"),
            reader.GetNullableString("status"));
    }

    private static SearchRowDelivery ReadDeliveryFields(SqliteDataReader reader)
    {
        return new SearchRowDelivery(
            reader.GetInt32ByName("attempt_count"),
            reader.GetDateTimeOffsetFromText("created_at"),
            reader.GetDateTimeOffsetFromText("available_at"),
            reader.GetNullableDateTimeOffsetFromText("sent_at"),
            reader.GetNullableDateTimeOffsetFromText("last_attempt_at"),
            reader.GetNullableDateTimeOffsetFromText("discarded_at"));
    }

    private static SearchRowFailure ReadFailureFields(SqliteDataReader reader)
    {
        return new SearchRowFailure(
            reader.GetNullableDateTimeOffsetFromText("failed_at"),
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

    private sealed record SearchRow(SearchRowIdentity Identity, SearchRowDelivery Delivery, SearchRowFailure Failure)
    {
        public EmailOutboxAdministrationProjection ToRecord()
        {
            return new EmailOutboxAdministrationProjection(
                Identity.Id,
                Identity.ToAddress,
                null,
                null,
                null,
                null,
                Identity.Subject,
                null,
                null,
                null,
                null,
                EmailOutboxDispatch.ParseSensitivity(Identity.Sensitivity),
                EmailOutboxDispatch.ParseBodyProtection(Identity.BodyProtection),
                EmailOutboxAdministrationProvider.ParseStatus(Identity.Status),
                Delivery.AttemptCount,
                Delivery.CreatedAt,
                Delivery.AvailableAt,
                Delivery.LastAttemptAt,
                Failure.FailedAt,
                Delivery.SentAt,
                Delivery.DiscardedAt,
                null,
                null,
                Failure.LastError);
        }
    }

    private sealed record SearchRowIdentity(Guid Id, string? ToAddress, string? Subject, string? Sensitivity, string? BodyProtection, string? Status);

    private sealed record SearchRowDelivery(int AttemptCount, DateTimeOffset CreatedAt, DateTimeOffset AvailableAt, DateTimeOffset? SentAt, DateTimeOffset? LastAttemptAt, DateTimeOffset? DiscardedAt);

    private sealed record SearchRowFailure(DateTimeOffset? FailedAt, string? LastError);

    private sealed record DetailRow(SearchRow Row, string? FromAddress, string? ReplyToAddress, string? CcAddress, bool HasTextBody, bool HasHtmlBody, bool HasHeaders, bool HasMetadata)
    {
        public EmailOutboxAdministrationProjection ToRecord()
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
