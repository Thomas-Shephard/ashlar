using Ashlar.Messaging;
using Ashlar.Security.Encryption;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Ashlar.Sqlite.Messaging;

/// <summary>
/// A SQLite-backed email outbox dispatcher.
/// </summary>
/// <typeparam name="TTransport">The transport type.</typeparam>
/// <param name="serviceProvider">The service provider value.</param>
/// <param name="timeProvider">The time provider value.</param>
/// <param name="options">The options value.</param>
/// <param name="logger">The logger value.</param>
public sealed class SqliteEmailOutboxDispatcher<TTransport>(
    IServiceProvider serviceProvider,
    TimeProvider timeProvider,
    IOptions<SqliteEmailOutboxOptions> options,
    ILogger<SqliteEmailOutboxDispatcher<TTransport>>? logger = null)
    : IEmailOutboxDispatcher
    where TTransport : IEmailTransport
{
    private const string LockedByParameter = "$lockedBy";
    private const string ClaimSql = """
        UPDATE ashlar_email_outbox
        SET locked_until = $lockedUntil,
            locked_by = $lockedBy
        WHERE id IN (
            SELECT id
            FROM ashlar_email_outbox
            WHERE sent_at IS NULL
              AND failed_at IS NULL
              AND available_at <= $now
              AND (locked_until IS NULL OR locked_until <= $now)
            ORDER BY available_at, id
            LIMIT $batchSize
        )
        """;
    private const string MarkAsSentSql = """
        UPDATE ashlar_email_outbox
        SET sent_at = $now,
            locked_until = NULL,
            locked_by = NULL,
            last_attempt_at = $now,
            attempt_count = attempt_count + 1
        WHERE id = $id AND locked_by = $lockedBy
        """;
    private const string MarkAsFailedSql = """
        UPDATE ashlar_email_outbox
        SET failed_at = $failedAt,
            last_error = $lastError,
            available_at = $availableAt,
            locked_until = NULL,
            locked_by = NULL,
            last_attempt_at = $now,
            attempt_count = $attemptCount
        WHERE id = $id AND locked_by = $lockedBy
        """;
    private readonly IServiceProvider _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    private readonly SqliteEmailOutboxOptions _options = (options ?? throw new ArgumentNullException(nameof(options))).Value;
    private readonly ILogger<SqliteEmailOutboxDispatcher<TTransport>> _logger = logger ?? NullLogger<SqliteEmailOutboxDispatcher<TTransport>>.Instance;

    /// <summary>
    /// Processes a single batch of pending email messages.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<int> ProcessBatchAsync(CancellationToken cancellationToken = default)
    {
        if (!SqliteEmailOutboxOptions.Validate(_options))
        {
            throw new InvalidOperationException("Email outbox options are invalid.");
        }

        var lockId = Guid.NewGuid().ToString("D");
        return await SqliteOutboxDispatch.ProcessBatchAsync(
            new SqliteOutboxProcessContext<EmailOutboxEntry>(
                _serviceProvider,
                ClaimSql,
                lockId,
                _timeProvider,
                _options.LockDuration,
                _options.BatchSize,
                LoadClaimedEntriesAsync,
                (entry, provider, token) => ProcessEntryAsync(entry, provider, lockId, token)),
            cancellationToken);
    }

    private static async Task<List<EmailOutboxEntry>> LoadClaimedEntriesAsync(
        IServiceProvider provider,
        string lockId,
        CancellationToken cancellationToken)
    {
        var connectionProvider = provider.GetRequiredService<ISqliteConnectionProvider>();
        await using var connectionHandle = await connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = connectionHandle.Connection.CreateCommand();
        command.Transaction = connectionHandle.Transaction;
        command.CommandText = """
            SELECT id, to_address, from_address, reply_to_address, cc_address, bcc_address, subject,
                   text_body, html_body, sensitivity, body_protection, headers, metadata, attempt_count
            FROM ashlar_email_outbox
            WHERE locked_by = $lockedBy
              AND sent_at IS NULL
              AND failed_at IS NULL
            ORDER BY available_at, id
            """;
        command.AddParameter(LockedByParameter, lockId);

        var entries = new List<EmailOutboxEntry>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var idOrdinal = reader.GetOrdinal("id");
        var toAddressOrdinal = reader.GetOrdinal("to_address");
        var fromAddressOrdinal = reader.GetOrdinal("from_address");
        var replyToAddressOrdinal = reader.GetOrdinal("reply_to_address");
        var ccAddressOrdinal = reader.GetOrdinal("cc_address");
        var bccAddressOrdinal = reader.GetOrdinal("bcc_address");
        var subjectOrdinal = reader.GetOrdinal("subject");
        var textBodyOrdinal = reader.GetOrdinal("text_body");
        var htmlBodyOrdinal = reader.GetOrdinal("html_body");
        var sensitivityOrdinal = reader.GetOrdinal("sensitivity");
        var bodyProtectionOrdinal = reader.GetOrdinal("body_protection");
        var headersOrdinal = reader.GetOrdinal("headers");
        var metadataOrdinal = reader.GetOrdinal("metadata");
        var attemptCountOrdinal = reader.GetOrdinal("attempt_count");

        while (await reader.ReadAsync(cancellationToken))
        {
            entries.Add(new EmailOutboxEntry
            {
                Id = Guid.Parse(reader.GetString(idOrdinal)),
                ToAddress = reader.GetString(toAddressOrdinal),
                FromAddress = reader.GetValue(fromAddressOrdinal) as string,
                ReplyToAddress = reader.GetValue(replyToAddressOrdinal) as string,
                CcAddress = reader.GetValue(ccAddressOrdinal) as string,
                BccAddress = reader.GetValue(bccAddressOrdinal) as string,
                Subject = reader.GetString(subjectOrdinal),
                TextBody = reader.GetValue(textBodyOrdinal) as string,
                HtmlBody = reader.GetValue(htmlBodyOrdinal) as string,
                Sensitivity = EmailOutboxDispatch.ParseSensitivity(reader.GetString(sensitivityOrdinal)),
                BodyProtection = EmailOutboxDispatch.ParseBodyProtection(reader.GetString(bodyProtectionOrdinal)),
                Headers = reader.GetValue(headersOrdinal) as string,
                Metadata = reader.GetValue(metadataOrdinal) as string,
                AttemptCount = reader.GetInt32(attemptCountOrdinal)
            });
        }

        return entries;
    }

    private async Task ProcessEntryAsync(EmailOutboxEntry entry, IServiceProvider provider, string lockId, CancellationToken cancellationToken)
    {
        await EmailOutboxDispatch.DispatchAsync(
            entry,
            new EmailOutboxDispatchContext(
                provider.GetRequiredService<TTransport>(),
                _options.MaxAttempts,
                (id, token) => MarkAsSentAsync(id, provider, lockId, token),
                (failedEntry, exception, token) => MarkAsFailedAsync(failedEntry, exception, provider, lockId, token),
                (id, attemptCount, finalFailure, exception) =>
                    SqliteEmailOutboxDispatcherLog.EmailOutboxDeliveryFailed(_logger, id, attemptCount, finalFailure, exception),
                provider.GetService<ISecretProtector>()),
            cancellationToken);
    }

    private async Task MarkAsSentAsync(Guid id, IServiceProvider provider, string lockId, CancellationToken cancellationToken)
    {
        await SqliteOutboxDispatch.MarkAsSentAsync(
            new SqliteOutboxSentUpdateContext(provider, MarkAsSentSql, lockId, _timeProvider.GetUtcNow()),
            id,
            cancellationToken);
    }

    private async Task MarkAsFailedAsync(EmailOutboxEntry entry, Exception exception, IServiceProvider provider, string lockId, CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();
        var failure = EmailOutboxDispatch.CreateFailureUpdate(
            entry.AttemptCount,
            _options.MaxAttempts,
            _options.InitialRetryDelay,
            now,
            exception,
            EmailOutboxDispatch.ShouldSuppressFailureDetails(entry));

        await SqliteOutboxDispatch.MarkAsFailedAsync(
            new SqliteOutboxFailedUpdateContext(provider, MarkAsFailedSql, lockId, now),
            entry.Id,
            new SqliteOutboxFailureUpdate(failure.AttemptCount, failure.FailedAt, failure.AvailableAt, failure.LastError),
            cancellationToken);
    }
}

internal static class SqliteEmailOutboxDispatcherLog
{
    public static readonly Action<ILogger, Guid, int, bool, Exception?> EmailOutboxDeliveryFailed =
        LoggerMessage.Define<Guid, int, bool>(
            LogLevel.Warning,
            new EventId(1000, nameof(EmailOutboxDeliveryFailed)),
            "SQLite email outbox delivery failed. MessageId={MessageId} AttemptCount={AttemptCount} FinalFailure={FinalFailure}");
}
