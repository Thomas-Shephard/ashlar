using Ashlar.Messaging;
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
    private const string TableName = "ashlar_email_outbox";
    private const string LockedByParameter = "$lockedBy";
    private readonly IServiceProvider _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    private readonly SqliteEmailOutboxOptions _options = (options ?? throw new ArgumentNullException(nameof(options))).Value;
    private readonly ILogger<SqliteEmailOutboxDispatcher<TTransport>> _logger = logger ?? NullLogger<SqliteEmailOutboxDispatcher<TTransport>>.Instance;
    private readonly string _lockId = Guid.NewGuid().ToString("D");

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

        return await SqliteOutboxDispatch.ProcessBatchAsync(
            _serviceProvider,
            TableName,
            _lockId,
            _timeProvider,
            _options.LockDuration,
            _options.BatchSize,
            LoadClaimedEntriesAsync,
            ProcessEntryAsync,
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
            SELECT id, to_address, from_address, reply_to_address, subject,
                   text_body, html_body, headers, metadata, attempt_count
            FROM ashlar_email_outbox
            WHERE locked_by = $lockedBy
              AND sent_at IS NULL
              AND failed_at IS NULL
            ORDER BY available_at, id
            """;
        command.AddParameter(LockedByParameter, lockId);

        var entries = new List<EmailOutboxEntry>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            entries.Add(new EmailOutboxEntry
            {
                Id = reader.GetGuidFromText("id"),
                ToAddress = reader.GetString(reader.GetOrdinal("to_address")),
                FromAddress = reader.GetNullableString("from_address"),
                ReplyToAddress = reader.GetNullableString("reply_to_address"),
                Subject = reader.GetString(reader.GetOrdinal("subject")),
                TextBody = reader.GetNullableString("text_body"),
                HtmlBody = reader.GetNullableString("html_body"),
                Headers = reader.GetNullableString("headers"),
                Metadata = reader.GetNullableString("metadata"),
                AttemptCount = reader.GetInt32ByName("attempt_count")
            });
        }

        return entries;
    }

    private async Task ProcessEntryAsync(EmailOutboxEntry entry, IServiceProvider provider, CancellationToken cancellationToken)
    {
        var transport = provider.GetRequiredService<TTransport>();

        try
        {
            var message = EmailOutboxDispatch.MapToEmailMessage(entry);
            await transport.DeliverAsync(message, cancellationToken);
            await MarkAsSentAsync(entry.Id, provider, CancellationToken.None);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            var attemptCount = entry.AttemptCount + 1;
            SqliteEmailOutboxDispatcherLog.EmailOutboxDeliveryFailed(_logger, entry.Id, attemptCount, attemptCount >= _options.MaxAttempts, ex);
            await MarkAsFailedAsync(entry, ex, provider, CancellationToken.None);
        }
    }

    private async Task MarkAsSentAsync(Guid id, IServiceProvider provider, CancellationToken cancellationToken)
    {
        await SqliteOutboxDispatch.MarkAsSentAsync(provider, TableName, id, _lockId, _timeProvider.GetUtcNow(), cancellationToken);
    }

    private async Task MarkAsFailedAsync(EmailOutboxEntry entry, Exception exception, IServiceProvider provider, CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();
        var failure = EmailOutboxDispatch.CreateFailureUpdate(
            entry.AttemptCount,
            _options.MaxAttempts,
            _options.InitialRetryDelay,
            now,
            exception);

        await SqliteOutboxDispatch.MarkAsFailedAsync(
            provider,
            TableName,
            entry.Id,
            _lockId,
            now,
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
