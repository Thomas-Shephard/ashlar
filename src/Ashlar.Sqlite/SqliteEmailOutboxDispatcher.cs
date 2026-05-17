using Ashlar.Messaging;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using System.Text.Json;

namespace Ashlar.Sqlite;

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
    where TTransport : IEmailTransport
{
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

        var now = _timeProvider.GetUtcNow();
        var lockedUntil = now.Add(_options.LockDuration);

        await using var scope = _serviceProvider.CreateAsyncScope();
        var connectionProvider = scope.ServiceProvider.GetRequiredService<ISqliteConnectionProvider>();
        await using (var connectionHandle = await connectionProvider.GetConnectionAsync(cancellationToken))
        {
            await using var command = connectionHandle.Connection.CreateCommand();
            command.Transaction = connectionHandle.Transaction;
            command.CommandText = """
                UPDATE ashlar_email_outbox
                SET locked_until = $lockedUntil,
                    locked_by = $lockedBy
                WHERE id IN (
                    SELECT id
                    FROM ashlar_email_outbox
                    WHERE sent_at IS NULL
                      AND failed_at IS NULL
                      AND available_at <= $now
                      AND (locked_until IS NULL OR locked_until < $now)
                    ORDER BY available_at, id
                    LIMIT $batchSize
                )
                """;
            command.AddDateTimeOffsetParameter("$lockedUntil", lockedUntil);
            command.AddParameter("$lockedBy", _lockId);
            command.AddDateTimeOffsetParameter("$now", now);
            command.AddParameter("$batchSize", _options.BatchSize);

            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        var entries = await LoadClaimedEntriesAsync(scope.ServiceProvider, _lockId, cancellationToken);
        if (entries.Count == 0)
        {
            return 0;
        }

        foreach (var entry in entries)
        {
            await using var entryScope = _serviceProvider.CreateAsyncScope();
            await ProcessEntryAsync(entry, entryScope.ServiceProvider, cancellationToken);
        }

        return entries.Count;
    }

    private static async Task<List<OutboxEntry>> LoadClaimedEntriesAsync(
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
        command.AddParameter("$lockedBy", lockId);

        var entries = new List<OutboxEntry>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            entries.Add(new OutboxEntry
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

    private async Task ProcessEntryAsync(OutboxEntry entry, IServiceProvider provider, CancellationToken cancellationToken)
    {
        var transport = provider.GetRequiredService<TTransport>();

        try
        {
            var message = MapToEmailMessage(entry);
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
        var now = _timeProvider.GetUtcNow();
        var connectionProvider = provider.GetRequiredService<ISqliteConnectionProvider>();
        await using var connectionHandle = await connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = connectionHandle.Connection.CreateCommand();
        command.Transaction = connectionHandle.Transaction;
        command.CommandText = """
            UPDATE ashlar_email_outbox
            SET sent_at = $now,
                locked_until = NULL,
                locked_by = NULL,
                last_attempt_at = $now,
                attempt_count = attempt_count + 1
            WHERE id = $id AND locked_by = $lockedBy
            """;
        command.AddDateTimeOffsetParameter("$now", now);
        command.AddGuidParameter("$id", id);
        command.AddParameter("$lockedBy", _lockId);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private async Task MarkAsFailedAsync(OutboxEntry entry, Exception exception, IServiceProvider provider, CancellationToken cancellationToken)
    {
        var attemptCount = entry.AttemptCount + 1;
        var isFinalFailure = attemptCount >= _options.MaxAttempts;
        var now = _timeProvider.GetUtcNow();
        var backoffMultiplier = Math.Pow(2, attemptCount - 1);
        var maxDelayTicks = TimeSpan.FromDays(7).Ticks;
        var delayTicks = Math.Min(_options.InitialRetryDelay.Ticks * backoffMultiplier, maxDelayTicks);
        var availableAt = isFinalFailure ? now : now.AddTicks((long)delayTicks);
        var lastError = exception.ToString();
        if (lastError.Length > 1000)
        {
            lastError = lastError[..1000];
        }

        var connectionProvider = provider.GetRequiredService<ISqliteConnectionProvider>();
        await using var connectionHandle = await connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = connectionHandle.Connection.CreateCommand();
        command.Transaction = connectionHandle.Transaction;
        command.CommandText = """
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
        command.AddNullableDateTimeOffsetParameter("$failedAt", isFinalFailure ? now : null);
        command.AddParameter("$lastError", lastError);
        command.AddDateTimeOffsetParameter("$availableAt", availableAt);
        command.AddDateTimeOffsetParameter("$now", now);
        command.AddParameter("$attemptCount", attemptCount);
        command.AddGuidParameter("$id", entry.Id);
        command.AddParameter("$lockedBy", _lockId);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    internal static EmailMessage MapToEmailMessage(OutboxEntry entry)
    {
        var headers = entry.Headers != null ? JsonSerializer.Deserialize<Dictionary<string, string>>(entry.Headers) : null;
        var metadata = entry.Metadata != null ? JsonSerializer.Deserialize<Dictionary<string, string>>(entry.Metadata) : null;

        return new EmailMessage(
            entry.ToAddress,
            entry.Subject,
            entry.TextBody,
            entry.HtmlBody,
            new EmailMessageOptions
            {
                From = entry.FromAddress,
                ReplyTo = entry.ReplyToAddress,
                Headers = headers,
                Metadata = metadata
            });
    }

    internal sealed class OutboxEntry
    {
        public Guid Id { get; init; }
        public required string ToAddress { get; init; }
        public string? FromAddress { get; init; }
        public string? ReplyToAddress { get; init; }
        public required string Subject { get; init; }
        public string? TextBody { get; init; }
        public string? HtmlBody { get; init; }
        public string? Headers { get; init; }
        public string? Metadata { get; init; }
        public int AttemptCount { get; init; }
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
