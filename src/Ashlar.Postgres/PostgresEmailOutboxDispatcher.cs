using Ashlar.Messaging;
using Dapper;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System.Text.Json;

namespace Ashlar.Postgres;

/// <summary>
/// A PostgreSQL-backed implementation of <see cref="IEmailOutboxDispatcher"/> that dispatches pending email messages.
/// </summary>
/// <typeparam name="TTransport">The ttransport type.</typeparam>
/// <param name="serviceProvider">The service provider value.</param>
/// <param name="timeProvider">The time provider value.</param>
/// <param name="options">The options value.</param>
public sealed class PostgresEmailOutboxDispatcher<TTransport>(
    IServiceProvider serviceProvider,
    TimeProvider timeProvider,
    IOptions<PostgresEmailOutboxOptions> options) : IEmailOutboxDispatcher
    where TTransport : IEmailTransport
{
    private readonly IServiceProvider _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    private readonly PostgresEmailOutboxOptions _options = (options ?? throw new ArgumentNullException(nameof(options))).Value;
    private readonly string _lockId = Guid.NewGuid().ToString();

    /// <inheritdoc />
    public async Task<int> ProcessBatchAsync(CancellationToken cancellationToken = default)
    {
        if (!PostgresEmailOutboxOptions.Validate(_options))
        {
            throw new InvalidOperationException("Email outbox options are invalid.");
        }

        const string claimSql = """
            UPDATE ashlar_email_outbox
            SET locked_until = @LockedUntil,
                locked_by = @LockedBy
            WHERE id IN (
                SELECT id
                FROM ashlar_email_outbox
                WHERE sent_at IS NULL
                  AND failed_at IS NULL
                  AND available_at <= @Now
                  AND (locked_until IS NULL OR locked_until < @Now)
                ORDER BY available_at
                LIMIT @BatchSize
                FOR UPDATE SKIP LOCKED
            )
            RETURNING id AS Id, to_address AS ToAddress, from_address AS FromAddress,
                      reply_to_address AS ReplyToAddress, subject AS Subject,
                      text_body AS TextBody, html_body AS HtmlBody,
                      headers AS Headers, metadata AS Metadata,
                      attempt_count AS AttemptCount
            """;

        var now = _timeProvider.GetUtcNow();
        var lockedUntil = now.Add(_options.LockDuration);

        List<OutboxEntry> entries;
        await using (var scope = _serviceProvider.CreateAsyncScope())
        {
            var connectionProvider = scope.ServiceProvider.GetRequiredService<IPostgresConnectionProvider>();
            var connectionHandle = await connectionProvider.GetConnectionAsync(cancellationToken);
            await using (connectionHandle)
            {
                var command = new CommandDefinition(claimSql, new
                {
                    Now = now,
                    LockedUntil = lockedUntil,
                    LockedBy = _lockId,
                    _options.BatchSize
                }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);

                entries = (await connectionHandle.Connection.QueryAsync<OutboxEntry>(command)).ToList();
            }
        }

        if (entries.Count == 0)
        {
            return 0;
        }

        foreach (var entry in entries)
        {
            await using var scope = _serviceProvider.CreateAsyncScope();
            await ProcessEntryAsync(entry, scope.ServiceProvider, cancellationToken);
        }

        return entries.Count;
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
            await MarkAsFailedAsync(entry, ex, provider, CancellationToken.None);
        }
    }

    private async Task MarkAsSentAsync(Guid id, IServiceProvider provider, CancellationToken cancellationToken)
    {
        const string sql = """
            UPDATE ashlar_email_outbox
            SET sent_at = @Now,
                locked_until = NULL,
                locked_by = NULL,
                last_attempt_at = @Now,
                attempt_count = attempt_count + 1
            WHERE id = @Id AND locked_by = @LockedBy
            """;

        var now = _timeProvider.GetUtcNow();
        var connectionProvider = provider.GetRequiredService<IPostgresConnectionProvider>();
        var connectionHandle = await connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new { Id = id, LockedBy = _lockId, Now = now }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            await connectionHandle.Connection.ExecuteAsync(command);
        }
    }

    private async Task MarkAsFailedAsync(OutboxEntry entry, Exception exception, IServiceProvider provider, CancellationToken cancellationToken)
    {
        var attemptCount = entry.AttemptCount + 1;
        var isFinalFailure = attemptCount >= _options.MaxAttempts;
        var now = _timeProvider.GetUtcNow();

        // Exponential backoff: InitialDelay * 2^(attempt - 1), safely capped to prevent overflow
        var backoffMultiplier = Math.Pow(2, attemptCount - 1);
        var maxDelayTicks = TimeSpan.FromDays(7).Ticks;
        var delayTicks = Math.Min(_options.InitialRetryDelay.Ticks * backoffMultiplier, maxDelayTicks);
        var availableAt = isFinalFailure ? now : now.AddTicks((long)delayTicks);

        const string sql = """
            UPDATE ashlar_email_outbox
            SET failed_at = @FailedAt,
                last_error = @LastError,
                available_at = @AvailableAt,
                locked_until = NULL,
                locked_by = NULL,
                last_attempt_at = @Now,
                attempt_count = @AttemptCount
            WHERE id = @Id AND locked_by = @LockedBy
            """;

        var lastError = exception.ToString();
        if (lastError.Length > 1000)
        {
            lastError = lastError[..1000];
        }

        var connectionProvider = provider.GetRequiredService<IPostgresConnectionProvider>();
        var connectionHandle = await connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new
            {
                entry.Id,
                LockedBy = _lockId,
                FailedAt = isFinalFailure ? now : (DateTimeOffset?)null,
                LastError = lastError,
                AvailableAt = availableAt,
                Now = now,
                AttemptCount = attemptCount
            }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);

            await connectionHandle.Connection.ExecuteAsync(command);
        }
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
        /// <summary>
        /// Gets or sets the id value.
        /// </summary>
        public Guid Id { get; init; }
        /// <summary>
        /// Gets or sets the to address value.
        /// </summary>
        public required string ToAddress { get; init; }
        /// <summary>
        /// Gets or sets the from address value.
        /// </summary>
        public string? FromAddress { get; init; }
        /// <summary>
        /// Gets or sets the reply to address value.
        /// </summary>
        public string? ReplyToAddress { get; init; }
        /// <summary>
        /// Gets or sets the subject value.
        /// </summary>
        public required string Subject { get; init; }
        /// <summary>
        /// Gets or sets the text body value.
        /// </summary>
        public string? TextBody { get; init; }
        /// <summary>
        /// Gets or sets the html body value.
        /// </summary>
        public string? HtmlBody { get; init; }
        /// <summary>
        /// Gets or sets the headers value.
        /// </summary>
        public string? Headers { get; init; }
        /// <summary>
        /// Gets or sets the metadata value.
        /// </summary>
        public string? Metadata { get; init; }
        /// <summary>
        /// Gets or sets the attempt count value.
        /// </summary>
        public int AttemptCount { get; init; }
    }
}
