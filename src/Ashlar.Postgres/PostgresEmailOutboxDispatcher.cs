using Ashlar.Messaging;
using Dapper;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using System.Text.Json;

namespace Ashlar.Postgres;

/// <summary>
/// A background service that dispatches pending email messages from the PostgreSQL outbox.
/// </summary>
/// <typeparam name="TTransport">The type of <see cref="IEmailTransport"/> to use for delivery.</typeparam>
public sealed class PostgresEmailOutboxDispatcher<TTransport>(
    IServiceProvider serviceProvider,
    IOptions<PostgresEmailOutboxOptions> options) : BackgroundService
    where TTransport : IEmailTransport
{
    private readonly IServiceProvider _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
    private readonly PostgresEmailOutboxOptions _options = (options ?? throw new ArgumentNullException(nameof(options))).Value;
    private readonly string _lockId = Guid.NewGuid().ToString();

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!PostgresEmailOutboxOptions.Validate(_options))
        {
            throw new InvalidOperationException("Email outbox options are invalid.");
        }

        // TODO: Add logging for dispatcher start

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var processedCount = await ProcessBatchAsync(stoppingToken);

                if (processedCount < _options.BatchSize)
                {
                    await Task.Delay(_options.PollingInterval, stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception)
            {
                // TODO: Add logging for batch error
                if (!await DelayUntilNextPollAsync(_options.PollingInterval, stoppingToken))
                {
                    break;
                }
            }
        }

        // TODO: Add logging for dispatcher stop
    }

    private static async ValueTask<bool> DelayUntilNextPollAsync(TimeSpan delay, CancellationToken stoppingToken)
    {
        try
        {
            await Task.Delay(delay, stoppingToken);
            return true;
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            return false;
        }
    }

    internal async Task<int> ProcessBatchAsync(CancellationToken cancellationToken)
    {
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

        var now = DateTimeOffset.UtcNow;
        var lockedUntil = now.Add(_options.LockDuration);

        List<OutboxEntry> entries;
        using (var scope = _serviceProvider.CreateScope())
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
            using var scope = _serviceProvider.CreateScope();
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

        var connectionProvider = provider.GetRequiredService<IPostgresConnectionProvider>();
        var connectionHandle = await connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new { Id = id, LockedBy = _lockId, Now = DateTimeOffset.UtcNow }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            await connectionHandle.Connection.ExecuteAsync(command);
        }
    }

    private async Task MarkAsFailedAsync(OutboxEntry entry, Exception exception, IServiceProvider provider, CancellationToken cancellationToken)
    {
        var attemptCount = entry.AttemptCount + 1;
        var isFinalFailure = attemptCount >= _options.MaxAttempts;
        var now = DateTimeOffset.UtcNow;

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
