using Ashlar.Messaging;
using Dapper;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Ashlar.Postgres;

/// <summary>
/// A PostgreSQL-backed implementation of <see cref="IEmailOutboxDispatcher"/> that dispatches pending email messages.
/// </summary>
/// <typeparam name="TTransport">The ttransport type.</typeparam>
/// <param name="serviceProvider">The service provider value.</param>
/// <param name="timeProvider">The time provider value.</param>
/// <param name="options">The options value.</param>
/// <param name="logger">The logger value.</param>
public sealed class PostgresEmailOutboxDispatcher<TTransport>(
    IServiceProvider serviceProvider,
    TimeProvider timeProvider,
    IOptions<PostgresEmailOutboxOptions> options,
    ILogger<PostgresEmailOutboxDispatcher<TTransport>>? logger = null) : IEmailOutboxDispatcher
    where TTransport : IEmailTransport
{
    private readonly IServiceProvider _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    private readonly PostgresEmailOutboxOptions _options = (options ?? throw new ArgumentNullException(nameof(options))).Value;
    private readonly ILogger<PostgresEmailOutboxDispatcher<TTransport>> _logger = logger ?? NullLogger<PostgresEmailOutboxDispatcher<TTransport>>.Instance;
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
                ORDER BY available_at, id
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

        List<EmailOutboxEntry> entries;
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

                entries = (await connectionHandle.Connection.QueryAsync<EmailOutboxEntry>(command)).ToList();
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
            PostgresEmailOutboxDispatcherLog.EmailOutboxDeliveryFailed(_logger, entry.Id, attemptCount, attemptCount >= _options.MaxAttempts, ex);
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

    private async Task MarkAsFailedAsync(EmailOutboxEntry entry, Exception exception, IServiceProvider provider, CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();
        var failure = EmailOutboxDispatch.CreateFailureUpdate(
            entry.AttemptCount,
            _options.MaxAttempts,
            _options.InitialRetryDelay,
            now,
            exception);

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

        var connectionProvider = provider.GetRequiredService<IPostgresConnectionProvider>();
        var connectionHandle = await connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new
            {
                entry.Id,
                LockedBy = _lockId,
                failure.FailedAt,
                failure.LastError,
                failure.AvailableAt,
                Now = now,
                failure.AttemptCount
            }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);

            await connectionHandle.Connection.ExecuteAsync(command);
        }
    }

}

internal static class PostgresEmailOutboxDispatcherLog
{
    public static readonly Action<ILogger, Guid, int, bool, Exception?> EmailOutboxDeliveryFailed =
        LoggerMessage.Define<Guid, int, bool>(
            LogLevel.Warning,
            new EventId(1000, nameof(EmailOutboxDeliveryFailed)),
            "Email outbox delivery failed. MessageId={MessageId} AttemptCount={AttemptCount} FinalFailure={FinalFailure}");
}
