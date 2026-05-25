using Ashlar.Messaging;
using Ashlar.Security.Encryption;
using Dapper;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Ashlar.Postgres.Messaging;

/// <summary>
/// A PostgreSQL-backed implementation of <see cref="IEmailOutboxDispatcher"/> that dispatches pending email messages.
/// </summary>
/// <typeparam name="TTransport">The transport type.</typeparam>
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

    /// <summary>
    /// Processes a single batch of pending email messages.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
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
                  AND (locked_until IS NULL OR locked_until <= @Now)
                ORDER BY available_at, id
                LIMIT @BatchSize
                FOR UPDATE SKIP LOCKED
            )
            RETURNING id AS Id, to_address AS ToAddress, from_address AS FromAddress,
                      reply_to_address AS ReplyToAddress, cc_address AS CcAddress,
                      bcc_address AS BccAddress, subject AS Subject,
                      text_body AS TextBody, html_body AS HtmlBody,
                      sensitivity AS Sensitivity, body_protection AS BodyProtection,
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

                entries = (await connectionHandle.Connection.QueryAsync<PostgresEmailOutboxEntry>(command))
                    .Select(entry => entry.ToEmailOutboxEntry())
                    .ToList();
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
        await EmailOutboxDispatch.DispatchAsync(
            entry,
            new EmailOutboxDispatchContext(
                provider.GetRequiredService<TTransport>(),
                _options.MaxAttempts,
                (id, token) => MarkAsSentAsync(id, provider, token),
                (failedEntry, exception, token) => MarkAsFailedAsync(failedEntry, exception, provider, token),
                (id, attemptCount, finalFailure, exception) =>
                    PostgresEmailOutboxDispatcherLog.EmailOutboxDeliveryFailed(_logger, id, attemptCount, finalFailure, exception),
                provider.GetService<ISecretProtector>()),
            cancellationToken);
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
            exception,
            EmailOutboxDispatch.ShouldSuppressFailureDetails(entry));

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

internal sealed class PostgresEmailOutboxEntry
{
    public Guid Id { get; init; }
    public required string ToAddress { get; init; }
    public string? FromAddress { get; init; }
    public string? ReplyToAddress { get; init; }
    public string? CcAddress { get; init; }
    public string? BccAddress { get; init; }
    public required string Subject { get; init; }
    public string? TextBody { get; init; }
    public string? HtmlBody { get; init; }
    public string? Sensitivity { get; init; }
    public string? BodyProtection { get; init; }
    public string? Headers { get; init; }
    public string? Metadata { get; init; }
    public int AttemptCount { get; init; }

    public EmailOutboxEntry ToEmailOutboxEntry()
    {
        return new EmailOutboxEntry
        {
            Id = Id,
            ToAddress = ToAddress,
            FromAddress = FromAddress,
            ReplyToAddress = ReplyToAddress,
            CcAddress = CcAddress,
            BccAddress = BccAddress,
            Subject = Subject,
            TextBody = TextBody,
            HtmlBody = HtmlBody,
            Sensitivity = EmailOutboxDispatch.ParseSensitivity(Sensitivity),
            BodyProtection = EmailOutboxDispatch.ParseBodyProtection(BodyProtection),
            Headers = Headers,
            Metadata = Metadata,
            AttemptCount = AttemptCount
        };
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
