using Ashlar.Messaging;
using System.Text.Json;

namespace Ashlar.Sqlite.Messaging;

/// <summary>
/// A SQLite-backed implementation of <see cref="IEmailSender"/> that persists messages to an outbox table.
/// </summary>
/// <param name="connectionProvider">The connection provider value.</param>
/// <param name="timeProvider">The time provider value.</param>
public sealed class SqliteEmailOutboxSender(
    ISqliteConnectionProvider connectionProvider,
    TimeProvider timeProvider) : IEmailSender
{
    private readonly ISqliteConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

    /// <summary>
    /// Stores an email message in the SQLite outbox.
    /// </summary>
    /// <param name="message">The email message.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task that represents the asynchronous send operation.</returns>
    public async Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);

        const string sql = """
            INSERT INTO ashlar_email_outbox (
                id, to_address, from_address, reply_to_address, subject, text_body, html_body, headers, metadata, created_at, available_at
            ) VALUES (
                $id, $to, $from, $replyTo, $subject, $textBody, $htmlBody, $headers, $metadata, $createdAt, $availableAt
            )
            """;

        var now = _timeProvider.GetUtcNow();
        await using var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = connectionHandle.Connection.CreateCommand();
        command.Transaction = connectionHandle.Transaction;
        command.CommandText = sql;
        command.AddGuidParameter("$id", Guid.NewGuid());
        command.AddParameter("$to", message.To);
        command.AddParameter("$from", message.From);
        command.AddParameter("$replyTo", message.ReplyTo);
        command.AddParameter("$subject", message.Subject);
        command.AddParameter("$textBody", message.TextBody);
        command.AddParameter("$htmlBody", message.HtmlBody);
        command.AddParameter("$headers", message.Headers != null ? JsonSerializer.Serialize(message.Headers) : null);
        command.AddParameter("$metadata", message.Metadata != null ? JsonSerializer.Serialize(message.Metadata) : null);
        command.AddDateTimeOffsetParameter("$createdAt", now);
        command.AddDateTimeOffsetParameter("$availableAt", now);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}






