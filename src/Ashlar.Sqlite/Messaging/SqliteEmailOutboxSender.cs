using Ashlar.Messaging;
using Ashlar.Security.Encryption;
using System.Text.Json;

namespace Ashlar.Sqlite.Messaging;

internal sealed class SqliteEmailOutboxSender(
    ISqliteConnectionProvider connectionProvider,
    TimeProvider timeProvider,
    ISecretProtector? secretProtector = null) : ITransactionalEmailOutboxSender
{
    private readonly ISqliteConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    private readonly ISecretProtector? _secretProtector = secretProtector;

    public async Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);

        const string sql = """
            INSERT INTO ashlar_email_outbox (
                id, to_address, from_address, reply_to_address, cc_address, bcc_address, subject, text_body, html_body, sensitivity, body_protection, headers, metadata, created_at, available_at
            ) VALUES (
                $id, $to, $from, $replyTo, $cc, $bcc, $subject, $textBody, $htmlBody, $sensitivity, $bodyProtection, $headers, $metadata, $createdAt, $availableAt
            )
            """;

        var now = _timeProvider.GetUtcNow();
        var storedBodies = EmailOutboxDispatch.ProtectBodiesForStorage(message, _secretProtector);
        await using var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = connectionHandle.Connection.CreateCommand();
        command.Transaction = connectionHandle.Transaction;
        command.CommandText = sql;
        command.AddGuidParameter("$id", Guid.NewGuid());
        command.AddParameter("$to", message.To);
        command.AddParameter("$from", message.From);
        command.AddParameter("$replyTo", message.ReplyTo);
        command.AddParameter("$cc", message.Cc);
        command.AddParameter("$bcc", message.Bcc);
        command.AddParameter("$subject", message.Subject);
        command.AddParameter("$textBody", storedBodies.TextBody);
        command.AddParameter("$htmlBody", storedBodies.HtmlBody);
        command.AddParameter("$sensitivity", message.Sensitivity.ToString());
        command.AddParameter("$bodyProtection", storedBodies.BodyProtection.ToString());
        command.AddParameter("$headers", message.Headers != null ? JsonSerializer.Serialize(message.Headers) : null);
        command.AddParameter("$metadata", message.Metadata != null ? JsonSerializer.Serialize(message.Metadata) : null);
        command.AddDateTimeOffsetParameter("$createdAt", now);
        command.AddDateTimeOffsetParameter("$availableAt", now);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
