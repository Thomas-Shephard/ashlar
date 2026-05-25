using Ashlar.Messaging;
using Ashlar.Security.Encryption;
using Dapper;
using System.Text.Json;

namespace Ashlar.Postgres.Messaging;

/// <summary>
/// A PostgreSQL-backed implementation of <see cref="IEmailSender"/> that persists messages to an outbox table.
/// </summary>
/// <param name="connectionProvider">The connection provider value.</param>
/// <param name="timeProvider">The time provider value.</param>
/// <param name="secretProtector">The optional secret protector used for sensitive message bodies.</param>
public sealed class PostgresEmailOutboxSender(
    IPostgresConnectionProvider connectionProvider,
    TimeProvider timeProvider,
    ISecretProtector? secretProtector = null) : ITransactionalEmailOutboxSender
{
    private readonly IPostgresConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    private readonly ISecretProtector? _secretProtector = secretProtector;

    /// <summary>
    /// Stores an email message in the PostgreSQL outbox.
    /// </summary>
    /// <param name="message">The email message.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task that represents the asynchronous send operation.</returns>
    public async Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);

        const string sql = """
            INSERT INTO ashlar_email_outbox (
                id, to_address, from_address, reply_to_address, cc_address, bcc_address, subject, text_body, html_body, sensitivity, body_protection, headers, metadata, created_at, available_at
            ) VALUES (
                @Id, @To, @From, @ReplyTo, @Cc, @Bcc, @Subject, @TextBody, @HtmlBody, @Sensitivity, @BodyProtection, @Headers::jsonb, @Metadata::jsonb, @CreatedAt, @AvailableAt
            )
            """;

        var id = Guid.NewGuid();
        var now = _timeProvider.GetUtcNow();
        var headersJson = message.Headers != null ? JsonSerializer.Serialize(message.Headers) : null;
        var metadataJson = message.Metadata != null ? JsonSerializer.Serialize(message.Metadata) : null;
        var storedBodies = EmailOutboxDispatch.ProtectBodiesForStorage(message, _secretProtector);

        var parameters = new
        {
            Id = id,
            message.To,
            message.From,
            message.ReplyTo,
            message.Cc,
            message.Bcc,
            message.Subject,
            storedBodies.TextBody,
            storedBodies.HtmlBody,
            Sensitivity = message.Sensitivity.ToString(),
            BodyProtection = storedBodies.BodyProtection.ToString(),
            Headers = headersJson,
            Metadata = metadataJson,
            CreatedAt = now,
            AvailableAt = now
        };

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, parameters, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            await connectionHandle.Connection.ExecuteAsync(command);
        }
    }
}
