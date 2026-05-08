using Ashlar.Messaging;
using Dapper;
using System.Text.Json;

namespace Ashlar.Postgres;

/// <summary>
/// A PostgreSQL-backed implementation of <see cref="IEmailSender"/> that persists messages to an outbox table.
/// </summary>
public sealed class PostgresEmailOutboxSender(IPostgresConnectionProvider connectionProvider) : IEmailSender
{
    private readonly IPostgresConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));

    /// <inheritdoc />
    public async Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);

        const string sql = """
            INSERT INTO ashlar_email_outbox (
                id, to_address, from_address, reply_to_address, subject, text_body, html_body, headers, metadata, created_at, available_at
            ) VALUES (
                @Id, @To, @From, @ReplyTo, @Subject, @TextBody, @HtmlBody, @Headers::jsonb, @Metadata::jsonb, @CreatedAt, @AvailableAt
            )
            """;

        var id = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        var headersJson = message.Headers != null ? JsonSerializer.Serialize(message.Headers) : null;
        var metadataJson = message.Metadata != null ? JsonSerializer.Serialize(message.Metadata) : null;

        var parameters = new
        {
            Id = id,
            message.To,
            message.From,
            message.ReplyTo,
            message.Subject,
            message.TextBody,
            message.HtmlBody,
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
