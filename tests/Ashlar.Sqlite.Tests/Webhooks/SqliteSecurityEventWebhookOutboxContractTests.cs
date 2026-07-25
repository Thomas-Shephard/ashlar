using System.Globalization;
using Ashlar.Webhooks.SecurityEvents;
using Ashlar.Identity.Abstractions.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Sqlite.Tests.Webhooks;

internal sealed class SqliteSecurityEventWebhookOutboxContractTests : SecurityEventWebhookOutboxContractTests
{
    private const string ValidSecret = "0123456789abcdef0123456789abcdef";

    private SqliteContractDatabase? _database;

    protected override async Task<IServiceProvider> CreateInitializedServiceProviderAsync()
    {
        _database = await SqliteContractDatabase.CreateAsync(services =>
        {
            services.AddSingleton<TimeProvider>(new FakeTimeProvider(Now));
            services.AddAshlarSqliteAuditSink();
            services.AddAshlarSecurityEventWebhookOutbox(options =>
            {
                options.Endpoints.Add(new AshlarSecurityEventWebhookEndpointOptions
                {
                    Name = "audit",
                    Uri = new Uri("https://example.test/security-events"),
                    SharedSecret = ValidSecret
                });
            });
            services.AddAshlarSqliteSecurityEventWebhookOutbox();
            services.AddSingleton<IAuthenticationSessionRepository>(Security.Sessions);
            services.AddSingleton<IAccountSecurityOperationAuthorizer>(Security.Authorizer);
            services.AddSqliteWebhookProviderContractTestService();
        });
        return _database.ServiceProvider;
    }

    protected override Task CleanupInitializedServiceProviderAsync()
    {
        _database?.Delete();
        _database = null;
        return Task.CompletedTask;
    }

    protected override async Task<Guid> SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow row)
    {
        var id = Guid.NewGuid();
        await using var connection = new Microsoft.Data.Sqlite.SqliteConnection(_database!.ConnectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO ashlar_security_event_webhook_outbox (
                id, endpoint_name, uri, event_id, event_type, outcome, occurred_at, timeout_ms, body, headers,
                created_at, available_at, sent_at, failed_at, discarded_at, locked_by, locked_until, last_attempt_at, attempt_count, last_error)
            VALUES (
                $id, $endpointName, 'https://example.test/security-events', $eventId, 'security.test', 'success', $createdAt, 1000, $body, $headers,
                $createdAt, $availableAt, $sentAt, $failedAt, $discardedAt, $lockedBy, $lockedUntil, $failedAt, $attemptCount, $lastError);
            """;
        command.AddGuidParameter("$id", id);
        command.AddParameter("$endpointName", row.EndpointName);
        command.AddGuidParameter("$eventId", row.EventId);
        command.AddDateTimeOffsetParameter("$createdAt", row.CreatedAt);
        command.AddDateTimeOffsetParameter("$availableAt", row.AvailableAt);
        command.AddNullableDateTimeOffsetParameter("$sentAt", row.SentAt);
        command.AddNullableDateTimeOffsetParameter("$failedAt", row.FailedAt);
        command.AddNullableDateTimeOffsetParameter("$discardedAt", row.DiscardedAt);
        command.AddParameter("$lockedBy", row.LockedBy);
        command.AddNullableDateTimeOffsetParameter("$lockedUntil", row.LockedUntil);
        command.AddParameter("$body", row.Body);
        command.AddParameter("$headers", "{}");
        command.AddParameter("$attemptCount", row.AttemptCount);
        command.AddParameter("$lastError", row.LastError);
        await command.ExecuteNonQueryAsync();
        return id;
    }

    protected override async Task<WebhookOutboxRowState> ReadWebhookOutboxRowStateAsync(Guid id)
    {
        await using var connection = new Microsoft.Data.Sqlite.SqliteConnection(_database!.ConnectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT available_at, sent_at, failed_at, discarded_at, locked_by, locked_until, last_error
            FROM ashlar_security_event_webhook_outbox
            WHERE id = $id;
            """;
        command.AddGuidParameter("$id", id);
        await using var reader = await command.ExecuteReaderAsync();
        Assert.That(await reader.ReadAsync(), Is.True);
        return new WebhookOutboxRowState(
            reader.GetDateTimeOffsetFromText("available_at"),
            reader.GetNullableDateTimeOffsetFromText("sent_at"),
            reader.GetNullableDateTimeOffsetFromText("failed_at"),
            reader.GetNullableDateTimeOffsetFromText("discarded_at"),
            reader.GetNullableString("locked_by"),
            reader.GetNullableDateTimeOffsetFromText("locked_until"),
            reader.GetNullableString("last_error"));
    }

    protected override async Task<int> CountWebhookOutboxRowsAsync()
    {
        await using var connection = new Microsoft.Data.Sqlite.SqliteConnection(_database!.ConnectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT count(*) FROM ashlar_security_event_webhook_outbox;";
        return Convert.ToInt32(await command.ExecuteScalarAsync(), CultureInfo.InvariantCulture);
    }

    protected override async Task<int> CountSecurityEventRowsAsync()
    {
        await using var connection = new Microsoft.Data.Sqlite.SqliteConnection(_database!.ConnectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT count(*) FROM ashlar_security_events;";
        return Convert.ToInt32(await command.ExecuteScalarAsync(), CultureInfo.InvariantCulture);
    }

    protected override async Task DropWebhookOutboxTableInCurrentTransactionAsync(IServiceProvider serviceProvider)
    {
        var connectionProvider = serviceProvider.GetRequiredService<ISqliteConnectionProvider>();
        await using var connectionHandle = await connectionProvider.GetConnectionAsync(CancellationToken.None);
        await using var command = connectionHandle.Connection.CreateCommand();
        command.Transaction = connectionHandle.Transaction;
        command.CommandText = "DROP TABLE ashlar_security_event_webhook_outbox;";
        await command.ExecuteNonQueryAsync();
    }

    protected override async Task AssertSentAndDiscardedTerminalStateIsRejectedAsync()
    {
        await using var connection = new Microsoft.Data.Sqlite.SqliteConnection(_database!.ConnectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO ashlar_security_event_webhook_outbox (
                id, endpoint_name, uri, event_id, event_type, outcome, occurred_at, timeout_ms, body, headers,
                created_at, available_at, sent_at, discarded_at)
            VALUES (
                $id, 'conflict', 'https://example.test/security-events', $eventId, 'security.test', 'success', $now, 1000, $body, $headers,
                $now, $now, $now, $now);
            """;
        command.AddGuidParameter("$id", Guid.NewGuid());
        command.AddGuidParameter("$eventId", Guid.NewGuid());
        command.AddDateTimeOffsetParameter("$now", Now);
        command.AddParameter("$body", new byte[] { 1, 2, 3 });
        command.AddParameter("$headers", "{}");

        var exception = Assert.ThrowsAsync<Microsoft.Data.Sqlite.SqliteException>(async () => await command.ExecuteNonQueryAsync());
        Assert.That(exception!.SqliteErrorCode, Is.EqualTo(19));
    }
}
