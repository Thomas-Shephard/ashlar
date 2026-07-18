using Dapper;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Postgres.Tests.Webhooks;

internal sealed class PostgresSecurityEventWebhookOutboxContractTests : SecurityEventWebhookOutboxContractTests
{
    private PostgresContractDatabaseLease? _database;

    protected override async Task<IServiceProvider> CreateInitializedServiceProviderAsync()
    {
        _database = await PostgresContractDatabase.CreateInitializedServiceProviderAsync(services =>
        {
            services.AddSingleton<TimeProvider>(new FakeTimeProvider(Now));
            services.AddAshlarPostgresAuditSink();
            services.AddAshlarSecurityEventWebhookOutbox(options =>
            {
                options.Endpoints.Add(new AshlarSecurityEventWebhookEndpointOptions
                {
                    Name = "audit",
                    Uri = new Uri("https://example.test/security-events"),
                    SharedSecret = "shared-secret"
                });
            });
            services.AddAshlarPostgresSecurityEventWebhookOutbox();
            services.AddPostgresWebhookProviderContractTestService();
        });
        return _database.ServiceProvider;
    }

    protected override async Task CleanupInitializedServiceProviderAsync()
    {
        if (_database != null)
        {
            await _database.DropDatabaseAsync();
            _database = null;
        }
    }

    protected override async Task<Guid> SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow row)
    {
        var id = Guid.NewGuid();
        await using var connection = new Npgsql.NpgsqlConnection(_database!.ConnectionString);
        await connection.OpenAsync();
        await connection.ExecuteAsync("""
            INSERT INTO ashlar_security_event_webhook_outbox (
                id, endpoint_name, uri, event_id, event_type, outcome, occurred_at, timeout_ms, body, headers,
                created_at, available_at, sent_at, failed_at, discarded_at, locked_by, locked_until, last_attempt_at, attempt_count, last_error)
            VALUES (
                @id, @endpointName, 'https://example.test/security-events', @eventId, 'security.test', 'success', @createdAt, 1000, @body, @headers::jsonb,
                @createdAt, @availableAt, @sentAt, @failedAt, @discardedAt, @lockedBy, @lockedUntil, @failedAt, @attemptCount, @lastError);
            """, new
        {
            id,
            endpointName = row.EndpointName,
            row.EventId,
            createdAt = row.CreatedAt,
            availableAt = row.AvailableAt,
            row.SentAt,
            row.FailedAt,
            row.DiscardedAt,
            row.LockedBy,
            row.LockedUntil,
            body = row.Body,
            headers = "{}",
            attemptCount = row.AttemptCount,
            row.LastError
        });
        return id;
    }

    protected override async Task<WebhookOutboxRowState> ReadWebhookOutboxRowStateAsync(Guid id)
    {
        await using var connection = new Npgsql.NpgsqlConnection(_database!.ConnectionString);
        await connection.OpenAsync();
        var row = await connection.QuerySingleAsync<OutboxStateRow>("""
            SELECT available_at AS AvailableAt, sent_at AS SentAt, failed_at AS FailedAt, discarded_at AS DiscardedAt,
                   locked_by AS LockedBy, locked_until AS LockedUntil, last_error AS LastError
            FROM ashlar_security_event_webhook_outbox
            WHERE id = @id
            """, new { id });
        return new WebhookOutboxRowState(
            PostgresAdminQuery.ToDateTimeOffset(row.AvailableAt),
            PostgresAdminQuery.ToNullableDateTimeOffset(row.SentAt),
            PostgresAdminQuery.ToNullableDateTimeOffset(row.FailedAt),
            PostgresAdminQuery.ToNullableDateTimeOffset(row.DiscardedAt),
            row.LockedBy,
            PostgresAdminQuery.ToNullableDateTimeOffset(row.LockedUntil),
            row.LastError);
    }

    protected override async Task<int> CountWebhookOutboxRowsAsync()
    {
        await using var connection = new Npgsql.NpgsqlConnection(_database!.ConnectionString);
        await connection.OpenAsync();
        return await connection.ExecuteScalarAsync<int>("SELECT count(*) FROM ashlar_security_event_webhook_outbox;");
    }

    protected override async Task<int> CountSecurityEventRowsAsync()
    {
        await using var connection = new Npgsql.NpgsqlConnection(_database!.ConnectionString);
        await connection.OpenAsync();
        return await connection.ExecuteScalarAsync<int>("SELECT count(*) FROM ashlar_security_events;");
    }

    protected override async Task DropWebhookOutboxTableInCurrentTransactionAsync(IServiceProvider serviceProvider)
    {
        var connectionProvider = serviceProvider.GetRequiredService<IPostgresConnectionProvider>();
        await using var connectionHandle = await connectionProvider.GetConnectionAsync(CancellationToken.None);
        await connectionHandle.Connection.ExecuteAsync(new CommandDefinition(
            "DROP TABLE ashlar_security_event_webhook_outbox;",
            transaction: connectionHandle.Transaction));
    }

    protected override async Task AssertSentAndDiscardedTerminalStateIsRejectedAsync()
    {
        await using var connection = new Npgsql.NpgsqlConnection(_database!.ConnectionString);
        await connection.OpenAsync();

        var exception = Assert.ThrowsAsync<Npgsql.PostgresException>(async () => await connection.ExecuteAsync("""
            INSERT INTO ashlar_security_event_webhook_outbox (
                id, endpoint_name, uri, event_id, event_type, outcome, occurred_at, timeout_ms, body, headers,
                created_at, available_at, sent_at, discarded_at)
            VALUES (
                @id, 'conflict', 'https://example.test/security-events', @eventId, 'security.test', 'success', @now, 1000, @body, @headers::jsonb,
                @now, @now, @now, @now);
            """, new
        {
            id = Guid.NewGuid(),
            eventId = Guid.NewGuid(),
            now = Now,
            body = new byte[] { 1, 2, 3 },
            headers = "{}"
        }));
        Assert.That(exception!.ConstraintName, Is.EqualTo("ck_ashlar_security_event_webhook_outbox_terminal_state"));
    }

    private sealed class OutboxStateRow
    {
        public DateTime AvailableAt { get; init; }
        public DateTime? SentAt { get; init; }
        public DateTime? FailedAt { get; init; }
        public DateTime? DiscardedAt { get; init; }
        public string? LockedBy { get; init; }
        public DateTime? LockedUntil { get; init; }
        public string? LastError { get; init; }
    }
}
