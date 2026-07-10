using Ashlar.Messaging;
using Dapper;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Npgsql;

namespace Ashlar.Postgres.Tests.Messaging;

internal sealed class PostgresEmailOutboxAdministrationContractTests : EmailOutboxAdministrationContractTests
{
    private PostgresContractDatabaseLease? _database;

    protected override async Task<IServiceProvider> CreateInitializedServiceProviderAsync()
    {
        _database = await PostgresContractDatabase.CreateInitializedServiceProviderAsync(services =>
        {
            services.AddSingleton<TimeProvider>(new FakeTimeProvider(AdminNow));
            services.AddAshlarPostgresEmailOutboxSender();
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

    protected override async Task<Guid> SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow row)
    {
        await using var connection = new NpgsqlConnection(_database!.ConnectionString);
        await connection.OpenAsync();
        await connection.ExecuteAsync(
            """
            INSERT INTO ashlar_email_outbox (
                id, to_address, from_address, reply_to_address, cc_address, subject, text_body, html_body, sensitivity, body_protection,
                created_at, available_at, sent_at, failed_at, discarded_at, locked_by, locked_until,
                attempt_count, last_error
            ) VALUES (
                @Id, @ToAddress, @FromAddress, @ReplyToAddress, @CcAddress, @Subject, @TextBody, @HtmlBody, @Sensitivity, @BodyProtection,
                @CreatedAt, @AvailableAt, @SentAt, @FailedAt, @DiscardedAt, @LockedBy, @LockedUntil,
                @AttemptCount, @LastError
            );
            """,
            row);
        return row.Id;
    }

    protected override async Task<EmailOutboxAdminRowState> ReadEmailOutboxAdminRowStateAsync(Guid id)
    {
        await using var connection = new NpgsqlConnection(_database!.ConnectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT available_at AS AvailableAt, failed_at AS FailedAt, discarded_at AS DiscardedAt,
                   locked_by AS LockedBy, locked_until AS LockedUntil, last_error AS LastError
            FROM ashlar_email_outbox
            WHERE id = @id;
            """;
        command.Parameters.AddWithValue("id", id);
        await using var reader = await command.ExecuteReaderAsync();
        Assert.That(await reader.ReadAsync(), Is.True);
        return new EmailOutboxAdminRowState(
            reader.GetFieldValue<DateTimeOffset>(reader.GetOrdinal("availableat")),
            reader.IsDBNull(reader.GetOrdinal("failedat")) ? null : reader.GetFieldValue<DateTimeOffset>(reader.GetOrdinal("failedat")),
            reader.IsDBNull(reader.GetOrdinal("discardedat")) ? null : reader.GetFieldValue<DateTimeOffset>(reader.GetOrdinal("discardedat")),
            reader.IsDBNull(reader.GetOrdinal("lockedby")) ? null : reader.GetString(reader.GetOrdinal("lockedby")),
            reader.IsDBNull(reader.GetOrdinal("lockeduntil")) ? null : reader.GetFieldValue<DateTimeOffset>(reader.GetOrdinal("lockeduntil")),
            reader.IsDBNull(reader.GetOrdinal("lasterror")) ? null : reader.GetString(reader.GetOrdinal("lasterror")));
    }

    [Test]
    public void ConstructorRejectsMissingDependencies()
    {
        var provider = _database!.ServiceProvider;
        var connectionProvider = provider.GetRequiredService<IPostgresConnectionProvider>();
        var audit = provider.GetRequiredService<ISecurityEventSink>();
        var transactionProvider = provider.GetRequiredService<IAshlarTransactionProvider>();
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => new PostgresEmailOutboxAdministrationService(null!, TimeProvider.System, audit, transactionProvider));
            Assert.Throws<ArgumentNullException>(() => new PostgresEmailOutboxAdministrationService(connectionProvider, null!, audit, transactionProvider));
            Assert.Throws<ArgumentNullException>(() => new PostgresEmailOutboxAdministrationService(connectionProvider, TimeProvider.System, null!, transactionProvider));
            Assert.Throws<ArgumentNullException>(() => new PostgresEmailOutboxAdministrationService(connectionProvider, TimeProvider.System, audit, null!));
            Assert.DoesNotThrow(() => new PostgresEmailOutboxAdministrationService(connectionProvider, TimeProvider.System, audit, transactionProvider));
        }
    }

    [Test]
    public async Task GetAsyncHandlesInvalidAndMissingIds()
    {
        var admin = _database!.ServiceProvider.GetRequiredService<IEmailOutboxAdministrationService>();

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentException>(() => admin.GetAsync(Guid.Empty));
            Assert.That(await admin.GetAsync(Guid.NewGuid()), Is.Null);
        }
    }

    [Test]
    public async Task DetailProjectionCoversOptionalContentFlags()
    {
        var id = Guid.NewGuid();
        await using var connection = new NpgsqlConnection(_database!.ConnectionString);
        await connection.OpenAsync();
        await connection.ExecuteAsync(
            """
            INSERT INTO ashlar_email_outbox (
                id, to_address, subject, text_body, html_body, headers, metadata,
                sensitivity, body_protection, created_at, available_at
            ) VALUES (
                @id, 'content@example.com', 'Content', 'text', '<p>html</p>', @headers::jsonb, @metadata::jsonb,
                'Normal', 'None', @now, @now
            );
            """,
            new { id, now = AdminNow, headers = """{"X-Test":"1"}""", metadata = """{"trace":"1"}""" });

        var detail = await _database.ServiceProvider.GetRequiredService<IEmailOutboxAdministrationService>().GetAsync(id);
        var empty = await SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow.Pending("empty@example.com", textBody: null, htmlBody: null));
        var emptyDetail = await _database.ServiceProvider.GetRequiredService<IEmailOutboxAdministrationService>().GetAsync(empty);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(detail, Is.Not.Null);
            Assert.That(detail!.HasTextBody, Is.True);
            Assert.That(detail.HasHtmlBody, Is.True);
            Assert.That(emptyDetail, Is.Not.Null);
            Assert.That(emptyDetail!.HasTextBody, Is.False);
            Assert.That(emptyDetail.HasHtmlBody, Is.False);
        }
    }

    [Test]
    public async Task RetryAuditFailureFailsCaller()
    {
        var originalAvailableAt = AdminNow.AddMinutes(-10);
        var id = await SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow.Failed("audit@example.com", availableAt: originalAvailableAt));
        var admin = new PostgresEmailOutboxAdministrationService(
            _database!.ServiceProvider.GetRequiredService<IPostgresConnectionProvider>(),
            _database.ServiceProvider.GetRequiredService<TimeProvider>(),
            new ThrowingSecurityEventSink(new InvalidOperationException("audit failed")),
            _database.ServiceProvider.GetRequiredService<IAshlarTransactionProvider>());

        Assert.ThrowsAsync<InvalidOperationException>(async () => await admin.RetryAsync(new EmailOutboxOperationRequest(id, new AuditContext(Guid.NewGuid()))));
        var state = await ReadEmailOutboxAdminRowStateAsync(id);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(state.FailedAt, Is.Not.Null);
            Assert.That(state.LastError, Is.Not.Null);
            Assert.That(state.AvailableAt, Is.EqualTo(originalAvailableAt));
        }
    }

    [Test]
    public async Task DiscardAuditFailureRollsBackMutation()
    {
        var id = await SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow.Failed("audit-discard-failure@example.com"));
        var admin = new PostgresEmailOutboxAdministrationService(
            _database!.ServiceProvider.GetRequiredService<IPostgresConnectionProvider>(),
            _database.ServiceProvider.GetRequiredService<TimeProvider>(),
            new ThrowingSecurityEventSink(new InvalidOperationException("audit failed")),
            _database.ServiceProvider.GetRequiredService<IAshlarTransactionProvider>());

        Assert.ThrowsAsync<InvalidOperationException>(async () => await admin.DiscardAsync(new EmailOutboxOperationRequest(id, new AuditContext(Guid.NewGuid()))));
        var state = await ReadEmailOutboxAdminRowStateAsync(id);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(state.FailedAt, Is.Not.Null);
            Assert.That(state.DiscardedAt, Is.Null);
        }
    }

    [Test]
    public async Task RetryAuditCancellationFailureFailsCaller()
    {
        var id = await SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow.Failed("audit-canceled@example.com"));
        var admin = new PostgresEmailOutboxAdministrationService(
            _database!.ServiceProvider.GetRequiredService<IPostgresConnectionProvider>(),
            _database.ServiceProvider.GetRequiredService<TimeProvider>(),
            new ThrowingSecurityEventSink(new OperationCanceledException("audit canceled")),
            _database.ServiceProvider.GetRequiredService<IAshlarTransactionProvider>());

        Assert.ThrowsAsync<OperationCanceledException>(async () => await admin.RetryAsync(new EmailOutboxOperationRequest(id, new AuditContext(Guid.NewGuid()))));
    }

    [Test]
    public async Task RetryAndDiscardRecordSafeAuditEvents()
    {
        var retryId = await SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow.Failed("audit-retry@example.com"));
        var discardId = await SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow.Failed("audit-discard@example.com"));
        var sink = new RecordingSecurityEventSink();
        var admin = new PostgresEmailOutboxAdministrationService(
            _database!.ServiceProvider.GetRequiredService<IPostgresConnectionProvider>(),
            _database.ServiceProvider.GetRequiredService<TimeProvider>(),
            sink,
            _database.ServiceProvider.GetRequiredService<IAshlarTransactionProvider>());
        var actorId = Guid.NewGuid();
        var audit = new AuditContext(actorId, "203.0.113.10", "audit-agent", "audit-correlation");

        await admin.RetryAsync(new EmailOutboxOperationRequest(retryId, audit));
        await admin.DiscardAsync(new EmailOutboxOperationRequest(discardId, audit));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(sink.Events, Has.Count.EqualTo(2));
            Assert.That(sink.Events.Select(static securityEvent => securityEvent.EventType), Is.EqualTo(new[]
            {
                AshlarSecurityEventTypes.EmailOutboxDeliveryRetried,
                AshlarSecurityEventTypes.EmailOutboxDeliveryDiscarded
            }));
            Assert.That(sink.Events.Select(static securityEvent => securityEvent.ActorUserId), Is.All.EqualTo(actorId));
            Assert.That(sink.Events.Select(static securityEvent => securityEvent.IpAddress), Is.All.EqualTo("203.0.113.10"));
            Assert.That(sink.Events.Select(static securityEvent => securityEvent.UserAgent), Is.All.EqualTo("audit-agent"));
            Assert.That(sink.Events.Select(static securityEvent => securityEvent.CorrelationId), Is.All.EqualTo("audit-correlation"));
            Assert.That(sink.Events.Select(static securityEvent => securityEvent.Outcome), Is.All.EqualTo(SecurityEventOutcomes.Success));
            Assert.That(sink.Events[0].Properties, Is.EquivalentTo(new Dictionary<string, string> { ["email_outbox_id"] = retryId.ToString("D") }));
            Assert.That(sink.Events[1].Properties, Is.EquivalentTo(new Dictionary<string, string> { ["email_outbox_id"] = discardId.ToString("D") }));
        }
    }

    private sealed class ThrowingSecurityEventSink(Exception exception) : ISecurityEventSink
    {
        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            throw exception;
        }
    }

    private sealed class RecordingSecurityEventSink : ISecurityEventSink
    {
        public List<AshlarSecurityEvent> Events { get; } = [];

        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            Events.Add(securityEvent);
            return Task.CompletedTask;
        }
    }
}
