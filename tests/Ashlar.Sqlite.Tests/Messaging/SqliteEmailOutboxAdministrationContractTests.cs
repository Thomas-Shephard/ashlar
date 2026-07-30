using Ashlar.Messaging;
using Ashlar.Operational;
using Ashlar.Testing;
using Ashlar.Identity.Abstractions.Services;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using System.Globalization;

namespace Ashlar.Sqlite.Tests.Messaging;

internal sealed class SqliteEmailOutboxAdministrationContractTests : EmailOutboxAdministrationContractTests
{
    private SqliteContractDatabase? _database;

    protected override async Task<IServiceProvider> CreateInitializedServiceProviderAsync()
    {
        _database = await SqliteContractDatabase.CreateAsync(services =>
        {
            services.AddSingleton<TimeProvider>(new FakeTimeProvider(AdminNow));
            services.AddSingleton<ISecurityEventSink, NullSecurityEventSink>();
            services.AddSingleton<IAccountSecurityOperationAuthorizer>(
                new StubAccountSecurityOperationAuthorizer { Authorized = true });
            services.AddAshlarSqliteAuditSink();
            services.AddAshlarSqliteEmailOutboxSender();
        });
        return _database.ServiceProvider;
    }

    protected override Task CleanupInitializedServiceProviderAsync()
    {
        _database?.Delete();
        _database = null;
        return Task.CompletedTask;
    }

    protected override async Task<Guid> SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow row)
    {
        await using var connection = new SqliteConnection(_database!.ConnectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO ashlar_email_outbox (
                id, to_address, from_address, reply_to_address, cc_address, subject, text_body, html_body, sensitivity, body_protection,
                created_at, available_at, sent_at, failed_at, discarded_at, locked_by, locked_until,
                attempt_count, last_error
            ) VALUES (
                $id, $toAddress, $fromAddress, $replyToAddress, $ccAddress, $subject, $textBody, $htmlBody, $sensitivity, $bodyProtection,
                $createdAt, $availableAt, $sentAt, $failedAt, $discardedAt, $lockedBy, $lockedUntil,
                $attemptCount, $lastError
            );
            """;
        command.AddGuidParameter("$id", row.Id);
        command.AddParameter("$toAddress", row.ToAddress);
        command.AddParameter("$fromAddress", row.FromAddress);
        command.AddParameter("$replyToAddress", row.ReplyToAddress);
        command.AddParameter("$ccAddress", row.CcAddress);
        command.AddParameter("$subject", row.Subject);
        command.AddParameter("$textBody", row.TextBody);
        command.AddParameter("$htmlBody", row.HtmlBody);
        command.AddParameter("$sensitivity", row.Sensitivity);
        command.AddParameter("$bodyProtection", row.BodyProtection);
        command.AddDateTimeOffsetParameter("$createdAt", row.CreatedAt);
        command.AddDateTimeOffsetParameter("$availableAt", row.AvailableAt);
        command.AddParameter("$sentAt", row.SentAt?.ToString("O", CultureInfo.InvariantCulture));
        command.AddParameter("$failedAt", row.FailedAt?.ToString("O", CultureInfo.InvariantCulture));
        command.AddParameter("$discardedAt", row.DiscardedAt?.ToString("O", CultureInfo.InvariantCulture));
        command.AddParameter("$lockedBy", row.LockedBy);
        command.AddParameter("$lockedUntil", row.LockedUntil?.ToString("O", CultureInfo.InvariantCulture));
        command.AddParameter("$attemptCount", row.AttemptCount);
        command.AddParameter("$lastError", row.LastError);
        await command.ExecuteNonQueryAsync();
        return row.Id;
    }

    protected override async Task<EmailOutboxAdminRowState> ReadEmailOutboxAdminRowStateAsync(Guid id)
    {
        await using var connection = new SqliteConnection(_database!.ConnectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT available_at, failed_at, discarded_at, locked_by, locked_until, last_error
            FROM ashlar_email_outbox
            WHERE id = $id;
            """;
        command.AddGuidParameter("$id", id);
        await using var reader = await command.ExecuteReaderAsync();
        Assert.That(await reader.ReadAsync(), Is.True);
        return new EmailOutboxAdminRowState(
            reader.GetDateTimeOffsetFromText("available_at"),
            reader.GetNullableDateTimeOffsetFromText("failed_at"),
            reader.GetNullableDateTimeOffsetFromText("discarded_at"),
            reader.GetNullableString("locked_by"),
            reader.GetNullableDateTimeOffsetFromText("locked_until"),
            reader.GetNullableString("last_error"));
    }

    [Test]
    public void ConstructorRejectsMissingDependencies()
    {
        var provider = _database!.ServiceProvider;
        var connectionProvider = provider.GetRequiredService<ISqliteConnectionProvider>();
        var audit = provider.GetRequiredService<ISecurityEventSink>();
        var transactionProvider = provider.GetRequiredService<AshlarDurableTransactionProvider>();
        var sessions = provider.GetRequiredService<IAuthenticationSessionRepository>();
        var authorizer = provider.GetRequiredService<IAccountSecurityOperationAuthorizer>();
        var auditSink = provider.GetRequiredService<IPersistentSecurityEventSink>();
        var administration = CreateAdministration(sessions, authorizer, auditSink, TimeProvider.System);
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => new SqliteEmailOutboxAdministrationService(null!, TimeProvider.System, audit, transactionProvider, administration));
            Assert.Throws<ArgumentNullException>(() => new SqliteEmailOutboxAdministrationService(connectionProvider, null!, audit, transactionProvider, administration));
            Assert.Throws<ArgumentNullException>(() => new SqliteEmailOutboxAdministrationService(connectionProvider, TimeProvider.System, null!, transactionProvider, administration));
            Assert.Throws<ArgumentNullException>(() => new SqliteEmailOutboxAdministrationService(connectionProvider, TimeProvider.System, audit, null!, administration));
            Assert.Throws<ArgumentNullException>(() => new SqliteEmailOutboxAdministrationService(connectionProvider, TimeProvider.System, audit, transactionProvider, null!));
            Assert.DoesNotThrow(() => new SqliteEmailOutboxAdministrationService(connectionProvider, TimeProvider.System, audit, transactionProvider, administration));
        }
    }

    [Test]
    public async Task GetAsyncHandlesInvalidAndMissingIds()
    {
        var admin = _database!.ServiceProvider.GetRequiredService<IEmailOutboxAdministrationService>();
        var actor = await CreateActorAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentException>(() => admin.GetAsync(new(Guid.Empty, actor, OperationalAdministrationScope.Global)));
            Assert.That(await admin.GetAsync(new(Guid.NewGuid(), actor, OperationalAdministrationScope.Global)), Is.Null);
        }
    }

    [Test]
    public async Task DetailProjectionCoversOptionalContentFlags()
    {
        var id = Guid.NewGuid();
        await using var connection = new SqliteConnection(_database!.ConnectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO ashlar_email_outbox (
                id, to_address, subject, text_body, html_body, headers, metadata,
                sensitivity, body_protection, created_at, available_at
            ) VALUES (
                $id, 'content@example.com', 'Content', 'text', '<p>html</p>', $headers, $metadata,
                'Normal', 'None', $now, $now
            );
            """;
        command.AddGuidParameter("$id", id);
        command.AddParameter("$headers", """{"X-Test":"1"}""");
        command.AddParameter("$metadata", """{"trace":"1"}""");
        command.AddDateTimeOffsetParameter("$now", AdminNow);
        await command.ExecuteNonQueryAsync();

        var actor = await CreateActorAsync();
        var detail = await _database.ServiceProvider.GetRequiredService<IEmailOutboxAdministrationService>().GetAsync(new(id, actor, OperationalAdministrationScope.Global));
        var empty = await SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow.Pending("empty@example.com", textBody: null, htmlBody: null));
        var emptyDetail = await _database.ServiceProvider.GetRequiredService<IEmailOutboxAdministrationService>().GetAsync(new(empty, actor, OperationalAdministrationScope.Global));

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
        var admin = CreateAdmin(new ThrowingSecurityEventSink(new InvalidOperationException("audit failed")));
        var actor = await CreateActorAsync(purpose: IAccountSecurityAdministrationService.ProofPurpose);

        Assert.ThrowsAsync<InvalidOperationException>(async () => await admin.RetryAsync(new(id, actor, OperationalAdministrationScope.Global)));
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
        var admin = CreateAdmin(new ThrowingSecurityEventSink(new InvalidOperationException("audit failed")));
        var actor = await CreateActorAsync(purpose: IAccountSecurityAdministrationService.ProofPurpose);

        Assert.ThrowsAsync<InvalidOperationException>(async () => await admin.DiscardAsync(new(id, actor, OperationalAdministrationScope.Global)));
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
        var admin = CreateAdmin(new ThrowingSecurityEventSink(new OperationCanceledException("audit canceled")));
        var actor = await CreateActorAsync(purpose: IAccountSecurityAdministrationService.ProofPurpose);

        Assert.ThrowsAsync<OperationCanceledException>(async () => await admin.RetryAsync(new(id, actor, OperationalAdministrationScope.Global)));
    }

    [Test]
    public async Task RetryAndDiscardRecordSafeAuditEvents()
    {
        var retryId = await SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow.Failed("audit-retry@example.com"));
        var discardId = await SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow.Failed("audit-discard@example.com"));
        var sink = new RecordingSecurityEventSink();
        var admin = CreateAdmin(sink);
        var actor = await CreateActorAsync(
            new AuditContext(Guid.Empty, "203.0.113.10", "audit-agent", "audit-correlation"),
            IAccountSecurityAdministrationService.ProofPurpose);
        var actorId = actor.ActorUserId;

        await admin.RetryAsync(new(retryId, actor, OperationalAdministrationScope.Global));
        await admin.DiscardAsync(new(discardId, actor, OperationalAdministrationScope.Global));

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

    private SqliteEmailOutboxAdministrationService CreateAdmin(ISecurityEventSink sink)
    {
        var services = _database!.ServiceProvider;
        return new(services.GetRequiredService<ISqliteConnectionProvider>(), services.GetRequiredService<TimeProvider>(),
            sink, services.GetRequiredService<AshlarDurableTransactionProvider>(),
            CreateAdministration(
                services.GetRequiredService<IAuthenticationSessionRepository>(),
                services.GetRequiredService<IAccountSecurityOperationAuthorizer>(),
                services.GetRequiredService<IPersistentSecurityEventSink>(),
                services.GetRequiredService<TimeProvider>()));
    }

    private static AshlarOperationalAdministrationContext CreateAdministration(
        IAuthenticationSessionRepository sessions,
        IAccountSecurityOperationAuthorizer authorizer,
        IPersistentSecurityEventSink auditSink,
        TimeProvider timeProvider) => new(
            new(sessions, authorizer, auditSink, timeProvider, eventType: "email_outbox.administration"),
            new(sessions, authorizer, auditSink, timeProvider, IAccountSecurityAdministrationService.ProofPurpose,
                "email_outbox.administration"));

    private async Task<AccountSecurityActorContext> CreateActorAsync(
        AuditContext? audit = null,
        string purpose = AccountSecurityActorContext.AdministrationReadProofPurpose)
    {
        var services = _database!.ServiceProvider;
        var user = await CreateUserAsync(GetUserRepository(services));
        var session = new AuthenticationSession { Id = Guid.NewGuid(), UserId = user.Id, TokenHash = Guid.NewGuid().ToString("N"), CreatedAt = AdminNow, ExpiresAt = AdminNow.AddYears(1) };
        await GetAuthenticationSessionRepository(services).CreateSessionAsync(session);
        var actorAudit = audit is null ? new AuditContext(user.Id) : audit with { ActorUserId = user.Id };
        return new(user.Id, TenantContext.Global, session.Id,
            FreshMfaVerificationProofFactory.Create(user.Id, null, session.Id, AdminNow, AdminNow.AddMinutes(5), purpose),
            actorAudit);
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
