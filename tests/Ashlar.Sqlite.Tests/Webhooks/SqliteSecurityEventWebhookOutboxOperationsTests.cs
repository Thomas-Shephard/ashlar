using Ashlar.Webhooks.SecurityEvents;
using Ashlar.Operational;
using Ashlar.Identity.Abstractions.Services;
using Ashlar.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Sqlite.Tests.Webhooks;

internal sealed class SqliteSecurityEventWebhookOutboxOperationsTests : SqliteTestBase
{
    private static readonly DateTimeOffset Now = new(2026, 5, 31, 12, 0, 0, TimeSpan.Zero);
    private static readonly string[] AuditPropertyNames = ["delivery_id", "endpoint_name", "event_id", "event_type", "outcome"];
    private static readonly AccountSecurityActorTestContext Security = new(Now, IAccountSecurityAdministrationService.ProofPurpose);
    private FakeTimeProvider _timeProvider = null!;
    private RecordingSecurityEventSink _audit = null!;
    private ServiceProvider _provider = null!;

    [SetUp]
    public async Task SetUpAsync()
    {
        _timeProvider = new FakeTimeProvider(Now);
        _audit = new RecordingSecurityEventSink();
        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(_timeProvider);
        services.AddSingleton<ISecurityEventHandler>(_audit);
        services.AddAshlarSqlite(GetConnectionString());
        services.AddAshlarSqliteSecurityEventWebhookOutbox();
        services.ReplaceAshlarProviderScoped<SqliteTransactionManager, IAuthenticationSessionRepository>("SQLite", _ => Security.Sessions);
        services.AddSingleton<IAccountSecurityOperationAuthorizer>(Security.Authorizer);
        services.ReplaceAshlarProviderScoped<SqliteTransactionManager, IPersistentSecurityEventSink>("SQLite", _ => Security.AuditSink);
        services.AddAshlarDurableTransactionParticipant<IPersistentSecurityEventSink>();
        _provider = services.BuildServiceProvider();
        await _provider.InitializeAshlarSqliteSchemaAsync();
    }

    [TearDown]
    public async Task TearDownAsync()
    {
        await _provider.DisposeAsync();
    }

    [Test]
    public void ConstructorRejectsNullRequiredArguments()
    {
        var connectionProvider = _provider.GetRequiredService<ISqliteConnectionProvider>();
        var audit = _provider.GetRequiredService<ISecurityEventSink>();
        var transactionProvider = _provider.GetRequiredService<AshlarDurableTransactionProvider>();
        var administration = Administration(Security);

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new SqliteSecurityEventWebhookOutboxOperations(null!, _timeProvider, audit, transactionProvider, administration));
            Assert.Throws<ArgumentNullException>(() => _ = new SqliteSecurityEventWebhookOutboxOperations(connectionProvider, null!, audit, transactionProvider, administration));
            Assert.Throws<ArgumentNullException>(() => _ = new SqliteSecurityEventWebhookOutboxOperations(connectionProvider, _timeProvider, null!, transactionProvider, administration));
            Assert.Throws<ArgumentNullException>(() => _ = new SqliteSecurityEventWebhookOutboxOperations(connectionProvider, _timeProvider, audit, null!, administration));
            Assert.Throws<ArgumentNullException>(() => _ = new SqliteSecurityEventWebhookOutboxOperations(connectionProvider, _timeProvider, audit, transactionProvider, null!));
            Assert.DoesNotThrow(() => _ = new SqliteSecurityEventWebhookOutboxOperations(connectionProvider, _timeProvider, audit, transactionProvider, administration));
        }
    }

    [Test]
    public async Task RetryAsyncRetriesOnlyTerminalFailedRowsAndAuditsSafely()
    {
        var id = await InsertRowAsync("failed", failedAt: Now.AddMinutes(-1), lastError: "secret https://example.test");

        var result = await Operations.RetryAsync(Request(id));

        var row = await QueryStateAsync(id);
        var audit = _audit.Events.Single();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarSecurityEventWebhookOutboxOperationStatus.Retried));
            Assert.That(result.EndpointName, Is.EqualTo("failed"));
            Assert.That(row.FailedAt, Is.Null);
            Assert.That(row.LastError, Is.Null);
            Assert.That(row.LockedBy, Is.Null);
            Assert.That(row.LockedUntil, Is.Null);
            Assert.That(row.AvailableAt, Is.EqualTo(Now));
            Assert.That(row.AttemptCount, Is.EqualTo(3));
            Assert.That(audit.EventType, Is.EqualTo(AshlarSecurityEventTypes.SecurityEventWebhookOutboxDeliveryRetried));
            Assert.That(audit.Properties!.Keys, Is.EquivalentTo(AuditPropertyNames));
            Assert.That(string.Join(" ", audit.Properties.Values), Does.Not.Contain("https://example.test"));
            Assert.That(string.Join(" ", audit.Properties.Values), Does.Not.Contain("secret"));
            Assert.That(Security.Authorizer.LastContext!.TargetTenant, Is.Null);
            Assert.That(Security.Authorizer.LastContext.IncludeAllTenants, Is.True);
        }
    }

    [Test]
    public async Task DiscardAsyncDiscardsOnlyTerminalFailedRowsAndPreventsDispatch()
    {
        var id = await InsertRowAsync("failed", failedAt: Now.AddMinutes(-1), lastError: "failure", lockedBy: "worker", lockedUntil: Now.AddMinutes(5));

        var result = await Operations.DiscardAsync(Request(id));

        var row = await QueryStateAsync(id);
        var dispatchable = await CountDispatchableAsync(id);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarSecurityEventWebhookOutboxOperationStatus.Discarded));
            Assert.That(row.DiscardedAt, Is.EqualTo(Now));
            Assert.That(row.LockedBy, Is.Null);
            Assert.That(row.LockedUntil, Is.Null);
            Assert.That(dispatchable, Is.Zero);
            Assert.That(_audit.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.SecurityEventWebhookOutboxDeliveryDiscarded));
        }
    }

    [Test]
    public async Task RetryAsyncRollsBackMutationWhenAuditFails()
    {
        var originalAvailableAt = Now.AddMinutes(-10);
        var id = await InsertRowAsync("failed", availableAt: originalAvailableAt, failedAt: Now.AddMinutes(-1), lastError: "failure");
        var operations = new SqliteSecurityEventWebhookOutboxOperations(
            _provider.GetRequiredService<ISqliteConnectionProvider>(),
            _timeProvider,
            new ThrowingSecurityEventSink(new InvalidOperationException("audit failed")),
            _provider.GetRequiredService<AshlarDurableTransactionProvider>(),
            Administration(Security));

        Assert.ThrowsAsync<InvalidOperationException>(async () => await operations.RetryAsync(Request(id)));
        var row = await QueryStateAsync(id);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(row.FailedAt, Is.Not.Null);
            Assert.That(row.LastError, Is.EqualTo("failure"));
            Assert.That(row.AvailableAt, Is.EqualTo(originalAvailableAt));
        }
    }

    [Test]
    public async Task DiscardAsyncRollsBackMutationWhenAuditFails()
    {
        var id = await InsertRowAsync("failed", failedAt: Now.AddMinutes(-1), lastError: "failure");
        var operations = new SqliteSecurityEventWebhookOutboxOperations(
            _provider.GetRequiredService<ISqliteConnectionProvider>(),
            _timeProvider,
            new ThrowingSecurityEventSink(new InvalidOperationException("audit failed")),
            _provider.GetRequiredService<AshlarDurableTransactionProvider>(),
            Administration(Security));

        Assert.ThrowsAsync<InvalidOperationException>(async () => await operations.DiscardAsync(Request(id)));
        var row = await QueryStateAsync(id);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(row.FailedAt, Is.Not.Null);
            Assert.That(row.DiscardedAt, Is.Null);
        }
    }

    [Test]
    public async Task OperationsReturnNoOpStatusesWithoutAudit()
    {
        var missing = Guid.NewGuid();
        var pending = await InsertRowAsync("pending");
        var sent = await InsertRowAsync("sent", sentAt: Now);
        var discarded = await InsertRowAsync("discarded", failedAt: Now.AddMinutes(-1), discardedAt: Now);

        var missingResult = await Operations.RetryAsync(Request(missing));
        var pendingRetry = await Operations.RetryAsync(Request(pending));
        var pendingDiscard = await Operations.DiscardAsync(Request(pending));
        var sentRetry = await Operations.RetryAsync(Request(sent));
        var discardedRetry = await Operations.RetryAsync(Request(discarded));
        var discardedDiscard = await Operations.DiscardAsync(Request(discarded));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missingResult.Status, Is.EqualTo(AshlarSecurityEventWebhookOutboxOperationStatus.NotFound));
            Assert.That(pendingRetry.Status, Is.EqualTo(AshlarSecurityEventWebhookOutboxOperationStatus.NotFailed));
            Assert.That(pendingDiscard.Status, Is.EqualTo(AshlarSecurityEventWebhookOutboxOperationStatus.NotFailed));
            Assert.That(sentRetry.Status, Is.EqualTo(AshlarSecurityEventWebhookOutboxOperationStatus.NotFailed));
            Assert.That(discardedRetry.Status, Is.EqualTo(AshlarSecurityEventWebhookOutboxOperationStatus.AlreadyDiscarded));
            Assert.That(discardedDiscard.Status, Is.EqualTo(AshlarSecurityEventWebhookOutboxOperationStatus.AlreadyDiscarded));
            Assert.That(_audit.Events, Is.Empty);
        }
    }

    [Test]
    public async Task RetryAsyncConcurrentConditionalUpdateReportsSingleSuccess()
    {
        var id = await InsertRowAsync("failed", failedAt: Now.AddMinutes(-1), lastError: "failure");

        var first = await Operations.RetryAsync(Request(id));
        var second = await Operations.RetryAsync(Request(id));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(new[] { first.Status, second.Status }, Is.EquivalentTo(new[]
            {
                AshlarSecurityEventWebhookOutboxOperationStatus.Retried,
                AshlarSecurityEventWebhookOutboxOperationStatus.NotFailed
            }));
            Assert.That(_audit.Events, Has.Count.EqualTo(1));
        }
    }

    [TestCase("scheduled")]
    [TestCase("locked")]
    [TestCase("expired")]
    public async Task OperationsDoNotTreatNonTerminalRowsAsFailed(string state)
    {
        var id = state switch
        {
            "scheduled" => await InsertRowAsync("scheduled", availableAt: Now.AddMinutes(5)),
            "locked" => await InsertRowAsync("locked", lockedBy: "worker", lockedUntil: Now.AddMinutes(5)),
            "expired" => await InsertRowAsync("expired", lockedBy: "worker", lockedUntil: Now.AddMinutes(-5)),
            _ => throw new ArgumentOutOfRangeException(nameof(state))
        };

        var retry = await Operations.RetryAsync(Request(id));
        var discard = await Operations.DiscardAsync(Request(id));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(retry.Status, Is.EqualTo(AshlarSecurityEventWebhookOutboxOperationStatus.NotFailed));
            Assert.That(discard.Status, Is.EqualTo(AshlarSecurityEventWebhookOutboxOperationStatus.NotFailed));
            Assert.That(_audit.Events, Is.Empty);
        }
    }

    [Test]
    public async Task ProviderRegistrationRegistersOperations()
    {
        await using var provider = new ServiceCollection()
            .AddSingleton<TimeProvider>(_timeProvider)
            .AddSingleton<ISecurityEventSink, NullSecurityEventSink>()
            .AddAshlarSqlite(GetConnectionString())
            .AddAshlarSqliteSecurityEventWebhookOutbox()
            .BuildServiceProvider();
        await using var bestEffortProvider = new ServiceCollection()
            .AddAshlarSecurityEventWebhooks()
            .BuildServiceProvider();

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<InvalidOperationException>(() => provider.GetRequiredService<IAshlarSecurityEventWebhookOutboxOperations>());
            Assert.That(bestEffortProvider.GetService<IAshlarSecurityEventWebhookOutboxOperations>(), Is.Null);
        }
    }

    private IAshlarSecurityEventWebhookOutboxOperations Operations => _provider.GetRequiredService<IAshlarSecurityEventWebhookOutboxOperations>();

    [Test]
    public async Task RetryAndDiscardDoNotMutateForAuthorizationProofSessionAndAuditFailures()
    {
        foreach (var failure in new[] { "authorization", "proof", "missing-session", "revoked-session", "audit" })
        {
            var retryId = await InsertRowAsync("retry-" + failure, failedAt: Now.AddMinutes(-1));
            var discardId = await InsertRowAsync("discard-" + failure, failedAt: Now.AddMinutes(-1));
            var security = FailedSecurity(failure);
            var operations = new SqliteSecurityEventWebhookOutboxOperations(
                _provider.GetRequiredService<ISqliteConnectionProvider>(), _timeProvider,
                _provider.GetRequiredService<ISecurityEventSink>(), _provider.GetRequiredService<AshlarDurableTransactionProvider>(),
                Administration(security));

            await operations.RetryAsync(new AshlarSecurityEventWebhookOutboxOperationRequest(retryId, security.Actor, OperationalAdministrationScope.Global));
            await operations.DiscardAsync(new AshlarSecurityEventWebhookOutboxOperationRequest(discardId, security.Actor, OperationalAdministrationScope.Global));

            using (Assert.EnterMultipleScope())
            {
                Assert.That((await QueryStateAsync(retryId)).FailedAt, Is.Not.Null, failure);
                Assert.That((await QueryStateAsync(discardId)).DiscardedAt, Is.Null, failure);
            }
        }
    }

    private AshlarOperationalAdministrationContext Administration(AccountSecurityActorTestContext security) => new(
        new(security.Sessions, security.Authorizer, security.AuditSink, _timeProvider,
            eventType: AshlarSecurityEventTypes.SecurityEventWebhookOutboxBrowse),
        new(security.Sessions, security.Authorizer, security.AuditSink, _timeProvider,
            IAccountSecurityAdministrationService.ProofPurpose, AshlarSecurityEventTypes.SecurityEventWebhookOutboxOperation));

    private static AccountSecurityActorTestContext FailedSecurity(string failure)
    {
        var security = new AccountSecurityActorTestContext(Now, IAccountSecurityAdministrationService.ProofPurpose, authorized: failure != "authorization");
        if (failure == "proof")
            security.Actor = new AccountSecurityActorContext(security.Actor.ActorUserId, security.Actor.ActorTenant, security.Actor.CurrentSessionId,
                FreshMfaVerificationProofFactory.Create(security.Actor.ActorUserId, null, security.Actor.CurrentSessionId, Now, Now.AddMinutes(5), "wrong"),
                security.Actor.Audit);
        else if (failure == "missing-session")
            security.Sessions.Session = null;
        else if (failure == "revoked-session")
            security.Sessions.Session!.RevokedAt = Now;
        else if (failure == "audit")
            security.Actor = new AccountSecurityActorContext(security.Actor.ActorUserId, security.Actor.ActorTenant, security.Actor.CurrentSessionId,
                security.Actor.FreshMfaProof, new AuditContext(Guid.NewGuid()));
        return security;
    }

    private static AshlarSecurityEventWebhookOutboxOperationRequest Request(Guid id)
    {
        return new AshlarSecurityEventWebhookOutboxOperationRequest(id, Security.Actor, OperationalAdministrationScope.Global);
    }

    private async Task<Guid> InsertRowAsync(
        string endpointName,
        DateTimeOffset? availableAt = null,
        DateTimeOffset? sentAt = null,
        DateTimeOffset? failedAt = null,
        DateTimeOffset? discardedAt = null,
        string? lockedBy = null,
        DateTimeOffset? lockedUntil = null,
        string? lastError = null)
    {
        var id = Guid.NewGuid();
        await using var connection = await OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO ashlar_security_event_webhook_outbox (
                id, endpoint_name, uri, event_id, event_type, outcome, occurred_at, timeout_ms, body, headers,
                created_at, available_at, sent_at, failed_at, discarded_at, locked_by, locked_until, last_attempt_at, attempt_count, last_error)
            VALUES (
                $id, $endpointName, 'https://example.test/security-events', $eventId, 'security.test', 'success', $now, 1000, $body, $headers,
                $now, $availableAt, $sentAt, $failedAt, $discardedAt, $lockedBy, $lockedUntil, $failedAt, 3, $lastError);
            """;
        command.AddGuidParameter("$id", id);
        command.AddParameter("$endpointName", endpointName);
        command.AddGuidParameter("$eventId", Guid.NewGuid());
        command.AddDateTimeOffsetParameter("$now", Now);
        command.AddDateTimeOffsetParameter("$availableAt", availableAt ?? Now);
        command.AddNullableDateTimeOffsetParameter("$sentAt", sentAt);
        command.AddNullableDateTimeOffsetParameter("$failedAt", failedAt);
        command.AddNullableDateTimeOffsetParameter("$discardedAt", discardedAt);
        command.AddParameter("$lockedBy", lockedBy);
        command.AddNullableDateTimeOffsetParameter("$lockedUntil", lockedUntil);
        command.AddParameter("$body", new byte[] { 1, 2, 3 });
        command.AddParameter("$headers", "{}");
        command.AddParameter("$lastError", lastError);
        await command.ExecuteNonQueryAsync();
        return id;
    }

    private async Task<int> CountDispatchableAsync(Guid id)
    {
        await using var connection = await OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT count(*)
            FROM ashlar_security_event_webhook_outbox
            WHERE id = $id AND sent_at IS NULL AND failed_at IS NULL AND discarded_at IS NULL AND available_at <= $now;
            """;
        command.AddGuidParameter("$id", id);
        command.AddDateTimeOffsetParameter("$now", Now);
        return Convert.ToInt32(await command.ExecuteScalarAsync(), System.Globalization.CultureInfo.InvariantCulture);
    }

    private async Task<OutboxState> QueryStateAsync(Guid id)
    {
        await using var connection = await OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT available_at, failed_at, discarded_at, locked_by, locked_until, attempt_count, last_error
            FROM ashlar_security_event_webhook_outbox
            WHERE id = $id;
            """;
        command.AddGuidParameter("$id", id);
        await using var reader = await command.ExecuteReaderAsync();
        Assert.That(await reader.ReadAsync(), Is.True);
        return new OutboxState(
            reader.GetDateTimeOffsetFromText("available_at"),
            reader.GetNullableDateTimeOffsetFromText("failed_at"),
            reader.GetNullableDateTimeOffsetFromText("discarded_at"),
            reader.GetNullableString("locked_by"),
            reader.GetNullableDateTimeOffsetFromText("locked_until"),
            reader.GetInt32ByName("attempt_count"),
            reader.GetNullableString("last_error"));
    }

    private sealed record OutboxState(
        DateTimeOffset AvailableAt,
        DateTimeOffset? FailedAt,
        DateTimeOffset? DiscardedAt,
        string? LockedBy,
        DateTimeOffset? LockedUntil,
        int AttemptCount,
        string? LastError);

    private sealed class RecordingSecurityEventSink : ISecurityEventHandler
    {
        public List<AshlarSecurityEvent> Events { get; } = [];

        public Task HandleAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            Events.Add(securityEvent);
            return Task.CompletedTask;
        }
    }

    private sealed class ThrowingSecurityEventSink(Exception exception) : ISecurityEventSink
    {
        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            throw exception;
        }
    }
}
