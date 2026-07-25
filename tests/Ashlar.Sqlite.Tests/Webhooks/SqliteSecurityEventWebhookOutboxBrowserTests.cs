using Ashlar.Webhooks.SecurityEvents;
using Ashlar.Identity.Abstractions.Services;
using Ashlar.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Sqlite.Tests.Webhooks;

internal sealed class SqliteSecurityEventWebhookOutboxBrowserTests : SqliteTestBase
{
    private static readonly DateTimeOffset Now = new(2026, 5, 24, 12, 0, 0, TimeSpan.Zero);
    private static readonly string[] FailedEndpointNames = ["failed"];
    private static readonly AccountSecurityActorTestContext Security = new(Now, AccountSecurityActorContext.AdministrationReadProofPurpose);
    private FakeTimeProvider _timeProvider = null!;
    private ServiceProvider _provider = null!;

    [SetUp]
    public async Task SetUpAsync()
    {
        _timeProvider = new FakeTimeProvider(Now);
        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(_timeProvider);
        services.AddAshlarSqlite(GetConnectionString());
        services.AddAshlarSqliteSecurityEventWebhookOutbox();
        services.AddSingleton<IAuthenticationSessionRepository>(Security.Sessions);
        services.AddSingleton<IAccountSecurityOperationAuthorizer>(Security.Authorizer);
        services.AddSingleton<IPersistentSecurityEventSink>(Security.AuditSink);
        _provider = services.BuildServiceProvider();
        await _provider.InitializeAshlarSqliteSchemaAsync();
    }

    [TearDown]
    public async Task TearDownAsync()
    {
        await _provider.DisposeAsync();
    }

    [Test]
    public void ConstructorRejectsNullArguments()
    {
        var connectionProvider = _provider.GetRequiredService<ISqliteConnectionProvider>();

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new SqliteSecurityEventWebhookOutboxBrowser(null!, _timeProvider, Security.Sessions, Security.Authorizer, Security.AuditSink));
            Assert.Throws<ArgumentNullException>(() => _ = new SqliteSecurityEventWebhookOutboxBrowser(connectionProvider, null!, Security.Sessions, Security.Authorizer, Security.AuditSink));
        }
    }

    [Test]
    public async Task ListAsyncReturnsSafeStatusesAndOmitsSentRows()
    {
        await InsertRowsAsync();
        await InsertDiscardedRowAsync();

        var result = await _provider.GetRequiredService<IAshlarSecurityEventWebhookOutboxBrowser>()
            .ListAsync(Security.Actor, new AshlarSecurityEventWebhookOutboxBrowseRequest { Limit = 10 });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.HasMore, Is.False);
            Assert.That(result.Deliveries.Select(delivery => delivery.Status), Is.EqualTo(new[]
            {
                AshlarSecurityEventWebhookOutboxStatus.Pending,
                AshlarSecurityEventWebhookOutboxStatus.Scheduled,
                AshlarSecurityEventWebhookOutboxStatus.Locked,
                AshlarSecurityEventWebhookOutboxStatus.ExpiredLock,
                AshlarSecurityEventWebhookOutboxStatus.Failed
            }));
            Assert.That(result.Deliveries.Select(delivery => delivery.EndpointName), Does.Not.Contain("sent"));
            Assert.That(result.Deliveries.Select(delivery => delivery.EndpointName), Does.Not.Contain("discarded"));
            Assert.That(result.Deliveries.All(delivery => delivery.EventType == "security.test"), Is.True);
            Assert.That(result.Deliveries.All(delivery => delivery.Outcome == "success"), Is.True);
            Assert.That(Security.Authorizer.LastContext!.TargetTenant, Is.Null);
            Assert.That(Security.Authorizer.LastContext.IncludeAllTenants, Is.True);
        }
    }

    [Test]
    public async Task ListAsyncExcludesDiscardedRowsFromFailedFilter()
    {
        await InsertRowsAsync();
        await InsertDiscardedRowAsync();

        var result = await _provider.GetRequiredService<IAshlarSecurityEventWebhookOutboxBrowser>()
            .ListAsync(Security.Actor, new AshlarSecurityEventWebhookOutboxBrowseRequest
            {
                Statuses = new HashSet<AshlarSecurityEventWebhookOutboxStatus> { AshlarSecurityEventWebhookOutboxStatus.Failed },
                Limit = 10
            });

        Assert.That(result.Deliveries.Select(delivery => delivery.EndpointName), Is.EqualTo(FailedEndpointNames));
    }

    [Test]
    public async Task ListAsyncFiltersStatusAndPagesWithHasMore()
    {
        await InsertRowsAsync();

        var browser = _provider.GetRequiredService<IAshlarSecurityEventWebhookOutboxBrowser>();
        var failed = await browser.ListAsync(Security.Actor, new AshlarSecurityEventWebhookOutboxBrowseRequest
        {
            Statuses = new HashSet<AshlarSecurityEventWebhookOutboxStatus> { AshlarSecurityEventWebhookOutboxStatus.Failed },
            Limit = 10
        });
        var page = await browser.ListAsync(Security.Actor, new AshlarSecurityEventWebhookOutboxBrowseRequest { Limit = 2, Offset = 1 });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(failed.Deliveries, Has.Count.EqualTo(1));
            Assert.That(failed.Deliveries.Single().Status, Is.EqualTo(AshlarSecurityEventWebhookOutboxStatus.Failed));
            Assert.That(page.Deliveries, Has.Count.EqualTo(2));
            Assert.That(page.HasMore, Is.True);
            Assert.That(page.Limit, Is.EqualTo(2));
            Assert.That(page.Offset, Is.EqualTo(1));
            Assert.That(page.Deliveries[0].Status, Is.EqualTo(AshlarSecurityEventWebhookOutboxStatus.Scheduled));
        }
    }

    [Test]
    public async Task ListAsyncSuppressesMalformedSafeFieldsAndUnsafeLastError()
    {
        var longError = "first line\r\n" + new string('x', AshlarSecurityEventWebhookOutboxBrowser.MaxLastErrorSummaryLength + 20);
        await InsertRowsAsync(eventType: "bad\nevent", outcome: "bad\routcome", lastError: longError);

        var result = await _provider.GetRequiredService<IAshlarSecurityEventWebhookOutboxBrowser>()
            .ListAsync(Security.Actor, new AshlarSecurityEventWebhookOutboxBrowseRequest
            {
                Statuses = new HashSet<AshlarSecurityEventWebhookOutboxStatus> { AshlarSecurityEventWebhookOutboxStatus.Failed },
                Limit = 10
            });
        var delivery = result.Deliveries.Single();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(delivery.EventType, Is.Null);
            Assert.That(delivery.Outcome, Is.Null);
            Assert.That(delivery.LastErrorSummary, Is.Null);
        }
    }

    [Test]
    public async Task ListAsyncReturnsSafeStoredFailureSummary()
    {
        await InsertRowsAsync(lastError: "kind=http_status;status=502;reason=non_success_status");

        var result = await _provider.GetRequiredService<IAshlarSecurityEventWebhookOutboxBrowser>()
            .ListAsync(Security.Actor, new AshlarSecurityEventWebhookOutboxBrowseRequest
            {
                Statuses = new HashSet<AshlarSecurityEventWebhookOutboxStatus> { AshlarSecurityEventWebhookOutboxStatus.Failed },
                Limit = 10
            });

        Assert.That(result.Deliveries.Single().LastErrorSummary, Is.EqualTo("kind=http_status;status=502;reason=non_success_status"));
    }

    [Test]
    public async Task ListAsyncKeepsNullLastErrorNull()
    {
        await InsertRowsAsync(lastError: null);

        var result = await _provider.GetRequiredService<IAshlarSecurityEventWebhookOutboxBrowser>()
            .ListAsync(Security.Actor, new AshlarSecurityEventWebhookOutboxBrowseRequest
            {
                Statuses = new HashSet<AshlarSecurityEventWebhookOutboxStatus> { AshlarSecurityEventWebhookOutboxStatus.Failed },
                Limit = 10
            });

        Assert.That(result.Deliveries.Single().LastErrorSummary, Is.Null);
    }

    [Test]
    public async Task ListAsyncReturnsNoDataForAuthorizationProofSessionAndAuditFailures()
    {
        await InsertRowsAsync();
        foreach (var failure in new[] { "authorization", "proof", "missing-session", "revoked-session", "audit" })
        {
            var security = FailedSecurity(failure, AccountSecurityActorContext.AdministrationReadProofPurpose);
            var browser = new SqliteSecurityEventWebhookOutboxBrowser(
                _provider.GetRequiredService<ISqliteConnectionProvider>(), _timeProvider,
                security.Sessions, security.Authorizer, security.AuditSink);
            var result = await browser.ListAsync(security.Actor, new AshlarSecurityEventWebhookOutboxBrowseRequest());
            using (Assert.EnterMultipleScope())
            {
                Assert.That(result.Deliveries, Is.Empty, failure);
            }
        }
    }

    private static AccountSecurityActorTestContext FailedSecurity(string failure, string purpose)
    {
        var security = new AccountSecurityActorTestContext(Now, purpose, authorized: failure != "authorization");
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

    private async Task InsertRowsAsync(
        string eventType = "security.test",
        string outcome = "success",
        string? lastError = "failure")
    {
        await using var connection = await OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO ashlar_security_event_webhook_outbox (id, endpoint_name, uri, event_id, event_type, outcome, occurred_at, timeout_ms, body, headers, created_at, available_at)
            VALUES ($pendingId, 'pending', 'https://example.test/pending', $pendingEventId, $eventType, $outcome, $pendingCreated, 1000, $body, $headers, $pendingCreated, $pendingCreated),
                   ($scheduledId, 'scheduled', 'https://example.test/scheduled', $scheduledEventId, $eventType, $outcome, $scheduledCreated, 1000, $body, $headers, $scheduledCreated, $scheduledAvailable);

            INSERT INTO ashlar_security_event_webhook_outbox (id, endpoint_name, uri, event_id, event_type, outcome, occurred_at, timeout_ms, body, headers, created_at, available_at, locked_until, locked_by)
            VALUES ($lockedId, 'locked', 'https://example.test/locked', $lockedEventId, $eventType, $outcome, $lockedCreated, 1000, $body, $headers, $lockedCreated, $pendingCreated, $lockedUntil, 'worker'),
                   ($expiredId, 'expired', 'https://example.test/expired', $expiredEventId, $eventType, $outcome, $expiredCreated, 1000, $body, $headers, $expiredCreated, $pendingCreated, $expiredUntil, 'worker');

            INSERT INTO ashlar_security_event_webhook_outbox (id, endpoint_name, uri, event_id, event_type, outcome, occurred_at, timeout_ms, body, headers, created_at, available_at, failed_at, last_attempt_at, attempt_count, last_error)
            VALUES ($failedId, 'failed', 'https://example.test/failed', $failedEventId, $eventType, $outcome, $failedCreated, 1000, $body, $headers, $failedCreated, $pendingCreated, $failedAt, $lastAttemptAt, 3, $lastError);

            INSERT INTO ashlar_security_event_webhook_outbox (id, endpoint_name, uri, event_id, event_type, outcome, occurred_at, timeout_ms, body, headers, created_at, available_at, sent_at)
            VALUES ($sentId, 'sent', 'https://example.test/sent', $sentEventId, $eventType, $outcome, $sentCreated, 1000, $body, $headers, $sentCreated, $sentCreated, $sentAt);
            """;
        command.AddGuidParameter("$pendingId", Guid.NewGuid());
        command.AddGuidParameter("$scheduledId", Guid.NewGuid());
        command.AddGuidParameter("$lockedId", Guid.NewGuid());
        command.AddGuidParameter("$expiredId", Guid.NewGuid());
        command.AddGuidParameter("$failedId", Guid.NewGuid());
        command.AddGuidParameter("$sentId", Guid.NewGuid());
        command.AddGuidParameter("$pendingEventId", Guid.NewGuid());
        command.AddGuidParameter("$scheduledEventId", Guid.NewGuid());
        command.AddGuidParameter("$lockedEventId", Guid.NewGuid());
        command.AddGuidParameter("$expiredEventId", Guid.NewGuid());
        command.AddGuidParameter("$failedEventId", Guid.NewGuid());
        command.AddGuidParameter("$sentEventId", Guid.NewGuid());
        command.AddParameter("$eventType", eventType);
        command.AddParameter("$outcome", outcome);
        command.AddParameter("$body", new byte[] { 1, 2, 3 });
        command.AddParameter("$headers", "{}");
        command.AddDateTimeOffsetParameter("$pendingCreated", Now.AddMinutes(-5));
        command.AddDateTimeOffsetParameter("$scheduledCreated", Now.AddMinutes(-4));
        command.AddDateTimeOffsetParameter("$scheduledAvailable", Now.AddMinutes(30));
        command.AddDateTimeOffsetParameter("$lockedCreated", Now.AddMinutes(-3));
        command.AddDateTimeOffsetParameter("$expiredCreated", Now.AddMinutes(-2));
        command.AddDateTimeOffsetParameter("$failedCreated", Now.AddMinutes(-1));
        command.AddDateTimeOffsetParameter("$sentCreated", Now);
        command.AddDateTimeOffsetParameter("$lockedUntil", Now.AddMinutes(5));
        command.AddDateTimeOffsetParameter("$expiredUntil", Now.AddMinutes(-1));
        command.AddDateTimeOffsetParameter("$failedAt", Now.AddSeconds(-30));
        command.AddDateTimeOffsetParameter("$lastAttemptAt", Now.AddSeconds(-30));
        command.AddDateTimeOffsetParameter("$sentAt", Now);
        command.AddParameter("$lastError", lastError);

        await command.ExecuteNonQueryAsync();
    }

    private async Task InsertDiscardedRowAsync()
    {
        await using var connection = await OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO ashlar_security_event_webhook_outbox (
                id, endpoint_name, uri, event_id, event_type, outcome, occurred_at, timeout_ms, body, headers,
                created_at, available_at, failed_at, discarded_at, attempt_count, last_error)
            VALUES (
                $id, 'discarded', 'https://example.test/discarded', $eventId, 'security.test', 'success', $createdAt, 1000, $body, $headers,
                $createdAt, $createdAt, $failedAt, $discardedAt, 3, 'failure');
            """;
        command.AddGuidParameter("$id", Guid.NewGuid());
        command.AddGuidParameter("$eventId", Guid.NewGuid());
        command.AddParameter("$body", new byte[] { 1, 2, 3 });
        command.AddParameter("$headers", "{}");
        command.AddDateTimeOffsetParameter("$createdAt", Now.AddSeconds(-10));
        command.AddDateTimeOffsetParameter("$failedAt", Now.AddSeconds(-5));
        command.AddDateTimeOffsetParameter("$discardedAt", Now);

        await command.ExecuteNonQueryAsync();
    }
}
