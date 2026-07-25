using Dapper;
using Ashlar.Identity.Models.AccountSecurity;
using Ashlar.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Postgres.Tests.Webhooks;

internal sealed class PostgresSecurityEventWebhookOutboxBrowserTests : PostgresTestBase
{
    private static readonly DateTimeOffset Now = new(2026, 5, 24, 12, 0, 0, TimeSpan.Zero);
    private static readonly string[] FailedEndpointNames = ["failed"];
    private static readonly AccountSecurityActorTestContext Security = new(Now, AccountSecurityActorContext.AdministrationReadProofPurpose);
    private FakeTimeProvider _timeProvider = null!;
    private ServiceProvider _provider = null!;

    public override async Task OneTimeSetUp()
    {
        await base.OneTimeSetUp();
        _timeProvider = new FakeTimeProvider(Now);
        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(_timeProvider);
        services.AddAshlarPostgres(GetConnectionString());
        services.AddAshlarPostgresSecurityEventWebhookOutbox();
        services.AddSingleton<IAuthenticationSessionRepository>(Security.Sessions);
        services.AddSingleton<IAccountSecurityOperationAuthorizer>(Security.Authorizer);
        services.AddSingleton<IPersistentSecurityEventSink>(Security.AuditSink);
        _provider = services.BuildServiceProvider();
        await _provider.InitializeAshlarPostgresSchemaAsync();
    }

    [OneTimeTearDown]
    public async Task DisposeProviderAsync()
    {
        await _provider.DisposeAsync();
    }

    [SetUp]
    public async Task ClearOutboxAsync()
    {
        await using var connection = await GetDataSource().OpenConnectionAsync();
        await connection.ExecuteAsync("TRUNCATE ashlar_security_event_webhook_outbox;");
        _timeProvider.SetUtcNow(Now);
    }

    [Test]
    public void ConstructorRejectsNullArguments()
    {
        var connectionProvider = _provider.GetRequiredService<IPostgresConnectionProvider>();

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new PostgresSecurityEventWebhookOutboxBrowser(null!, _timeProvider, Security.Sessions, Security.Authorizer, Security.AuditSink));
            Assert.Throws<ArgumentNullException>(() => _ = new PostgresSecurityEventWebhookOutboxBrowser(connectionProvider, null!, Security.Sessions, Security.Authorizer, Security.AuditSink));
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
        }
    }

    [Test]
    public async Task ListAsyncReturnsNoDataWhenAuthorizationFails()
    {
        var security = new AccountSecurityActorTestContext(
            Now,
            AccountSecurityActorContext.AdministrationReadProofPurpose,
            authorized: false);
        var browser = new PostgresSecurityEventWebhookOutboxBrowser(
            _provider.GetRequiredService<IPostgresConnectionProvider>(),
            _timeProvider,
            security.Sessions,
            security.Authorizer,
            security.AuditSink);

        var result = await browser.ListAsync(
            security.Actor,
            new AshlarSecurityEventWebhookOutboxBrowseRequest { Limit = 10 });

        Assert.That(result.Deliveries, Is.Empty);
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

        var failed = await _provider.GetRequiredService<IAshlarSecurityEventWebhookOutboxBrowser>()
            .ListAsync(Security.Actor, new AshlarSecurityEventWebhookOutboxBrowseRequest
            {
                Statuses = new HashSet<AshlarSecurityEventWebhookOutboxStatus> { AshlarSecurityEventWebhookOutboxStatus.Failed },
                Limit = 10
            });
        var page = await _provider.GetRequiredService<IAshlarSecurityEventWebhookOutboxBrowser>()
            .ListAsync(Security.Actor, new AshlarSecurityEventWebhookOutboxBrowseRequest { Limit = 2, Offset = 1 });

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

    private async Task InsertRowsAsync(
        string eventType = "security.test",
        string outcome = "success",
        string? lastError = "failure")
    {
        await using var connection = await GetDataSource().OpenConnectionAsync();
        await connection.ExecuteAsync("""
            INSERT INTO ashlar_security_event_webhook_outbox (id, endpoint_name, uri, event_id, event_type, outcome, occurred_at, timeout_ms, body, headers, created_at, available_at)
            VALUES (@pendingId, 'pending', 'https://example.test/pending', @pendingEventId, @eventType, @outcome, @pendingCreated, 1000, @body, @headers::jsonb, @pendingCreated, @pendingCreated),
                   (@scheduledId, 'scheduled', 'https://example.test/scheduled', @scheduledEventId, @eventType, @outcome, @scheduledCreated, 1000, @body, @headers::jsonb, @scheduledCreated, @scheduledAvailable);

            INSERT INTO ashlar_security_event_webhook_outbox (id, endpoint_name, uri, event_id, event_type, outcome, occurred_at, timeout_ms, body, headers, created_at, available_at, locked_until, locked_by)
            VALUES (@lockedId, 'locked', 'https://example.test/locked', @lockedEventId, @eventType, @outcome, @lockedCreated, 1000, @body, @headers::jsonb, @lockedCreated, @pendingCreated, @lockedUntil, 'worker'),
                   (@expiredId, 'expired', 'https://example.test/expired', @expiredEventId, @eventType, @outcome, @expiredCreated, 1000, @body, @headers::jsonb, @expiredCreated, @pendingCreated, @expiredUntil, 'worker');

            INSERT INTO ashlar_security_event_webhook_outbox (id, endpoint_name, uri, event_id, event_type, outcome, occurred_at, timeout_ms, body, headers, created_at, available_at, failed_at, last_attempt_at, attempt_count, last_error)
            VALUES (@failedId, 'failed', 'https://example.test/failed', @failedEventId, @eventType, @outcome, @failedCreated, 1000, @body, @headers::jsonb, @failedCreated, @pendingCreated, @failedAt, @lastAttemptAt, 3, @lastError);

            INSERT INTO ashlar_security_event_webhook_outbox (id, endpoint_name, uri, event_id, event_type, outcome, occurred_at, timeout_ms, body, headers, created_at, available_at, sent_at)
            VALUES (@sentId, 'sent', 'https://example.test/sent', @sentEventId, @eventType, @outcome, @sentCreated, 1000, @body, @headers::jsonb, @sentCreated, @sentCreated, @sentAt);
            """, new
        {
            pendingId = Guid.NewGuid(),
            scheduledId = Guid.NewGuid(),
            lockedId = Guid.NewGuid(),
            expiredId = Guid.NewGuid(),
            failedId = Guid.NewGuid(),
            sentId = Guid.NewGuid(),
            pendingEventId = Guid.NewGuid(),
            scheduledEventId = Guid.NewGuid(),
            lockedEventId = Guid.NewGuid(),
            expiredEventId = Guid.NewGuid(),
            failedEventId = Guid.NewGuid(),
            sentEventId = Guid.NewGuid(),
            eventType,
            outcome,
            body = new byte[] { 1, 2, 3 },
            headers = "{}",
            pendingCreated = Now.AddMinutes(-5),
            scheduledCreated = Now.AddMinutes(-4),
            scheduledAvailable = Now.AddMinutes(30),
            lockedCreated = Now.AddMinutes(-3),
            expiredCreated = Now.AddMinutes(-2),
            failedCreated = Now.AddMinutes(-1),
            sentCreated = Now,
            lockedUntil = Now.AddMinutes(5),
            expiredUntil = Now.AddMinutes(-1),
            failedAt = Now.AddSeconds(-30),
            lastAttemptAt = Now.AddSeconds(-30),
            sentAt = Now,
            lastError
        });
    }

    private async Task InsertDiscardedRowAsync()
    {
        await using var connection = await GetDataSource().OpenConnectionAsync();
        await connection.ExecuteAsync("""
            INSERT INTO ashlar_security_event_webhook_outbox (
                id, endpoint_name, uri, event_id, event_type, outcome, occurred_at, timeout_ms, body, headers,
                created_at, available_at, failed_at, discarded_at, attempt_count, last_error)
            VALUES (
                @id, 'discarded', 'https://example.test/discarded', @eventId, 'security.test', 'success', @createdAt, 1000, @body, @headers::jsonb,
                @createdAt, @createdAt, @failedAt, @discardedAt, 3, 'failure');
            """, new
        {
            id = Guid.NewGuid(),
            eventId = Guid.NewGuid(),
            body = new byte[] { 1, 2, 3 },
            headers = "{}",
            createdAt = Now.AddSeconds(-10),
            failedAt = Now.AddSeconds(-5),
            discardedAt = Now
        });
    }
}
