using Dapper;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Postgres.Tests.Webhooks;

internal sealed class PostgresSecurityEventWebhookOutboxOperationsTests : PostgresTestBase
{
    private static readonly DateTimeOffset Now = new(2026, 5, 31, 12, 0, 0, TimeSpan.Zero);
    private static readonly string[] AuditPropertyNames = ["delivery_id", "endpoint_name", "event_id", "event_type", "outcome"];
    private FakeTimeProvider _timeProvider = null!;
    private RecordingSecurityEventSink _audit = null!;
    private ServiceProvider _provider = null!;

    public override async Task OneTimeSetUp()
    {
        await base.OneTimeSetUp();
        _timeProvider = new FakeTimeProvider(Now);
        _audit = new RecordingSecurityEventSink();
        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(_timeProvider);
        services.AddSingleton<ISecurityEventSink>(_audit);
        services.AddAshlarPostgres(GetConnectionString());
        services.AddAshlarPostgresSecurityEventWebhookOutbox();
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
        _audit.Events.Clear();
        _timeProvider.SetUtcNow(Now);
    }

    [Test]
    public void ConstructorRejectsNullRequiredArguments()
    {
        var connectionProvider = _provider.GetRequiredService<IPostgresConnectionProvider>();

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new PostgresSecurityEventWebhookOutboxOperations(null!, _timeProvider));
            Assert.Throws<ArgumentNullException>(() => _ = new PostgresSecurityEventWebhookOutboxOperations(connectionProvider, null!));
            Assert.DoesNotThrow(() => _ = new PostgresSecurityEventWebhookOutboxOperations(connectionProvider, _timeProvider));
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
            Assert.That(audit.Outcome, Is.EqualTo(SecurityEventOutcomes.Success));
            Assert.That(audit.Properties!.Keys, Is.EquivalentTo(AuditPropertyNames));
            Assert.That(string.Join(" ", audit.Properties.Values), Does.Not.Contain("https://example.test"));
            Assert.That(string.Join(" ", audit.Properties.Values), Does.Not.Contain("secret"));
        }
    }

    [Test]
    public async Task DiscardAsyncDiscardsOnlyTerminalFailedRowsAndPreventsDispatch()
    {
        var id = await InsertRowAsync("failed", failedAt: Now.AddMinutes(-1), lastError: "failure", lockedBy: "worker", lockedUntil: Now.AddMinutes(5));

        var result = await Operations.DiscardAsync(Request(id));

        var row = await QueryStateAsync(id);
        await using var connection = await GetDataSource().OpenConnectionAsync();
        var dispatchable = await connection.ExecuteScalarAsync<int>("SELECT count(*) FROM ashlar_security_event_webhook_outbox WHERE id = @id AND sent_at IS NULL AND failed_at IS NULL AND discarded_at IS NULL AND available_at <= @now", new { id, now = Now });

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
            .AddAshlarPostgres(GetConnectionString())
            .AddAshlarPostgresSecurityEventWebhookOutbox()
            .BuildServiceProvider();
        await using var bestEffortProvider = new ServiceCollection()
            .AddAshlarSecurityEventWebhooks()
            .BuildServiceProvider();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.GetRequiredService<IAshlarSecurityEventWebhookOutboxOperations>(), Is.TypeOf<PostgresSecurityEventWebhookOutboxOperations>());
            Assert.That(bestEffortProvider.GetService<IAshlarSecurityEventWebhookOutboxOperations>(), Is.Null);
        }
    }

    private IAshlarSecurityEventWebhookOutboxOperations Operations => _provider.GetRequiredService<IAshlarSecurityEventWebhookOutboxOperations>();

    private static AshlarSecurityEventWebhookOutboxOperationRequest Request(Guid id)
    {
        return new AshlarSecurityEventWebhookOutboxOperationRequest(id, new AuditContext(Guid.NewGuid(), "203.0.113.9", "agent", "corr"));
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
        await using var connection = await GetDataSource().OpenConnectionAsync();
        await connection.ExecuteAsync("""
            INSERT INTO ashlar_security_event_webhook_outbox (
                id, endpoint_name, uri, event_id, event_type, outcome, occurred_at, timeout_ms, body, headers,
                created_at, available_at, sent_at, failed_at, discarded_at, locked_by, locked_until, last_attempt_at, attempt_count, last_error)
            VALUES (
                @id, @endpointName, 'https://example.test/security-events', @eventId, 'security.test', 'success', @now, 1000, @body, @headers::jsonb,
                @now, @availableAt, @sentAt, @failedAt, @discardedAt, @lockedBy, @lockedUntil, @failedAt, 3, @lastError);
            """, new
        {
            id,
            endpointName,
            eventId = Guid.NewGuid(),
            now = Now,
            availableAt = availableAt ?? Now,
            sentAt,
            failedAt,
            discardedAt,
            lockedBy,
            lockedUntil,
            body = new byte[] { 1, 2, 3 },
            headers = "{}",
            lastError
        });
        return id;
    }

    private async Task<OutboxState> QueryStateAsync(Guid id)
    {
        await using var connection = await GetDataSource().OpenConnectionAsync();
        var row = await connection.QuerySingleAsync<OutboxStateRow>("""
            SELECT available_at AS AvailableAt, failed_at AS FailedAt, discarded_at AS DiscardedAt,
                   locked_by AS LockedBy, locked_until AS LockedUntil, attempt_count AS AttemptCount, last_error AS LastError
            FROM ashlar_security_event_webhook_outbox
            WHERE id = @id
            """, new { id });
        return new OutboxState(
            PostgresAdminQuery.ToDateTimeOffset(row.AvailableAt),
            PostgresAdminQuery.ToNullableDateTimeOffset(row.FailedAt),
            PostgresAdminQuery.ToNullableDateTimeOffset(row.DiscardedAt),
            row.LockedBy,
            PostgresAdminQuery.ToNullableDateTimeOffset(row.LockedUntil),
            row.AttemptCount,
            row.LastError);
    }

    private sealed record OutboxState(
        DateTimeOffset AvailableAt,
        DateTimeOffset? FailedAt,
        DateTimeOffset? DiscardedAt,
        string? LockedBy,
        DateTimeOffset? LockedUntil,
        int AttemptCount,
        string? LastError);

    private sealed class OutboxStateRow
    {
        public DateTime AvailableAt { get; init; }
        public DateTime? FailedAt { get; init; }
        public DateTime? DiscardedAt { get; init; }
        public string? LockedBy { get; init; }
        public DateTime? LockedUntil { get; init; }
        public int AttemptCount { get; init; }
        public string? LastError { get; init; }
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
