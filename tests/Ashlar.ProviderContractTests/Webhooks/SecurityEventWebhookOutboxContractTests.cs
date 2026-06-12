using System.Text;
using System.Text.Json;

namespace Ashlar.ProviderContractTests.Webhooks;

internal abstract class SecurityEventWebhookOutboxContractTests : ProviderContractFixture
{
    protected static readonly DateTimeOffset Now = new(2026, 5, 24, 12, 0, 0, TimeSpan.Zero);
    private static readonly AshlarSecurityEventWebhookOutboxStatus[] ExpectedPagedStatuses =
    [
        AshlarSecurityEventWebhookOutboxStatus.Scheduled,
        AshlarSecurityEventWebhookOutboxStatus.Locked
    ];
    private static readonly string[] FailedEndpointNames = ["failed"];
    private static readonly JsonSerializerOptions WebJsonOptions = new(JsonSerializerDefaults.Web);

    protected abstract Task<Guid> SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow row);

    protected abstract Task<WebhookOutboxRowState> ReadWebhookOutboxRowStateAsync(Guid id);

    protected abstract Task<int> CountWebhookOutboxRowsAsync();

    [Test]
    public async Task BrowserListsProviderNeutralStatusesWithPaging()
    {
        await SeedWebhookOutboxRowsAsync();
        await using var scope = CreateAsyncScope();
        var browser = GetSecurityEventWebhookOutboxBrowser(scope.ServiceProvider);

        var page = await browser.ListAsync(new AshlarSecurityEventWebhookOutboxBrowseRequest { Limit = 2, Offset = 1 });
        var failed = await browser.ListAsync(new AshlarSecurityEventWebhookOutboxBrowseRequest
        {
            Statuses = new HashSet<AshlarSecurityEventWebhookOutboxStatus> { AshlarSecurityEventWebhookOutboxStatus.Failed },
            Limit = 10
        });
        var failedDelivery = failed.Deliveries.Single();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(page.Deliveries, Has.Count.EqualTo(2));
            Assert.That(page.HasMore, Is.True);
            Assert.That(page.Deliveries.Select(delivery => delivery.Status), Is.EqualTo(ExpectedPagedStatuses));
            Assert.That(failed.Deliveries.Select(delivery => delivery.EndpointName), Is.EqualTo(FailedEndpointNames));
            Assert.That(failedDelivery.EventType, Is.EqualTo("security.test"));
            Assert.That(failedDelivery.Outcome, Is.EqualTo("success"));
            Assert.That(failedDelivery.LastErrorSummary, Is.EqualTo("delivery failure"));
        }
    }

    [Test]
    public async Task RetryAndDiscardOperateOnlyOnTerminalFailedRows()
    {
        var failed = await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Failed("failed", lastError: "secret https://example.test"));
        var pending = await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Pending("pending"));
        var discarded = await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Discarded("discarded"));
        await using var scope = CreateAsyncScope();
        var operations = GetSecurityEventWebhookOutboxOperations(scope.ServiceProvider);

        var missingRetry = await operations.RetryAsync(CreateOperationRequest(Guid.NewGuid()));
        var retry = await operations.RetryAsync(CreateOperationRequest(failed));
        var retriedState = await ReadWebhookOutboxRowStateAsync(failed);
        var pendingDiscard = await operations.DiscardAsync(CreateOperationRequest(pending));
        var discardedRetry = await operations.RetryAsync(CreateOperationRequest(discarded));
        var failedAgain = await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Failed("failed-discard"));
        var discard = await operations.DiscardAsync(CreateOperationRequest(failedAgain));
        var discardedState = await ReadWebhookOutboxRowStateAsync(failedAgain);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missingRetry.Status, Is.EqualTo(AshlarSecurityEventWebhookOutboxOperationStatus.NotFound));
            Assert.That(retry.Status, Is.EqualTo(AshlarSecurityEventWebhookOutboxOperationStatus.Retried));
            Assert.That(retry.EndpointName, Is.EqualTo("failed"));
            Assert.That(retry.EventType, Is.EqualTo("security.test"));
            Assert.That(retry.Outcome, Is.EqualTo("success"));
            Assert.That(retriedState.FailedAt, Is.Null);
            Assert.That(retriedState.LastError, Is.Null);
            Assert.That(retriedState.LockedBy, Is.Null);
            Assert.That(retriedState.LockedUntil, Is.Null);
            Assert.That(retriedState.AvailableAt, Is.EqualTo(Now));
            Assert.That(pendingDiscard.Status, Is.EqualTo(AshlarSecurityEventWebhookOutboxOperationStatus.NotFailed));
            Assert.That(discardedRetry.Status, Is.EqualTo(AshlarSecurityEventWebhookOutboxOperationStatus.AlreadyDiscarded));
            Assert.That(discard.Status, Is.EqualTo(AshlarSecurityEventWebhookOutboxOperationStatus.Discarded));
            Assert.That(discardedState.DiscardedAt, Is.EqualTo(Now));
            Assert.That(discardedState.LockedBy, Is.Null);
            Assert.That(discardedState.LockedUntil, Is.Null);
        }
    }

    [Test]
    public async Task DiagnosticsAggregateProviderNeutralBucketsAndOldestTimestamps()
    {
        var oldPending = Now.AddMinutes(-20);
        var oldestFailed = Now.AddDays(-2);
        await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Pending("old-pending", createdAt: oldPending, availableAt: oldPending));
        await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Pending("new-pending", createdAt: Now.AddMinutes(-5), availableAt: Now.AddMinutes(-5)));
        await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Pending("scheduled", createdAt: Now.AddMinutes(-4), availableAt: Now.AddMinutes(5)));
        await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Locked("locked", Now.AddMinutes(5)));
        await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Locked("expired", Now.AddMinutes(-1)));
        await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Failed("failed-old", failedAt: oldestFailed));
        await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Failed("failed-new", failedAt: Now.AddDays(-1)));
        await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Discarded("discarded"));
        await using var scope = CreateAsyncScope();

        var result = await GetSecurityEventWebhookOutboxDiagnostics(scope.ServiceProvider).CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Healthy));
            Assert.That(result.PendingCount, Is.EqualTo(3));
            Assert.That(result.ScheduledCount, Is.EqualTo(1));
            Assert.That(result.LockedCount, Is.EqualTo(1));
            Assert.That(result.ExpiredLockCount, Is.EqualTo(1));
            Assert.That(result.FailedCount, Is.EqualTo(2));
            Assert.That(result.OldestPendingAt, Is.EqualTo(oldPending));
            Assert.That(result.OldestFailedAt, Is.EqualTo(oldestFailed));
        }
    }

    [Test]
    public async Task EnqueueParticipatesInAshlarTransactions()
    {
        await using var scope = CreateAsyncScope();
        var transactionProvider = GetTransactionProvider(scope.ServiceProvider)
            ?? throw new InvalidOperationException("Transaction provider is not registered.");
        var enqueuer = GetSecurityEventWebhookEnqueuer(scope.ServiceProvider);

        await using (var transaction = await transactionProvider.BeginTransactionAsync())
        {
            await enqueuer.EnqueueAsync(CreateDelivery("rolled-back"));
            await transaction.RollbackAsync();
        }

        Assert.That(await CountWebhookOutboxRowsAsync(), Is.Zero);

        await using (var transaction = await transactionProvider.BeginTransactionAsync())
        {
            await enqueuer.EnqueueAsync(CreateDelivery("committed"));
            await transaction.CommitAsync();
        }

        Assert.That(await CountWebhookOutboxRowsAsync(), Is.EqualTo(1));
    }

    private async Task SeedWebhookOutboxRowsAsync()
    {
        await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Pending("pending", createdAt: Now.AddMinutes(-5), availableAt: Now.AddMinutes(-5)));
        await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Pending("scheduled", createdAt: Now.AddMinutes(-4), availableAt: Now.AddMinutes(30)));
        await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Locked("locked", Now.AddMinutes(5), createdAt: Now.AddMinutes(-3)));
        await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Locked("expired", Now.AddMinutes(-1), createdAt: Now.AddMinutes(-2)));
        await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Failed("failed", failedAt: Now.AddSeconds(-30), createdAt: Now.AddMinutes(-1), lastError: "delivery failure"));
        await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Sent("sent"));
        await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Discarded("discarded"));
    }

    private static AshlarSecurityEventWebhookOutboxOperationRequest CreateOperationRequest(Guid id)
    {
        return new AshlarSecurityEventWebhookOutboxOperationRequest(id, new AuditContext(Guid.NewGuid(), "203.0.113.9", "agent", "corr"));
    }

    private static AshlarSecurityEventWebhookDelivery CreateDelivery(string endpointName)
    {
        var securityEvent = new AshlarSecurityEvent
        {
            Id = Guid.NewGuid(),
            EventType = "ashlar.sign_in.failed",
            OccurredAt = Now.AddHours(-1),
            Outcome = SecurityEventOutcomes.Failure,
            IpAddress = "203.0.113.10"
        };
        var payload = AshlarSecurityEventWebhookDeliveryFactory.CreatePayload(securityEvent);
        var body = JsonSerializer.SerializeToUtf8Bytes(payload, WebJsonOptions);
        var endpoint = new AshlarSecurityEventWebhookEndpointOptions
        {
            Name = endpointName,
            Uri = new Uri($"https://example.test/{endpointName}"),
            SharedSecret = "shared-secret"
        };
        var headers = AshlarSecurityEventWebhookDeliveryFactory.CreateHeaders(
            endpoint,
            payload,
            body,
            DateTimeOffset.FromUnixTimeSeconds(1_800_000_000));

        return new AshlarSecurityEventWebhookDelivery(
            endpointName,
            endpoint.Uri,
            TimeSpan.FromSeconds(10),
            headers,
            payload);
    }

    protected sealed record SeedWebhookOutboxRow(
        string EndpointName,
        DateTimeOffset CreatedAt,
        DateTimeOffset AvailableAt,
        DateTimeOffset? SentAt,
        DateTimeOffset? FailedAt,
        DateTimeOffset? DiscardedAt,
        string? LockedBy,
        DateTimeOffset? LockedUntil,
        int AttemptCount,
        string? LastError)
    {
        public Guid EventId { get; } = Guid.NewGuid();

        public byte[] Body { get; } = Encoding.UTF8.GetBytes("{}");

        public static SeedWebhookOutboxRow Pending(string endpointName, DateTimeOffset? createdAt = null, DateTimeOffset? availableAt = null)
        {
            return new SeedWebhookOutboxRow(endpointName, createdAt ?? Now, availableAt ?? Now, null, null, null, null, null, 0, null);
        }

        public static SeedWebhookOutboxRow Locked(string endpointName, DateTimeOffset lockedUntil, DateTimeOffset? createdAt = null)
        {
            return new SeedWebhookOutboxRow(endpointName, createdAt ?? Now, Now, null, null, null, "worker", lockedUntil, 0, null);
        }

        public static SeedWebhookOutboxRow Failed(string endpointName, DateTimeOffset? failedAt = null, DateTimeOffset? createdAt = null, string? lastError = "failure")
        {
            var failureTime = failedAt ?? Now.AddMinutes(-1);
            return new SeedWebhookOutboxRow(endpointName, createdAt ?? Now, Now, null, failureTime, null, null, null, 3, lastError);
        }

        public static SeedWebhookOutboxRow Sent(string endpointName)
        {
            return new SeedWebhookOutboxRow(endpointName, Now, Now, Now, null, null, null, null, 1, null);
        }

        public static SeedWebhookOutboxRow Discarded(string endpointName)
        {
            return new SeedWebhookOutboxRow(endpointName, Now, Now, null, Now.AddMinutes(-1), Now, null, null, 3, "discarded");
        }
    }

    protected sealed record WebhookOutboxRowState(
        DateTimeOffset AvailableAt,
        DateTimeOffset? FailedAt,
        DateTimeOffset? DiscardedAt,
        string? LockedBy,
        DateTimeOffset? LockedUntil,
        string? LastError);
}
