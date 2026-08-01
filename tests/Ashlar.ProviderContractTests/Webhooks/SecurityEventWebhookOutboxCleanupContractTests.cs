using Ashlar.Operational;
using System.Text;

namespace Ashlar.ProviderContractTests.Webhooks;

/// <summary>Verifies terminal webhook retention boundaries, deletion counts, batching, and disabled categories.</summary>
public abstract class SecurityEventWebhookOutboxCleanupContractTests : ProviderContractFixture
{
    /// <summary>Fixed timestamp used to create deterministic provider rows.</summary>
    protected static readonly DateTimeOffset CleanupNow = new(2026, 5, 24, 12, 0, 0, TimeSpan.Zero);

    /// <summary>Persists one webhook delivery in the supplied state and age for cleanup.</summary>
    /// <param name="row">Provider-neutral state to persist before the assertion.</param>
    protected abstract Task SeedWebhookOutboxCleanupRowAsync(SeedWebhookCleanupRow row);

    /// <summary>Counts every webhook delivery currently stored by the provider.</summary>
    /// <returns>The number of webhook outbox rows.</returns>
    protected abstract Task<int> CountWebhookOutboxRowsAsync();

    /// <summary>Counts stored webhook deliveries whose endpoint name exactly matches the supplied value.</summary>
    /// <param name="endpointName">Webhook endpoint whose rows are counted.</param>
    /// <returns>The number of rows belonging to the endpoint.</returns>
    protected abstract Task<int> CountWebhookOutboxRowsByEndpointNameAsync(string endpointName);

    /// <summary>Runs cleanup with sent, failed, and discarded webhook retention disabled.</summary>
    /// <returns>The cleanup counts reported with webhook retention disabled.</returns>
    protected abstract Task<AshlarCleanupResult> RunCleanupWithNullWebhookRetentionsAsync();

    /// <summary>Runs one cleanup pass using the fixture's configured webhook retention and batch size.</summary>
    /// <param name="serviceProvider">Scoped services participating in the contract operation.</param>
    /// <returns>The cleanup counts reported by the provider.</returns>
    protected abstract Task<AshlarCleanupResult> RunCleanupAsync(IServiceProvider serviceProvider);

    /// <summary>Deletes expired sent, failed, and discarded deliveries while preserving active and recent rows.</summary>
    [Test]
    public async Task CleanupAsyncRemovesOnlyTerminalWebhookRowsOlderThanRetentionAndReturnsCounts()
    {
        await SeedWebhookOutboxCleanupRowAsync(SeedWebhookCleanupRow.Sent("old-sent", CleanupNow.AddDays(-8)));
        await SeedWebhookOutboxCleanupRowAsync(SeedWebhookCleanupRow.Sent("recent-sent", CleanupNow.AddDays(-6)));
        await SeedWebhookOutboxCleanupRowAsync(SeedWebhookCleanupRow.Failed("old-failed", CleanupNow.AddDays(-31)));
        await SeedWebhookOutboxCleanupRowAsync(SeedWebhookCleanupRow.Failed("recent-failed", CleanupNow.AddDays(-29)));
        await SeedWebhookOutboxCleanupRowAsync(SeedWebhookCleanupRow.Discarded("old-discarded", CleanupNow.AddDays(-31)));
        await SeedWebhookOutboxCleanupRowAsync(SeedWebhookCleanupRow.Discarded("recent-discarded", CleanupNow.AddDays(-29)));
        await SeedWebhookOutboxCleanupRowAsync(SeedWebhookCleanupRow.Pending("old-pending", CleanupNow.AddDays(-90)));
        await SeedWebhookOutboxCleanupRowAsync(SeedWebhookCleanupRow.Scheduled("old-scheduled", CleanupNow.AddDays(-90)));
        await SeedWebhookOutboxCleanupRowAsync(SeedWebhookCleanupRow.Locked("old-locked", CleanupNow.AddDays(-90), CleanupNow.AddMinutes(5)));
        await SeedWebhookOutboxCleanupRowAsync(SeedWebhookCleanupRow.Retryable("old-retryable", CleanupNow.AddDays(-90)));
        await using var scope = CreateAsyncScope();

        var result = await RunCleanupAsync(scope.ServiceProvider);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.SentSecurityEventWebhooks, Is.EqualTo(1));
            Assert.That(result.FailedSecurityEventWebhooks, Is.EqualTo(1));
            Assert.That(result.DiscardedSecurityEventWebhooks, Is.EqualTo(1));
            Assert.That(await CountWebhookOutboxRowsAsync(), Is.EqualTo(7));
            Assert.That(await CountWebhookOutboxRowsByEndpointNameAsync("old-sent"), Is.Zero);
            Assert.That(await CountWebhookOutboxRowsByEndpointNameAsync("old-failed"), Is.Zero);
            Assert.That(await CountWebhookOutboxRowsByEndpointNameAsync("old-discarded"), Is.Zero);
            Assert.That(await CountWebhookOutboxRowsByEndpointNameAsync("recent-sent"), Is.EqualTo(1));
            Assert.That(await CountWebhookOutboxRowsByEndpointNameAsync("recent-failed"), Is.EqualTo(1));
            Assert.That(await CountWebhookOutboxRowsByEndpointNameAsync("recent-discarded"), Is.EqualTo(1));
            Assert.That(await CountWebhookOutboxRowsByEndpointNameAsync("old-pending"), Is.EqualTo(1));
            Assert.That(await CountWebhookOutboxRowsByEndpointNameAsync("old-scheduled"), Is.EqualTo(1));
            Assert.That(await CountWebhookOutboxRowsByEndpointNameAsync("old-locked"), Is.EqualTo(1));
            Assert.That(await CountWebhookOutboxRowsByEndpointNameAsync("old-retryable"), Is.EqualTo(1));
        }
    }

    /// <summary>Deletes no more webhook deliveries than the configured batch limit in one pass.</summary>
    [Test]
    public async Task CleanupAsyncRespectsBatchSizeForWebhookRows()
    {
        await SeedWebhookOutboxCleanupRowAsync(SeedWebhookCleanupRow.Sent("old-sent-one", CleanupNow.AddDays(-8)));
        await SeedWebhookOutboxCleanupRowAsync(SeedWebhookCleanupRow.Sent("old-sent-two", CleanupNow.AddDays(-8).AddMinutes(1)));
        await SeedWebhookOutboxCleanupRowAsync(SeedWebhookCleanupRow.Sent("old-sent-three", CleanupNow.AddDays(-8).AddMinutes(2)));
        await using var scope = CreateAsyncScope();
        var first = await RunCleanupAsync(scope.ServiceProvider);
        var second = await RunCleanupAsync(scope.ServiceProvider);
        var third = await RunCleanupAsync(scope.ServiceProvider);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(first.SentSecurityEventWebhooks, Is.EqualTo(2));
            Assert.That(second.SentSecurityEventWebhooks, Is.EqualTo(1));
            Assert.That(third.SentSecurityEventWebhooks, Is.Zero);
            Assert.That(await CountWebhookOutboxRowsAsync(), Is.Zero);
        }
    }

    /// <summary>Preserves sent, failed, and discarded deliveries when their retention periods are disabled.</summary>
    [Test]
    public async Task CleanupAsyncSkipsWebhookCategoriesWithNullRetention()
    {
        await SeedWebhookOutboxCleanupRowAsync(SeedWebhookCleanupRow.Sent("disabled-sent", CleanupNow.AddDays(-90)));
        await SeedWebhookOutboxCleanupRowAsync(SeedWebhookCleanupRow.Failed("disabled-failed", CleanupNow.AddDays(-90)));
        await SeedWebhookOutboxCleanupRowAsync(SeedWebhookCleanupRow.Discarded("disabled-discarded", CleanupNow.AddDays(-90)));

        var result = await RunCleanupWithNullWebhookRetentionsAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.SentSecurityEventWebhooks, Is.Zero);
            Assert.That(result.FailedSecurityEventWebhooks, Is.Zero);
            Assert.That(result.DiscardedSecurityEventWebhooks, Is.Zero);
            Assert.That(await CountWebhookOutboxRowsByEndpointNameAsync("disabled-sent"), Is.EqualTo(1));
            Assert.That(await CountWebhookOutboxRowsByEndpointNameAsync("disabled-failed"), Is.EqualTo(1));
            Assert.That(await CountWebhookOutboxRowsByEndpointNameAsync("disabled-discarded"), Is.EqualTo(1));
        }
    }

    /// <summary>Provider-neutral state used to seed a webhook cleanup row.</summary>
    /// <param name="EndpointName">Webhook endpoint that owns the delivery.</param>
    /// <param name="CreatedAt">Time the delivery was created.</param>
    /// <param name="AvailableAt">Time the delivery becomes eligible for dispatch.</param>
    /// <param name="SentAt">Successful-delivery time, if sent.</param>
    /// <param name="FailedAt">Terminal failure time, if failed.</param>
    /// <param name="DiscardedAt">Time further delivery was abandoned, if discarded.</param>
    /// <param name="LockedUntil">Time the dispatch lock expires, if locked.</param>
    /// <param name="AttemptCount">Number of delivery attempts.</param>
    protected sealed record SeedWebhookCleanupRow(
        string EndpointName,
        DateTimeOffset CreatedAt,
        DateTimeOffset AvailableAt,
        DateTimeOffset? SentAt,
        DateTimeOffset? FailedAt,
        DateTimeOffset? DiscardedAt,
        DateTimeOffset? LockedUntil,
        int AttemptCount)
    {
        /// <summary>Unique event identifier persisted with this seeded row.</summary>
        public Guid EventId { get; } = Guid.NewGuid();

        /// <summary>Serialized event body persisted with this seeded row.</summary>
        public byte[] Body { get; } = Encoding.UTF8.GetBytes("{}");

        /// <summary>Creates a sent row for provider-state assertions.</summary>
        /// <param name="endpointName">Webhook endpoint that owns the seeded delivery.</param>
        /// <param name="sentAt">Terminal successful-delivery time.</param>
        /// <returns>A sent row descriptor.</returns>
        public static SeedWebhookCleanupRow Sent(string endpointName, DateTimeOffset sentAt)
        {
            return new SeedWebhookCleanupRow(endpointName, sentAt, sentAt, sentAt, null, null, null, 1);
        }

        /// <summary>Creates a failed row for provider-state assertions.</summary>
        /// <param name="endpointName">Webhook endpoint that owns the seeded delivery.</param>
        /// <param name="failedAt">Terminal failure time.</param>
        /// <returns>A terminally failed row descriptor.</returns>
        public static SeedWebhookCleanupRow Failed(string endpointName, DateTimeOffset failedAt)
        {
            return new SeedWebhookCleanupRow(endpointName, failedAt, failedAt, null, failedAt, null, null, 3);
        }

        /// <summary>Creates a discarded row for provider-state assertions.</summary>
        /// <param name="endpointName">Webhook endpoint that owns the seeded delivery.</param>
        /// <param name="discardedAt">Time when further delivery was abandoned.</param>
        /// <returns>A discarded row descriptor.</returns>
        public static SeedWebhookCleanupRow Discarded(string endpointName, DateTimeOffset discardedAt)
        {
            return new SeedWebhookCleanupRow(endpointName, discardedAt, discardedAt, null, discardedAt, discardedAt, null, 3);
        }

        /// <summary>Creates a pending row for provider-state assertions.</summary>
        /// <param name="endpointName">Webhook endpoint that owns the seeded delivery.</param>
        /// <param name="createdAt">Creation time to persist.</param>
        /// <returns>A pending row descriptor.</returns>
        public static SeedWebhookCleanupRow Pending(string endpointName, DateTimeOffset createdAt)
        {
            return new SeedWebhookCleanupRow(endpointName, createdAt, createdAt, null, null, null, null, 0);
        }

        /// <summary>Creates a scheduled row for provider-state assertions.</summary>
        /// <param name="endpointName">Webhook endpoint that owns the seeded delivery.</param>
        /// <param name="createdAt">Creation time to persist.</param>
        /// <returns>A scheduled row descriptor.</returns>
        public static SeedWebhookCleanupRow Scheduled(string endpointName, DateTimeOffset createdAt)
        {
            return new SeedWebhookCleanupRow(endpointName, createdAt, CleanupNow.AddMinutes(30), null, null, null, null, 0);
        }

        /// <summary>Creates a locked row for provider-state assertions.</summary>
        /// <param name="endpointName">Webhook endpoint that owns the seeded delivery.</param>
        /// <param name="createdAt">Creation time to persist.</param>
        /// <param name="lockedUntil">Time until which a worker owns the row.</param>
        /// <returns>A locked row descriptor.</returns>
        public static SeedWebhookCleanupRow Locked(string endpointName, DateTimeOffset createdAt, DateTimeOffset lockedUntil)
        {
            return new SeedWebhookCleanupRow(endpointName, createdAt, createdAt, null, null, null, lockedUntil, 0);
        }

        /// <summary>Creates a retryable row for provider-state assertions.</summary>
        /// <param name="endpointName">Webhook endpoint that owns the seeded delivery.</param>
        /// <param name="createdAt">Creation time to persist.</param>
        /// <returns>A retryable row descriptor.</returns>
        public static SeedWebhookCleanupRow Retryable(string endpointName, DateTimeOffset createdAt)
        {
            return new SeedWebhookCleanupRow(endpointName, createdAt, createdAt, null, null, null, null, 1);
        }
    }
}
