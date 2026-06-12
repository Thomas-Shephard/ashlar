using System.Text;

namespace Ashlar.ProviderContractTests.Webhooks;

internal abstract class SecurityEventWebhookOutboxCleanupContractTests : ProviderContractFixture
{
    protected static readonly DateTimeOffset CleanupNow = new(2026, 5, 24, 12, 0, 0, TimeSpan.Zero);

    protected abstract Task SeedWebhookOutboxCleanupRowAsync(SeedWebhookCleanupRow row);

    protected abstract Task<int> CountWebhookOutboxRowsAsync();

    protected abstract Task<int> CountWebhookOutboxRowsByEndpointNameAsync(string endpointName);

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

        var result = await GetCleanupService(scope.ServiceProvider).CleanupAsync();

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

    [Test]
    public async Task CleanupAsyncRespectsBatchSizeForWebhookRows()
    {
        await SeedWebhookOutboxCleanupRowAsync(SeedWebhookCleanupRow.Sent("old-sent-one", CleanupNow.AddDays(-8)));
        await SeedWebhookOutboxCleanupRowAsync(SeedWebhookCleanupRow.Sent("old-sent-two", CleanupNow.AddDays(-8).AddMinutes(1)));
        await SeedWebhookOutboxCleanupRowAsync(SeedWebhookCleanupRow.Sent("old-sent-three", CleanupNow.AddDays(-8).AddMinutes(2)));
        await using var scope = CreateAsyncScope();
        var cleanup = GetCleanupService(scope.ServiceProvider);

        var first = await cleanup.CleanupAsync();
        var second = await cleanup.CleanupAsync();
        var third = await cleanup.CleanupAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(first.SentSecurityEventWebhooks, Is.EqualTo(2));
            Assert.That(second.SentSecurityEventWebhooks, Is.EqualTo(1));
            Assert.That(third.SentSecurityEventWebhooks, Is.Zero);
            Assert.That(await CountWebhookOutboxRowsAsync(), Is.Zero);
        }
    }

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
        public Guid EventId { get; } = Guid.NewGuid();

        public byte[] Body { get; } = Encoding.UTF8.GetBytes("{}");

        public static SeedWebhookCleanupRow Sent(string endpointName, DateTimeOffset sentAt)
        {
            return new SeedWebhookCleanupRow(endpointName, sentAt, sentAt, sentAt, null, null, null, 1);
        }

        public static SeedWebhookCleanupRow Failed(string endpointName, DateTimeOffset failedAt)
        {
            return new SeedWebhookCleanupRow(endpointName, failedAt, failedAt, null, failedAt, null, null, 3);
        }

        public static SeedWebhookCleanupRow Discarded(string endpointName, DateTimeOffset discardedAt)
        {
            return new SeedWebhookCleanupRow(endpointName, discardedAt, discardedAt, null, discardedAt, discardedAt, null, 3);
        }

        public static SeedWebhookCleanupRow Pending(string endpointName, DateTimeOffset createdAt)
        {
            return new SeedWebhookCleanupRow(endpointName, createdAt, createdAt, null, null, null, null, 0);
        }

        public static SeedWebhookCleanupRow Scheduled(string endpointName, DateTimeOffset createdAt)
        {
            return new SeedWebhookCleanupRow(endpointName, createdAt, CleanupNow.AddMinutes(30), null, null, null, null, 0);
        }

        public static SeedWebhookCleanupRow Locked(string endpointName, DateTimeOffset createdAt, DateTimeOffset lockedUntil)
        {
            return new SeedWebhookCleanupRow(endpointName, createdAt, createdAt, null, null, null, lockedUntil, 0);
        }

        public static SeedWebhookCleanupRow Retryable(string endpointName, DateTimeOffset createdAt)
        {
            return new SeedWebhookCleanupRow(endpointName, createdAt, createdAt, null, null, null, null, 1);
        }
    }
}
