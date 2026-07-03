using Ashlar.Operational.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using StackExchange.Redis;

namespace Ashlar.Redis.Tests.RateLimiting;

internal sealed class RedisAuthenticationRateLimiterDiagnosticsUnitTests
{
    private static readonly DateTimeOffset CheckedAt = new(2026, 5, 22, 15, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task CheckAsyncReturnsUnknownWithoutSensitiveDetailsWhenRedisPingFails()
    {
        var database = new Mock<IDatabase>(MockBehavior.Strict);
        database
            .Setup(redis => redis.PingAsync(CommandFlags.None))
            .ThrowsAsync(new InvalidOperationException("Sensitive Redis failure."));

        var connection = new Mock<IConnectionMultiplexer>(MockBehavior.Strict);
        connection
            .Setup(redis => redis.GetDatabase(3, null))
            .Returns(database.Object);

        var diagnostics = new RedisAuthenticationRateLimiterDiagnostics(
            new RedisAuthenticationRateLimiterConnection(new Lazy<Task<IConnectionMultiplexer>>(() => Task.FromResult(connection.Object)), false),
            Options.Create(new RedisAuthenticationRateLimiterOptions { KeyPrefix = "unit-test:ashlar:rate-limits", Database = 3 }),
            new FakeTimeProvider(CheckedAt),
            NullLogger<RedisAuthenticationRateLimiterDiagnostics>.Instance);

        var result = await diagnostics.CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Unknown));
            Assert.That(result.ProviderName, Is.EqualTo("Redis"));
            Assert.That(result.Reason, Is.EqualTo("Authentication rate limiter diagnostics could not query provider state."));
            Assert.That(result.Reason, Does.Not.Contain("Sensitive"));
            Assert.That(result.Distributed, Is.True);
            Assert.That(result.Persistent, Is.False);
        }
    }

    [Test]
    public void CheckAsyncObservesCancellationBeforeRedisWork()
    {
        var created = false;
        var connection = new RedisAuthenticationRateLimiterConnection(new Lazy<Task<IConnectionMultiplexer>>(() =>
        {
            created = true;
            return Task.FromResult(Mock.Of<IConnectionMultiplexer>());
        }), false);
        var diagnostics = new RedisAuthenticationRateLimiterDiagnostics(
            connection,
            ValidOptions(),
            new FakeTimeProvider(CheckedAt),
            NullLogger<RedisAuthenticationRateLimiterDiagnostics>.Instance);
        using var cancellationTokenSource = new CancellationTokenSource();
        cancellationTokenSource.Cancel();

        Assert.ThrowsAsync<OperationCanceledException>(async () => await diagnostics.CheckAsync(cancellationTokenSource.Token));
        Assert.That(created, Is.False);
    }

    [Test]
    public void ConstructorRejectsNullArguments()
    {
        var connection = new RedisAuthenticationRateLimiterConnection(new Lazy<Task<IConnectionMultiplexer>>(() => Task.FromResult(Mock.Of<IConnectionMultiplexer>())), false);
        var options = ValidOptions();
        var timeProvider = new FakeTimeProvider(CheckedAt);

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new RedisAuthenticationRateLimiterDiagnostics(null!, options, timeProvider));
            Assert.Throws<ArgumentNullException>(() => _ = new RedisAuthenticationRateLimiterDiagnostics(connection, null!, timeProvider));
            Assert.Throws<ArgumentNullException>(() => _ = new RedisAuthenticationRateLimiterDiagnostics(connection, options, null!));
        }
    }

    [Test]
    public void ConstructorRejectsInvalidOptions()
    {
        var connection = new RedisAuthenticationRateLimiterConnection(new Lazy<Task<IConnectionMultiplexer>>(() => Task.FromResult(Mock.Of<IConnectionMultiplexer>())), false);
        var timeProvider = new FakeTimeProvider(CheckedAt);

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentException>(() => _ = new RedisAuthenticationRateLimiterDiagnostics(connection, Options.Create(new RedisAuthenticationRateLimiterOptions()), timeProvider));
            Assert.Throws<ArgumentException>(() => _ = new RedisAuthenticationRateLimiterDiagnostics(
                connection,
                Options.Create(new RedisAuthenticationRateLimiterOptions { KeyPrefix = "ashlar:rate-limits" }),
                timeProvider));
        }
    }

    private static IOptions<RedisAuthenticationRateLimiterOptions> ValidOptions()
    {
        return Options.Create(new RedisAuthenticationRateLimiterOptions { KeyPrefix = "unit-test:ashlar:rate-limits" });
    }
}
