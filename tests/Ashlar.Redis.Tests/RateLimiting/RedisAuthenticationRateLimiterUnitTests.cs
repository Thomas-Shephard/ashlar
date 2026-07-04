using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using StackExchange.Redis;

namespace Ashlar.Redis.Tests.RateLimiting;

internal sealed class RedisAuthenticationRateLimiterUnitTests
{
    [Test]
    public void ConstructorRejectsNullArguments()
    {
        var connection = Mock.Of<IConnectionMultiplexer>();
        var options = ValidOptions();

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new RedisAuthenticationRateLimiter((IConnectionMultiplexer)null!, options, TimeProvider.System));
            Assert.Throws<ArgumentNullException>(() => _ = new RedisAuthenticationRateLimiter(connection, null!, TimeProvider.System));
            Assert.Throws<ArgumentNullException>(() => _ = new RedisAuthenticationRateLimiter(connection, options, null!));
        }
    }

    [Test]
    public void ConstructorRejectsInvalidOptions()
    {
        var connection = Mock.Of<IConnectionMultiplexer>();
        var options = Options.Create(new RedisAuthenticationRateLimiterOptions { KeyPrefix = "invalid prefix" });

        Assert.Throws<ArgumentException>(() => _ = new RedisAuthenticationRateLimiter(connection, options, TimeProvider.System));
    }

    [Test]
    public void WrapperConstructorRejectsInvalidOptions()
    {
        var connection = new RedisAuthenticationRateLimiterConnection(new Lazy<Task<IConnectionMultiplexer>>(() => Task.FromResult(Mock.Of<IConnectionMultiplexer>())), false);
        var options = Options.Create(new RedisAuthenticationRateLimiterOptions { KeyPrefix = "invalid prefix" });

        Assert.Throws<ArgumentException>(() => _ = new RedisAuthenticationRateLimiter(connection, options, TimeProvider.System));
    }

    [Test]
    public void CheckAsyncRejectsSubMillisecondWindow()
    {
        var database = Mock.Of<IDatabase>();
        var connection = new Mock<IConnectionMultiplexer>(MockBehavior.Strict);
        connection
            .Setup(redis => redis.GetDatabase(-1, null))
            .Returns(database);
        var limiter = new RedisAuthenticationRateLimiter(
            connection.Object,
            ValidOptions(),
            new FakeTimeProvider());

        Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await limiter.CheckAsync(
            new Ashlar.Identity.RateLimiting.Models.RateLimitAttempt { Key = "test" },
            new Ashlar.Identity.RateLimiting.Models.RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromTicks(1) }));
    }

    [Test]
    public void CheckAsyncObservesCancellationBeforeRedisWork()
    {
        var connection = new Mock<IConnectionMultiplexer>(MockBehavior.Strict);
        var limiter = new RedisAuthenticationRateLimiter(
            connection.Object,
            ValidOptions(),
            new FakeTimeProvider());
        using var cancellationTokenSource = new CancellationTokenSource();
        cancellationTokenSource.Cancel();

        Assert.ThrowsAsync<OperationCanceledException>(async () => await limiter.CheckAsync(
            new Ashlar.Identity.RateLimiting.Models.RateLimitAttempt { Key = "cancelled" },
            new Ashlar.Identity.RateLimiting.Models.RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(1) },
            cancellationTokenSource.Token));
        connection.Verify(redis => redis.GetDatabase(It.IsAny<int>(), It.IsAny<object>()), Times.Never);
    }

    [Test]
    public void CheckAsyncRejectsNullRedisScriptResponse()
    {
        var database = new Mock<IDatabase>(MockBehavior.Strict);
        database
            .Setup(redis => redis.ScriptEvaluateAsync(
                It.IsAny<string>(),
                It.IsAny<RedisKey[]>(),
                It.IsAny<RedisValue[]>(),
                CommandFlags.None))
            .ReturnsAsync(RedisResult.Create(RedisValue.Null));

        var connection = new Mock<IConnectionMultiplexer>(MockBehavior.Strict);
        connection
            .Setup(redis => redis.GetDatabase(-1, null))
            .Returns(database.Object);
        var limiter = new RedisAuthenticationRateLimiter(
            connection.Object,
            ValidOptions(),
            new FakeTimeProvider());

        Assert.ThrowsAsync<InvalidOperationException>(async () => await limiter.CheckAsync(
            new Ashlar.Identity.RateLimiting.Models.RateLimitAttempt { Key = "test" },
            new Ashlar.Identity.RateLimiting.Models.RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(1) }));
    }

    [Test]
    public void CheckAsyncRejectsScalarRedisScriptResponse()
    {
        var database = new Mock<IDatabase>(MockBehavior.Strict);
        database
            .Setup(redis => redis.ScriptEvaluateAsync(
                It.IsAny<string>(),
                It.IsAny<RedisKey[]>(),
                It.IsAny<RedisValue[]>(),
                CommandFlags.None))
            .ReturnsAsync(RedisResult.Create(1));

        var connection = new Mock<IConnectionMultiplexer>(MockBehavior.Strict);
        connection
            .Setup(redis => redis.GetDatabase(-1, null))
            .Returns(database.Object);
        var limiter = new RedisAuthenticationRateLimiter(
            connection.Object,
            ValidOptions(),
            new FakeTimeProvider());

        Assert.ThrowsAsync<InvalidOperationException>(async () => await limiter.CheckAsync(
            new Ashlar.Identity.RateLimiting.Models.RateLimitAttempt { Key = "test" },
            new Ashlar.Identity.RateLimiting.Models.RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(1) }));
    }

    [Test]
    public void CheckAsyncRejectsUnexpectedRedisScriptResponseLength()
    {
        var database = new Mock<IDatabase>(MockBehavior.Strict);
        database
            .Setup(redis => redis.ScriptEvaluateAsync(
                It.IsAny<string>(),
                It.IsAny<RedisKey[]>(),
                It.IsAny<RedisValue[]>(),
                CommandFlags.None))
            .ReturnsAsync(RedisResult.Create([RedisResult.Create(0)]));

        var connection = new Mock<IConnectionMultiplexer>(MockBehavior.Strict);
        connection
            .Setup(redis => redis.GetDatabase(-1, null))
            .Returns(database.Object);
        var limiter = new RedisAuthenticationRateLimiter(
            connection.Object,
            ValidOptions(),
            new FakeTimeProvider());

        Assert.ThrowsAsync<InvalidOperationException>(async () => await limiter.CheckAsync(
            new Ashlar.Identity.RateLimiting.Models.RateLimitAttempt { Key = "test" },
            new Ashlar.Identity.RateLimiting.Models.RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(1) }));
    }

    [Test]
    public void KeyBuilderLengthPrefixesPurposeToPreventDelimiterCollisions()
    {
        var first = RedisRateLimitKeyBuilder.Build("ashlar:test", "A\nB", "C");
        var second = RedisRateLimitKeyBuilder.Build("ashlar:test", "A", "B\nC");

        Assert.That(first, Is.Not.EqualTo(second));
    }

    [Test]
    public void KeyBuilderSupportsLongHashMaterial()
    {
        var key = RedisRateLimitKeyBuilder.Build("ashlar:test:", new string('p', 200), new string('k', 200));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(key, Does.StartWith("ashlar:test:auth:"));
            Assert.That(key, Has.Length.EqualTo("ashlar:test:auth:".Length + 64));
            Assert.That(key["ashlar:test:auth:".Length..], Does.Match("^[0-9a-f]{64}$"));
        }
    }

    [TestCase("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", true)]
    [TestCase("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde", false)]
    [TestCase("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0", false)]
    [TestCase("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg", false)]
    [TestCase("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", false)]
    [TestCase("0123456789abcdef0123456789abcdef:../../0123456789abcdef01234567a", false)]
    public void KeyBuilderValidatesEmittedBucketIdShape(string bucketId, bool expected)
    {
        Assert.That(RedisRateLimitKeyBuilder.IsBucketId(bucketId), Is.EqualTo(expected));
    }

    [Test]
    public void KeyBuilderIsolatesAppSpecificPrefixes()
    {
        var first = RedisRateLimitKeyBuilder.Build("first-app:ashlar:rate-limits", "login", "same-key");
        var second = RedisRateLimitKeyBuilder.Build("second-app:ashlar:rate-limits", "login", "same-key");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(first, Does.StartWith("first-app:ashlar:rate-limits:auth:"));
            Assert.That(second, Does.StartWith("second-app:ashlar:rate-limits:auth:"));
            Assert.That(first, Is.Not.EqualTo(second));
        }
    }

    [Test]
    public void KeyBuilderTrimsTrailingPrefixColonsConsistently()
    {
        var normalized = RedisRateLimitKeyBuilder.Build("my-app:ashlar:rate-limits", "login", "same-key");
        var trailing = RedisRateLimitKeyBuilder.Build("my-app:ashlar:rate-limits::", "login", "same-key");

        Assert.That(trailing, Is.EqualTo(normalized));
    }

    private static IOptions<RedisAuthenticationRateLimiterOptions> ValidOptions()
    {
        return Options.Create(new RedisAuthenticationRateLimiterOptions { KeyPrefix = "unit-test:ashlar:rate-limits" });
    }
}
