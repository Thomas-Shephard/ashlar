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
        var options = Options.Create(new RedisAuthenticationRateLimiterOptions());

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
            Options.Create(new RedisAuthenticationRateLimiterOptions()),
            new FakeTimeProvider());

        Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await limiter.CheckAsync(
            new Ashlar.Identity.RateLimiting.Models.RateLimitAttempt { Key = "test" },
            new Ashlar.Identity.RateLimiting.Models.RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromTicks(1) }));
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
            Options.Create(new RedisAuthenticationRateLimiterOptions()),
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
            Options.Create(new RedisAuthenticationRateLimiterOptions()),
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
        }
    }
}
