using Moq;
using StackExchange.Redis;

namespace Ashlar.Redis.Tests.RateLimiting;

internal sealed class RedisAuthenticationRateLimiterConnectionTests
{
    [Test]
    public async Task DisposeDisposesOwnedCreatedConnection()
    {
        var multiplexer = new Mock<IConnectionMultiplexer>(MockBehavior.Strict);
        multiplexer.Setup(redis => redis.Dispose());
        var connection = new RedisAuthenticationRateLimiterConnection(new Lazy<Task<IConnectionMultiplexer>>(() => Task.FromResult(multiplexer.Object)), true);

        _ = await connection.GetConnectionAsync();
        connection.Dispose();

        multiplexer.Verify(redis => redis.Dispose(), Times.Once);
    }

    [Test]
    public void DisposeDoesNotCreateOwnedUncreatedConnection()
    {
        var created = false;
        var connection = new RedisAuthenticationRateLimiterConnection(new Lazy<Task<IConnectionMultiplexer>>(() =>
        {
            created = true;
            return Task.FromResult(Mock.Of<IConnectionMultiplexer>());
        }), true);

        connection.Dispose();

        Assert.That(created, Is.False);
    }

    [Test]
    public async Task DisposeDoesNotBlockOnOwnedIncompleteConnectionTask()
    {
        var multiplexer = new Mock<IConnectionMultiplexer>(MockBehavior.Strict);
        multiplexer.Setup(redis => redis.Dispose());
        var source = new TaskCompletionSource<IConnectionMultiplexer>();
        var connection = new RedisAuthenticationRateLimiterConnection(new Lazy<Task<IConnectionMultiplexer>>(() => source.Task), true);

        var connectionTask = connection.GetConnectionAsync().AsTask();
        connection.Dispose();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(source.Task.IsCompleted, Is.False);
            Assert.That(connectionTask.IsCompleted, Is.False);
        }
        source.SetResult(multiplexer.Object);
        _ = await connectionTask;
        multiplexer.Verify(redis => redis.Dispose(), Times.Once);
    }

    [Test]
    public void DisposeDoesNotThrowForOwnedFaultedConnectionTask()
    {
        var connection = new RedisAuthenticationRateLimiterConnection(
            new Lazy<Task<IConnectionMultiplexer>>(() => Task.FromException<IConnectionMultiplexer>(new InvalidOperationException("connect failed"))),
            true);

        _ = connection.GetConnectionAsync().AsTask();

        Assert.DoesNotThrow(() => connection.Dispose());
    }

    [Test]
    public async Task DisposeDoesNotDisposeUnownedCreatedConnection()
    {
        var multiplexer = new Mock<IConnectionMultiplexer>(MockBehavior.Strict);
        var connection = new RedisAuthenticationRateLimiterConnection(new Lazy<Task<IConnectionMultiplexer>>(() => Task.FromResult(multiplexer.Object)), false);

        _ = await connection.GetConnectionAsync();
        connection.Dispose();

        multiplexer.Verify(redis => redis.Dispose(), Times.Never);
    }

    [Test]
    public async Task DisposeAsyncDisposesOwnedCreatedConnection()
    {
        var multiplexer = new Mock<IConnectionMultiplexer>(MockBehavior.Strict);
        multiplexer.Setup(redis => redis.DisposeAsync()).Returns(ValueTask.CompletedTask);
        var connection = new RedisAuthenticationRateLimiterConnection(new Lazy<Task<IConnectionMultiplexer>>(() => Task.FromResult(multiplexer.Object)), true);

        _ = await connection.GetConnectionAsync();
        await connection.DisposeAsync();

        multiplexer.Verify(redis => redis.DisposeAsync(), Times.Once);
    }

    [Test]
    public async Task DisposeAsyncDoesNotCreateOwnedUncreatedConnection()
    {
        var created = false;
        var connection = new RedisAuthenticationRateLimiterConnection(new Lazy<Task<IConnectionMultiplexer>>(() =>
        {
            created = true;
            return Task.FromResult(Mock.Of<IConnectionMultiplexer>());
        }), true);

        await connection.DisposeAsync();

        Assert.That(created, Is.False);
    }

    [Test]
    public async Task DisposeAsyncDoesNotAwaitOwnedIncompleteConnectionTask()
    {
        var multiplexer = new Mock<IConnectionMultiplexer>(MockBehavior.Strict);
        multiplexer.Setup(redis => redis.DisposeAsync()).Returns(ValueTask.CompletedTask);
        var source = new TaskCompletionSource<IConnectionMultiplexer>();
        var connection = new RedisAuthenticationRateLimiterConnection(new Lazy<Task<IConnectionMultiplexer>>(() => source.Task), true);

        var connectionTask = connection.GetConnectionAsync().AsTask();
        await connection.DisposeAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(source.Task.IsCompleted, Is.False);
            Assert.That(connectionTask.IsCompleted, Is.False);
        }
        source.SetResult(multiplexer.Object);
        _ = await connectionTask;
        multiplexer.Verify(redis => redis.DisposeAsync(), Times.Once);
    }

    [Test]
    public void DisposeAsyncDoesNotThrowForOwnedFaultedConnectionTask()
    {
        var connection = new RedisAuthenticationRateLimiterConnection(
            new Lazy<Task<IConnectionMultiplexer>>(() => Task.FromException<IConnectionMultiplexer>(new InvalidOperationException("connect failed"))),
            true);

        _ = connection.GetConnectionAsync().AsTask();

        Assert.DoesNotThrowAsync(async () => await connection.DisposeAsync());
    }

    [Test]
    public async Task DisposeAsyncDoesNotDisposeUnownedCreatedConnection()
    {
        var multiplexer = new Mock<IConnectionMultiplexer>(MockBehavior.Strict);
        var connection = new RedisAuthenticationRateLimiterConnection(new Lazy<Task<IConnectionMultiplexer>>(() => Task.FromResult(multiplexer.Object)), false);

        _ = await connection.GetConnectionAsync();
        await connection.DisposeAsync();

        multiplexer.Verify(redis => redis.DisposeAsync(), Times.Never);
    }
}
