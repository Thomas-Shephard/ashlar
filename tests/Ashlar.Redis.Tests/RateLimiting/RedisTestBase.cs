using DotNet.Testcontainers.Builders;
using StackExchange.Redis;
using Testcontainers.Redis;

namespace Ashlar.Redis.Tests.RateLimiting;

internal abstract class RedisTestBase
{
    private static readonly SemaphoreSlim ContainerLock = new(1, 1);
    private static readonly Lazy<RedisContainer> RedisContainer = new(() => new RedisBuilder("redis:7-alpine").Build());
    private static bool _containerStarted;

    private Lazy<ConnectionMultiplexer>? _connection;

    [OneTimeSetUp]
    public virtual async Task OneTimeSetUp()
    {
        try
        {
            await EnsureContainerStartedAsync();
        }
        catch (DockerUnavailableException ex)
        {
            Assert.Ignore($"Redis integration tests require Docker/Testcontainers. {ex.Message}");
        }
    }

    [OneTimeTearDown]
    public virtual async Task OneTimeTearDown()
    {
        if (_connection?.IsValueCreated == true)
        {
            await _connection.Value.DisposeAsync();
        }
    }

    protected static string GetConnectionString()
    {
        return RedisContainer.Value.GetConnectionString();
    }

    protected IConnectionMultiplexer GetConnection()
    {
        _connection ??= new Lazy<ConnectionMultiplexer>(CreateConnection);
        return _connection.Value;
    }

    protected async Task FlushDatabaseAsync()
    {
        foreach (var endpoint in GetConnection().GetEndPoints())
        {
            var server = GetConnection().GetServer(endpoint);
            await server.FlushDatabaseAsync();
        }
    }

    private static async Task EnsureContainerStartedAsync()
    {
        if (_containerStarted)
        {
            return;
        }

        await ContainerLock.WaitAsync();
        try
        {
            if (!_containerStarted)
            {
                await RedisContainer.Value.StartAsync();
                _containerStarted = true;
            }
        }
        finally
        {
            ContainerLock.Release();
        }
    }

    private static ConnectionMultiplexer CreateConnection()
    {
        var configuration = ConfigurationOptions.Parse(GetConnectionString());
        configuration.AllowAdmin = true;
        return ConnectionMultiplexer.Connect(configuration);
    }
}
