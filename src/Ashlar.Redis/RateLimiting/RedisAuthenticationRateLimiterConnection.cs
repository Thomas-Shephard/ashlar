using StackExchange.Redis;

namespace Ashlar.Redis.RateLimiting;

internal sealed class RedisAuthenticationRateLimiterConnection : IDisposable, IAsyncDisposable
{
    private readonly Lazy<Task<IConnectionMultiplexer>> _connection;
    private readonly bool _ownsConnection;

    public RedisAuthenticationRateLimiterConnection(Lazy<Task<IConnectionMultiplexer>> connection, bool ownsConnection)
    {
        ArgumentNullException.ThrowIfNull(connection);

        _connection = connection;
        _ownsConnection = ownsConnection;
    }

    public ValueTask<IConnectionMultiplexer> GetConnectionAsync()
    {
        return new ValueTask<IConnectionMultiplexer>(_connection.Value);
    }

    public void Dispose()
    {
        if (!_ownsConnection || !_connection.IsValueCreated)
        {
            return;
        }

        DisposeConnectionWhenAvailable(_connection.Value);
    }

    public async ValueTask DisposeAsync()
    {
        if (!_ownsConnection || !_connection.IsValueCreated)
        {
            return;
        }

        await DisposeConnectionWhenAvailableAsync(_connection.Value);
    }

    private static void DisposeConnectionWhenAvailable(Task<IConnectionMultiplexer> connectionTask)
    {
        if (connectionTask.IsCompletedSuccessfully)
        {
            connectionTask.Result.Dispose();
            return;
        }

        _ = connectionTask.ContinueWith(
            task =>
            {
                if (task.IsCompletedSuccessfully)
                {
                    task.Result.Dispose();
                }
            },
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    private static async ValueTask DisposeConnectionWhenAvailableAsync(Task<IConnectionMultiplexer> connectionTask)
    {
        if (connectionTask.IsCompletedSuccessfully)
        {
            await connectionTask.Result.DisposeAsync();
            return;
        }

        _ = connectionTask.ContinueWith(
            task =>
            {
                if (task.IsCompletedSuccessfully)
                {
                    _ = DisposeCompletedConnectionAsync(task.Result);
                }
            },
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    private static async Task DisposeCompletedConnectionAsync(IConnectionMultiplexer connection)
    {
        await connection.DisposeAsync();
    }
}
