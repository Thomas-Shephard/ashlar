namespace Ashlar.Postgres.Connections;

using Microsoft.Extensions.Logging;
using Npgsql;

internal interface IPostgresConnectionProvider
{
    ValueTask<PostgresConnectionHandle> GetConnectionAsync(CancellationToken cancellationToken);
}

internal sealed class PostgresTransactionManagerOwner : IPostgresConnectionProvider, IDisposable, IAsyncDisposable
{
    public PostgresTransactionManagerOwner(NpgsqlDataSource dataSource, ILogger<PostgresTransactionManager>? logger = null)
    {
        Value = new PostgresTransactionManager(dataSource, logger);
    }

    internal PostgresTransactionManager Value { get; }

    public ValueTask<PostgresConnectionHandle> GetConnectionAsync(CancellationToken cancellationToken) =>
        Value.GetConnectionAsync(cancellationToken);

    public void Dispose() => Value.DisposeAsync().AsTask().GetAwaiter().GetResult();

    public ValueTask DisposeAsync() => Value.DisposeAsync();
}
