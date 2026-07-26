namespace Ashlar.Postgres.Connections;

using Microsoft.Extensions.Logging;
using Npgsql;

internal interface IPostgresConnectionProvider
{
    ValueTask<PostgresConnectionHandle> GetConnectionAsync(CancellationToken cancellationToken);
}

internal sealed class PostgresTransactionManagerOwner(NpgsqlDataSource dataSource, ILogger<PostgresTransactionManager>? logger = null) : IPostgresConnectionProvider, IDisposable, IAsyncDisposable
{
    internal PostgresTransactionManager Value { get; } = new PostgresTransactionManager(dataSource, logger);

    public ValueTask<PostgresConnectionHandle> GetConnectionAsync(CancellationToken cancellationToken) =>
        Value.GetConnectionAsync(cancellationToken);

    public void Dispose() => Value.DisposeAsync().AsTask().GetAwaiter().GetResult();

    public ValueTask DisposeAsync() => Value.DisposeAsync();
}
