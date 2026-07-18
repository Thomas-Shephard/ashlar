namespace Ashlar.Sqlite.Connections;

using Microsoft.Extensions.Logging;

internal interface ISqliteConnectionProvider
{
    ValueTask<SqliteConnectionHandle> GetConnectionAsync(CancellationToken cancellationToken);
}

internal sealed class SqliteTransactionManagerOwner : ISqliteConnectionProvider, IDisposable, IAsyncDisposable
{
    public SqliteTransactionManagerOwner(SqliteConnectionFactory connectionFactory, ILogger<SqliteTransactionManager>? logger = null)
    {
        Value = new SqliteTransactionManager(connectionFactory, logger);
    }

    internal SqliteTransactionManager Value { get; }

    public ValueTask<SqliteConnectionHandle> GetConnectionAsync(CancellationToken cancellationToken) =>
        Value.GetConnectionAsync(cancellationToken);

    public void Dispose() => Value.DisposeAsync().AsTask().GetAwaiter().GetResult();

    public ValueTask DisposeAsync() => Value.DisposeAsync();
}
