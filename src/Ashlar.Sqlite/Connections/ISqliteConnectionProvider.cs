namespace Ashlar.Sqlite.Connections;

using Microsoft.Extensions.Logging;

internal interface ISqliteConnectionProvider
{
    ValueTask<SqliteConnectionHandle> GetConnectionAsync(CancellationToken cancellationToken);
}

internal sealed class SqliteTransactionManagerOwner(SqliteConnectionFactory connectionFactory, ILogger<SqliteTransactionManager>? logger = null) : ISqliteConnectionProvider, IDisposable, IAsyncDisposable
{
    internal SqliteTransactionManager Value { get; } = new SqliteTransactionManager(connectionFactory, logger);

    public ValueTask<SqliteConnectionHandle> GetConnectionAsync(CancellationToken cancellationToken) =>
        Value.GetConnectionAsync(cancellationToken);

    public void Dispose() => Value.DisposeAsync().AsTask().GetAwaiter().GetResult();

    public ValueTask DisposeAsync() => Value.DisposeAsync();
}
