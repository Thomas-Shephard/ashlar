namespace Ashlar.Sqlite.Connections;

internal interface ISqliteConnectionProvider
{
    ValueTask<SqliteConnectionHandle> GetConnectionAsync(CancellationToken cancellationToken);
}

internal sealed class SqliteConnectionProvider(SqliteTransactionManager transactionManager) : ISqliteConnectionProvider
{
    public ValueTask<SqliteConnectionHandle> GetConnectionAsync(CancellationToken cancellationToken) =>
        transactionManager.GetConnectionAsync(cancellationToken);
}
