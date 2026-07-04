namespace Ashlar.Sqlite.Connections;

internal interface ISqliteConnectionProvider
{
    ValueTask<SqliteConnectionHandle> GetConnectionAsync(CancellationToken cancellationToken);
}
