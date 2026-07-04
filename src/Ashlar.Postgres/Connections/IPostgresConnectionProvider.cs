namespace Ashlar.Postgres.Connections;

internal interface IPostgresConnectionProvider
{
    ValueTask<PostgresConnectionHandle> GetConnectionAsync(CancellationToken cancellationToken);
}
