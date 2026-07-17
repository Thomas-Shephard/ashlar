namespace Ashlar.Postgres.Connections;

internal interface IPostgresConnectionProvider
{
    ValueTask<PostgresConnectionHandle> GetConnectionAsync(CancellationToken cancellationToken);
}

internal sealed class PostgresConnectionProvider(PostgresTransactionManager transactionManager) : IPostgresConnectionProvider
{
    public ValueTask<PostgresConnectionHandle> GetConnectionAsync(CancellationToken cancellationToken) =>
        transactionManager.GetConnectionAsync(cancellationToken);
}
