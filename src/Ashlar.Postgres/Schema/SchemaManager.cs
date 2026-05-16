using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using DbUp;
using Npgsql;

namespace Ashlar.Postgres.Schema;

internal class SchemaManager(NpgsqlDataSource dataSource)
{
    private readonly NpgsqlDataSource _dataSource = dataSource ?? throw new ArgumentNullException(nameof(dataSource));

    /// <summary>
    /// Performs the initialize <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await EnsureMinimumVersionAsync(cancellationToken);

        var connectionManager = new DbUp.Postgresql.PostgresqlConnectionManager(_dataSource);

        var upgradeEngine = DeployChanges.To
            .PostgresqlDatabase(connectionManager)
            .WithScriptsEmbeddedInAssembly(Assembly.GetExecutingAssembly())
            .JournalToPostgresqlTable(string.Empty, "ashlar_schema_versions")
            .WithTransaction()
            // TODO: Integrate with Ashlar's logging abstraction once available.
            .LogToNowhere()
            .Build();

        var result = await Task.Run(upgradeEngine.PerformUpgrade, cancellationToken);

        if (!result.Successful)
        {
            throw new InvalidOperationException("Failed to initialize Ashlar PostgreSQL schema.", result.Error);
        }
    }

    private async Task EnsureMinimumVersionAsync(CancellationToken cancellationToken)
    {
        const int minVersion = 150000; // PostgreSQL 15.0

        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        var versionNum = await GetServerVersionAsync(connection, cancellationToken);

        if (versionNum == null || !int.TryParse(versionNum, out var version))
        {
            throw new InvalidOperationException("Could not determine PostgreSQL server version.");
        }

        if (version < minVersion)
        {
            throw new NotSupportedException($"Ashlar PostgreSQL persistence requires PostgreSQL 15 or higher. Current server version number: {version}");
        }
    }

    /// <summary>
    /// Performs the get server version <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="connection">The connection value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    [ExcludeFromCodeCoverage]
    protected virtual async Task<string?> GetServerVersionAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("SHOW server_version_num;", connection);
        var result = await command.ExecuteScalarAsync(cancellationToken);
        return result?.ToString();
    }
}
