using System.Globalization;
using Ashlar.Operational.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;

namespace Ashlar.Postgres.Schema;

internal sealed class PostgresSchemaDiagnostics(
    NpgsqlDataSource dataSource,
    TimeProvider timeProvider,
    ILogger<PostgresSchemaDiagnostics>? logger = null) : IAshlarSchemaDiagnostics
{
    private const string ProviderName = "PostgreSQL";
    private const string MinimumProviderVersion = "150000";
    private static readonly AshlarSchemaDiagnosticsRunner DiagnosticsRunner = new(
        ProviderName,
        AshlarSchemaDiagnosticsRunner.GetExpectedMigrationNames(typeof(PostgresSchemaDiagnostics).Assembly),
        MinimumProviderVersion);

    private static readonly Action<ILogger, Exception?> SchemaDiagnosticsFailed =
        LoggerMessage.Define(
            LogLevel.Error,
            new EventId(1005, nameof(SchemaDiagnosticsFailed)),
            "PostgreSQL schema diagnostics failed.");

    private readonly NpgsqlDataSource _dataSource = dataSource ?? throw new ArgumentNullException(nameof(dataSource));
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    private readonly ILogger<PostgresSchemaDiagnostics> _logger = logger ?? NullLogger<PostgresSchemaDiagnostics>.Instance;

    public async Task<AshlarSchemaDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
    {
        return await DiagnosticsRunner.CheckAsync(
            _timeProvider,
            _dataSource.OpenConnectionAsync,
            GetProviderVersionAsync,
            GetSchemaJournalCountAsync,
            GetAppliedMigrationNamesAsync,
            LogSchemaDiagnosticsFailed,
            cancellationToken);
    }

    private static async Task<string?> GetProviderVersionAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("SHOW server_version_num;", connection);
        var result = await command.ExecuteScalarAsync(cancellationToken);
        return Convert.ToString(result, CultureInfo.InvariantCulture);
    }

    private static async Task<int> GetSchemaJournalCountAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            """
            SELECT COUNT(*)
            FROM information_schema.tables
            WHERE table_schema = current_schema()
              AND table_name = 'ashlar_schema_versions';
            """,
            connection);
        var result = await command.ExecuteScalarAsync(cancellationToken);
        return Convert.ToInt32(result, CultureInfo.InvariantCulture);
    }

    private static async Task<IReadOnlyCollection<string>> GetAppliedMigrationNamesAsync(
        NpgsqlConnection connection,
        CancellationToken cancellationToken)
    {
        var migrationNames = new List<string>();
        await using var command = new NpgsqlCommand(
            """
            SELECT scriptname
            FROM ashlar_schema_versions
            ORDER BY applied, schemaversionsid;
            """,
            connection);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            migrationNames.Add(reader.GetString(0));
        }

        return migrationNames;
    }

    private void LogSchemaDiagnosticsFailed(Exception exception)
    {
        SchemaDiagnosticsFailed(_logger, exception);
    }
}
