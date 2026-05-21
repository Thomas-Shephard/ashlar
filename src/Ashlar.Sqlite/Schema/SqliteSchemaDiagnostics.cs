using System.Globalization;
using Ashlar.Operational.Diagnostics;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Ashlar.Sqlite.Schema;

internal sealed class SqliteSchemaDiagnostics(
    SqliteConnectionFactory connectionFactory,
    TimeProvider timeProvider,
    ILogger<SqliteSchemaDiagnostics>? logger = null) : IAshlarSchemaDiagnostics
{
    private const string ProviderName = "Sqlite";
    private static readonly AshlarSchemaDiagnosticsRunner DiagnosticsRunner = new(
        ProviderName,
        AshlarSchemaDiagnosticsRunner.GetExpectedMigrationNames(typeof(SqliteSchemaDiagnostics).Assembly),
        null);

    private static readonly Action<ILogger, Exception?> SchemaDiagnosticsFailed =
        LoggerMessage.Define(
            LogLevel.Error,
            new EventId(1003, nameof(SchemaDiagnosticsFailed)),
            "SQLite schema diagnostics failed.");

    private readonly SqliteConnectionFactory _connectionFactory = connectionFactory ?? throw new ArgumentNullException(nameof(connectionFactory));
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    private readonly ILogger<SqliteSchemaDiagnostics> _logger = logger ?? NullLogger<SqliteSchemaDiagnostics>.Instance;

    public async Task<AshlarSchemaDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
    {
        return await DiagnosticsRunner.CheckAsync(
            _timeProvider,
            _connectionFactory.OpenConnectionAsync,
            GetProviderVersionAsync,
            GetSchemaJournalCountAsync,
            GetAppliedMigrationNamesAsync,
            LogSchemaDiagnosticsFailed,
            cancellationToken);
    }

    private static async Task<string?> GetProviderVersionAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT sqlite_version();";
        var result = await command.ExecuteScalarAsync(cancellationToken);
        return Convert.ToString(result, CultureInfo.InvariantCulture);
    }

    private static async Task<int> GetSchemaJournalCountAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT COUNT(*)
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'ashlar_schema_versions';
            """;
        var result = await command.ExecuteScalarAsync(cancellationToken);
        return Convert.ToInt32(result, CultureInfo.InvariantCulture);
    }

    private static async Task<IReadOnlyCollection<string>> GetAppliedMigrationNamesAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        var migrationNames = new List<string>();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT script_name
            FROM ashlar_schema_versions
            ORDER BY applied_at, rowid;
            """;
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
