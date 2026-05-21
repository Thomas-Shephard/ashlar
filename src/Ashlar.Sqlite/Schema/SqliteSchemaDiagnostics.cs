using System.Globalization;
using System.Reflection;
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
    private static readonly string[] ExpectedMigrationNames = GetExpectedMigrationNames();
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
        var checkedAt = _timeProvider.GetUtcNow();
        AshlarSchemaDiagnosticResult result;

        try
        {
            await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken);
            var providerVersion = await GetProviderVersionAsync(connection, cancellationToken);

            if (await GetSchemaJournalCountAsync(connection, cancellationToken) == 0)
            {
                result = CreateNotInitializedResult(checkedAt, providerVersion);
            }
            else
            {
                var appliedMigrationNames = await GetAppliedMigrationNamesAsync(connection, cancellationToken);
                result = CreateAppliedResult(checkedAt, providerVersion, appliedMigrationNames);
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            SchemaDiagnosticsFailed(_logger, ex);
            return CreateUnknownResult(checkedAt);
        }

        return result;
    }

    private static AshlarSchemaDiagnosticResult CreateNotInitializedResult(DateTimeOffset checkedAt, string? providerVersion)
    {
        return new AshlarSchemaDiagnosticResult(
            AshlarDiagnosticStatus.Unhealthy,
            ProviderName,
            "Schema has not been initialized.",
            checkedAt,
            AshlarSchemaStatus.NotInitialized,
            0,
            ExpectedMigrationNames.Length,
            ExpectedMigrationNames.Length,
            null,
            LatestExpectedMigrationName,
            null,
            providerVersion);
    }

    private static AshlarSchemaDiagnosticResult CreateAppliedResult(
        DateTimeOffset checkedAt,
        string? providerVersion,
        IReadOnlyCollection<string> appliedMigrationNames)
    {
        var appliedMigrationNameSet = appliedMigrationNames.ToHashSet(StringComparer.Ordinal);
        var missingMigrationCount = ExpectedMigrationNames.Count(name => !appliedMigrationNameSet.Contains(name));
        var schemaStatus = missingMigrationCount == 0 ? AshlarSchemaStatus.Current : AshlarSchemaStatus.PendingMigrations;
        var status = schemaStatus == AshlarSchemaStatus.Current ? AshlarDiagnosticStatus.Healthy : AshlarDiagnosticStatus.Unhealthy;

        return new AshlarSchemaDiagnosticResult(
            status,
            ProviderName,
            schemaStatus == AshlarSchemaStatus.Current ? null : "Schema has pending migrations.",
            checkedAt,
            schemaStatus,
            appliedMigrationNames.Count,
            ExpectedMigrationNames.Length,
            missingMigrationCount,
            appliedMigrationNames.LastOrDefault(),
            LatestExpectedMigrationName,
            null,
            providerVersion);
    }

    private static AshlarSchemaDiagnosticResult CreateUnknownResult(DateTimeOffset checkedAt)
    {
        return new AshlarSchemaDiagnosticResult(
            AshlarDiagnosticStatus.Unknown,
            ProviderName,
            "Schema diagnostics could not query provider state.",
            checkedAt,
            AshlarSchemaStatus.Unknown,
            null,
            ExpectedMigrationNames.Length,
            null,
            null,
            LatestExpectedMigrationName,
            null,
            null);
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

    private static string? LatestExpectedMigrationName => ExpectedMigrationNames.LastOrDefault();

    private static string[] GetExpectedMigrationNames()
    {
        var assembly = Assembly.GetExecutingAssembly();
        return assembly.GetManifestResourceNames()
            .Where(name => name.Contains(".Schema.Scripts.", StringComparison.Ordinal) && name.EndsWith(".sql", StringComparison.Ordinal))
            .Order(StringComparer.Ordinal)
            .ToArray();
    }
}
