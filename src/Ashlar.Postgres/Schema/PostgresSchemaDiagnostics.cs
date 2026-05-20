using System.Globalization;
using System.Reflection;
using Ashlar.Operational.Diagnostics;
using Npgsql;

namespace Ashlar.Postgres.Schema;

internal sealed class PostgresSchemaDiagnostics(NpgsqlDataSource dataSource, TimeProvider timeProvider) : IAshlarSchemaDiagnostics
{
    private const string ProviderName = "Postgres";
    private const string MinimumProviderVersion = "150000";
    private static readonly string[] ExpectedMigrationNames = GetExpectedMigrationNames();

    private readonly NpgsqlDataSource _dataSource = dataSource ?? throw new ArgumentNullException(nameof(dataSource));
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

    public async Task<AshlarSchemaDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
    {
        var checkedAt = _timeProvider.GetUtcNow();
        AshlarSchemaDiagnosticResult result;

        try
        {
            await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
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
        catch
        {
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
            MinimumProviderVersion,
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
            MinimumProviderVersion,
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
            MinimumProviderVersion,
            null);
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
