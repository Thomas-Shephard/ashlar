using System.Reflection;
using System.Data;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Ashlar.Sqlite.Schema;

internal sealed class SqliteSchemaManager(SqliteConnectionFactory connectionFactory, ILogger<SqliteSchemaManager>? logger = null)
{
    private static readonly Action<ILogger, Exception?> SchemaInitializationStarted =
        LoggerMessage.Define(
            LogLevel.Information,
            new EventId(1000, nameof(SchemaInitializationStarted)),
            "Initializing Ashlar SQLite schema.");

    private static readonly Action<ILogger, Exception?> SchemaInitializationCompleted =
        LoggerMessage.Define(
            LogLevel.Information,
            new EventId(1001, nameof(SchemaInitializationCompleted)),
            "Ashlar SQLite schema initialization completed.");

    private static readonly Action<ILogger, Exception?> SchemaInitializationFailed =
        LoggerMessage.Define(
            LogLevel.Error,
            new EventId(1002, nameof(SchemaInitializationFailed)),
            "Ashlar SQLite schema initialization failed.");

    private readonly SqliteConnectionFactory _connectionFactory = connectionFactory ?? throw new ArgumentNullException(nameof(connectionFactory));
    private readonly ILogger<SqliteSchemaManager> _logger = logger ?? NullLogger<SqliteSchemaManager>.Instance;

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        SchemaInitializationStarted(_logger, null);

        try
        {
            await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken);
            await EnsureJournalAsync(connection, cancellationToken);
            foreach (var script in GetSchemaScripts())
            {
                if (await IsScriptAppliedAsync(connection, script.Name, cancellationToken))
                {
                    continue;
                }

                await ApplyScriptAsync(connection, script, cancellationToken);
            }

            SchemaInitializationCompleted(_logger, null);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            SchemaInitializationFailed(_logger, ex);
            throw new InvalidOperationException("Failed to initialize Ashlar SQLite schema.", ex);
        }
    }

    private static async Task EnsureJournalAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS ashlar_schema_versions (
                script_name TEXT PRIMARY KEY,
                applied_at TEXT NOT NULL
            );
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<bool> IsScriptAppliedAsync(SqliteConnection connection, string scriptName, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT 1 FROM ashlar_schema_versions WHERE script_name = $script_name LIMIT 1;";
        command.Parameters.AddWithValue("$script_name", scriptName);
        var result = await command.ExecuteScalarAsync(cancellationToken);
        return result != null;
    }

    private static async Task ApplyScriptAsync(SqliteConnection connection, SchemaScript script, CancellationToken cancellationToken)
    {
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = script.Sql;
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "INSERT INTO ashlar_schema_versions (script_name, applied_at) VALUES ($script_name, $applied_at);";
            command.Parameters.AddWithValue("$script_name", script.Name);
            command.Parameters.AddWithValue("$applied_at", DateTimeOffset.UtcNow.ToString("O"));
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
    }

    private static SchemaScript[] GetSchemaScripts()
    {
        var assembly = Assembly.GetExecutingAssembly();
        return assembly.GetManifestResourceNames()
            .Where(name => name.Contains(".Schema.Scripts.", StringComparison.Ordinal) && name.EndsWith(".sql", StringComparison.Ordinal))
            .Order(StringComparer.Ordinal)
            .Select(name => new SchemaScript(name, ReadResource(assembly, name)))
            .ToArray();
    }

    [ExcludeFromCodeCoverage]
    private static string ReadResource(Assembly assembly, string resourceName)
    {
        using var stream = assembly.GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException($"Embedded schema script was not found: {resourceName}");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private sealed record SchemaScript(string Name, string Sql);
}
