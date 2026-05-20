using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Reflection;
using DbUp;
using DbUp.Engine.Output;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;

namespace Ashlar.Postgres.Schema;

internal class SchemaManager(NpgsqlDataSource dataSource, ILogger<SchemaManager>? logger = null)
{
    private static readonly Action<ILogger, Exception?> SchemaInitializationStarted =
        LoggerMessage.Define(
            LogLevel.Information,
            new EventId(1000, nameof(SchemaInitializationStarted)),
            "Initializing Ashlar PostgreSQL schema.");

    private static readonly Action<ILogger, Exception?> SchemaInitializationCompleted =
        LoggerMessage.Define(
            LogLevel.Information,
            new EventId(1001, nameof(SchemaInitializationCompleted)),
            "Ashlar PostgreSQL schema initialization completed.");

    private static readonly Action<ILogger, Exception?> SchemaInitializationFailed =
        LoggerMessage.Define(
            LogLevel.Error,
            new EventId(1002, nameof(SchemaInitializationFailed)),
            "Ashlar PostgreSQL schema initialization failed.");

    private static readonly Action<ILogger, string?, Exception?> ServerVersionUndetermined =
        LoggerMessage.Define<string?>(
            LogLevel.Error,
            new EventId(1003, nameof(ServerVersionUndetermined)),
            "Could not determine PostgreSQL server version. ServerVersionNum={ServerVersionNum}");

    private static readonly Action<ILogger, int, int, Exception?> ServerVersionUnsupported =
        LoggerMessage.Define<int, int>(
            LogLevel.Error,
            new EventId(1004, nameof(ServerVersionUnsupported)),
            "PostgreSQL server version is unsupported. RequiredVersion={RequiredVersion} CurrentVersion={CurrentVersion}");

    private readonly NpgsqlDataSource _dataSource = dataSource ?? throw new ArgumentNullException(nameof(dataSource));
    private readonly ILogger<SchemaManager> _logger = logger ?? NullLogger<SchemaManager>.Instance;

    /// <summary>
    /// Performs the initialize <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await EnsureMinimumVersionAsync(cancellationToken);
        SchemaInitializationStarted(_logger, null);

        var connectionManager = new DbUp.Postgresql.PostgresqlConnectionManager(_dataSource);

        var upgradeEngine = DeployChanges.To
            .PostgresqlDatabase(connectionManager)
            .WithScriptsEmbeddedInAssembly(Assembly.GetExecutingAssembly())
            .JournalToPostgresqlTable(string.Empty, "ashlar_schema_versions")
            .WithTransaction()
            .LogTo(new DbUpUpgradeLogger(_logger))
            .Build();

        var result = await Task.Run(upgradeEngine.PerformUpgrade, cancellationToken);

        if (!result.Successful)
        {
            SchemaInitializationFailed(_logger, result.Error);
            throw new InvalidOperationException("Failed to initialize Ashlar PostgreSQL schema.", result.Error);
        }

        SchemaInitializationCompleted(_logger, null);
    }

    private async Task EnsureMinimumVersionAsync(CancellationToken cancellationToken)
    {
        const int minVersion = 150000; // PostgreSQL 15.0

        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        var versionNum = await GetServerVersionAsync(connection, cancellationToken);

        if (versionNum == null || !int.TryParse(versionNum, out var version))
        {
            ServerVersionUndetermined(_logger, versionNum, null);
            throw new InvalidOperationException("Could not determine PostgreSQL server version.");
        }

        if (version < minVersion)
        {
            ServerVersionUnsupported(_logger, minVersion, version, null);
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

    internal sealed class DbUpUpgradeLogger(ILogger logger) : IUpgradeLog
    {
        private readonly ILogger _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        public void LogTrace(string format, params object[] args)
        {
            Log(LogLevel.Trace, null, format, args);
        }

        public void LogDebug(string format, params object[] args)
        {
            Log(LogLevel.Debug, null, format, args);
        }

        public void LogInformation(string format, params object[] args)
        {
            Log(LogLevel.Information, null, format, args);
        }

        public void LogWarning(string format, params object[] args)
        {
            Log(LogLevel.Warning, null, format, args);
        }

        public void LogError(string format, params object[] args)
        {
            Log(LogLevel.Error, null, format, args);
        }

        public void LogError(Exception ex, string format, params object[] args)
        {
            Log(LogLevel.Error, ex, format, args);
        }

        private void Log(LogLevel logLevel, Exception? exception, string format, object[] args)
        {
            if (!_logger.IsEnabled(logLevel))
            {
                return;
            }

            _logger.Log(
                logLevel,
                new EventId(0, "DbUp"),
                new DbUpLogState(format, args),
                exception,
                static (state, _) => state.ToString());
        }

        private sealed class DbUpLogState(string format, object[] args) : IReadOnlyList<KeyValuePair<string, object?>>
        {
            public int Count => args.Length + 1;

            public KeyValuePair<string, object?> this[int index]
            {
                get
                {
                    if (index < args.Length)
                    {
                        return new KeyValuePair<string, object?>($"Arg{index}", args[index]);
                    }

                    if (index == args.Length)
                    {
                        return new KeyValuePair<string, object?>("{OriginalFormat}", format);
                    }

                    throw new ArgumentOutOfRangeException(nameof(index));
                }
            }

            public IEnumerator<KeyValuePair<string, object?>> GetEnumerator()
            {
                for (var i = 0; i < Count; i++)
                {
                    yield return this[i];
                }
            }

            System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
            {
                return GetEnumerator();
            }

            public override string ToString()
            {
                if (args.Length == 0)
                {
                    return format;
                }

                try
                {
                    return string.Format(CultureInfo.InvariantCulture, format, args);
                }
                catch (FormatException)
                {
                    return format;
                }
            }
        }
    }
}


