using Ashlar.Operational;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Ashlar.Sqlite.Operational;

/// <summary>
/// Provides SQLite cleanup for Ashlar operational tables.
/// </summary>
public sealed partial class SqliteAshlarCleanupService : IAshlarCleanupService
{
    private const string CutoffParameter = "$cutoff";
    private const string LimitParameter = "$limit";

    private readonly ISqliteConnectionProvider _connectionProvider;
    private readonly TimeProvider _timeProvider;
    private readonly AshlarCleanupOptions _options;
    private readonly ILogger<SqliteAshlarCleanupService> _logger;

    /// <summary>
    /// Initializes a configured SQLite cleanup service.
    /// </summary>
    /// <param name="connectionProvider">The SQLite connection provider.</param>
    /// <param name="timeProvider">The time provider.</param>
    /// <param name="options">The cleanup options.</param>
    /// <param name="logger">The logger value.</param>
    public SqliteAshlarCleanupService(
        ISqliteConnectionProvider connectionProvider,
        TimeProvider timeProvider,
        IOptions<AshlarCleanupOptions> options,
        ILogger<SqliteAshlarCleanupService>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(connectionProvider);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(options);

        _connectionProvider = connectionProvider;
        _timeProvider = timeProvider;
        _options = options.Value;
        _logger = logger ?? NullLogger<SqliteAshlarCleanupService>.Instance;
        if (!AshlarCleanupOptions.Validate(_options))
        {
            throw new ArgumentException("Cleanup options are invalid.", nameof(options));
        }
    }

    public async Task<AshlarCleanupResult> CleanupAsync(CancellationToken cancellationToken = default)
    {
        var now = _timeProvider.GetUtcNow();
        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        return await AshlarCleanupPlan.RunAsync(
            _options,
            now,
            handle,
            DeleteWithLoggingAsync,
            CreateDefinition,
            cancellationToken);
    }

    private async Task<int> DeleteWithLoggingAsync(
        SqliteConnectionHandle handle,
        AshlarCleanupDeleteDefinition definition,
        DateTimeOffset cutoff,
        CancellationToken cancellationToken)
    {
        try
        {
            return await DeleteAsync(handle, definition, cutoff, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogCleanupCategoryFailed(_logger, definition.Category, definition.TableName, ex);
            throw;
        }
    }

    private async Task<int> DeleteAsync(
        SqliteConnectionHandle handle,
        AshlarCleanupDeleteDefinition definition,
        DateTimeOffset cutoff,
        CancellationToken cancellationToken)
    {
        var sql = $"""
            DELETE FROM {definition.TableName}
            WHERE rowid IN (
                SELECT rowid
                FROM {definition.TableName}
                WHERE {definition.Predicate}
                ORDER BY {definition.OrderColumn}, rowid
                LIMIT $limit
            );
            """;

        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddDateTimeOffsetParameter(CutoffParameter, cutoff);
        command.AddParameter(LimitParameter, _options.BatchSize);
        return await command.ExecuteNonQueryAsync(cancellationToken);
    }

    [LoggerMessage(EventId = 1000, Level = LogLevel.Error, Message = "SQLite cleanup category failed. Category={Category} TableName={TableName}")]
    private static partial void LogCleanupCategoryFailed(ILogger logger, string category, string tableName, Exception exception);

    private static AshlarCleanupDeleteDefinition CreateDefinition(AshlarCleanupCategoryDefinition category)
    {
        return new AshlarCleanupDeleteDefinition(
            category.Category,
            category.TableName,
            AshlarCleanupPlan.RenderPredicate(category.PredicateTemplate, CutoffParameter, "1", "0"),
            category.OrderColumn);
    }
}






