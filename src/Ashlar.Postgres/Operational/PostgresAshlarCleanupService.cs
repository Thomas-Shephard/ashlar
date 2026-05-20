using Ashlar.Operational;
using Dapper;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Npgsql;

namespace Ashlar.Postgres.Operational;

/// <summary>
/// Provides postgres ashlar cleanup service behavior.
/// </summary>
public sealed class PostgresAshlarCleanupService : IAshlarCleanupService
{
    private static readonly Action<ILogger, string, string, Exception?> CleanupCategoryFailed =
        LoggerMessage.Define<string, string>(
            LogLevel.Error,
            new EventId(1000, nameof(CleanupCategoryFailed)),
            "PostgreSQL cleanup category failed. Category={Category} TableName={TableName}");

    private readonly NpgsqlDataSource _dataSource;
    private readonly TimeProvider _timeProvider;
    private readonly AshlarCleanupOptions _options;
    private readonly ILogger<PostgresAshlarCleanupService> _logger;

    /// <summary>
    /// Initializes a configured PostgreSQL cleanup service.
    /// </summary>
    /// <param name="dataSource">The PostgreSQL data source.</param>
    /// <param name="timeProvider">The time provider.</param>
    /// <param name="options">The cleanup options.</param>
    /// <param name="logger">The logger value.</param>
    public PostgresAshlarCleanupService(
        NpgsqlDataSource dataSource,
        TimeProvider timeProvider,
        IOptions<AshlarCleanupOptions> options,
        ILogger<PostgresAshlarCleanupService>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(dataSource);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(options);

        _dataSource = dataSource;
        _timeProvider = timeProvider;
        _options = options.Value;
        _logger = logger ?? NullLogger<PostgresAshlarCleanupService>.Instance;
        if (!AshlarCleanupOptions.Validate(_options))
        {
            throw new ArgumentException("Cleanup options are invalid.", nameof(options));
        }
    }

    /// <summary>
    /// Performs the cleanup <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<AshlarCleanupResult> CleanupAsync(CancellationToken cancellationToken = default)
    {
        var now = _timeProvider.GetUtcNow();
        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        return await AshlarCleanupPlan.RunAsync(
            _options,
            now,
            connection,
            DeleteWithLoggingAsync,
            CreateDefinition,
            cancellationToken);
    }

    private async Task<int> DeleteWithLoggingAsync(
        NpgsqlConnection connection,
        AshlarCleanupDeleteDefinition definition,
        DateTimeOffset cutoff,
        CancellationToken cancellationToken)
    {
        try
        {
            return await DeleteAsync(connection, definition, cutoff, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            CleanupCategoryFailed(_logger, definition.Category, definition.TableName, ex);
            throw;
        }
    }

    private async Task<int> DeleteAsync(
        NpgsqlConnection connection,
        AshlarCleanupDeleteDefinition definition,
        DateTimeOffset cutoff,
        CancellationToken cancellationToken)
    {
        var sql = $"""
            DELETE FROM {definition.TableName}
            WHERE ctid IN (
                SELECT ctid
                FROM {definition.TableName}
                WHERE {definition.Predicate}
                ORDER BY {definition.OrderColumn}, ctid
                FOR UPDATE SKIP LOCKED
                LIMIT @limit
            );
            """;

        var command = new CommandDefinition(sql, new { cutoff, limit = _options.BatchSize }, cancellationToken: cancellationToken);
        return await connection.ExecuteAsync(command);
    }

    private static AshlarCleanupDeleteDefinition CreateDefinition(AshlarCleanupCategoryDefinition category)
    {
        return new AshlarCleanupDeleteDefinition(
            category.Category,
            category.TableName,
            AshlarCleanupPlan.RenderPredicate(category.PredicateTemplate, "@cutoff", "TRUE", "FALSE"),
            category.OrderColumn);
    }
}
