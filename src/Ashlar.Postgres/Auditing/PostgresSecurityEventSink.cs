using Ashlar.Auditing;
using Dapper;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;

namespace Ashlar.Postgres.Auditing;

/// <summary>
/// A PostgreSQL-backed security event sink that persists audit events to the ashlar_security_events table.
/// </summary>
public sealed class PostgresSecurityEventSink : PersistentSecurityEventSink, IUserSecurityEventSummaryRepository
{
    private readonly NpgsqlDataSource _dataSource;

    /// <summary>
    /// Initializes a new instance of the postgres security event sink class.
    /// </summary>
    /// <param name="dataSource">The data source value.</param>
    /// <param name="logger">The logger value.</param>
    public PostgresSecurityEventSink(NpgsqlDataSource dataSource, ILogger<PostgresSecurityEventSink>? logger = null)
        : base(logger ?? NullLogger<PostgresSecurityEventSink>.Instance)
    {
        _dataSource = dataSource ?? throw new ArgumentNullException(nameof(dataSource));
    }

    /// <summary>
    /// Counts recent security events for a user.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="since">The since value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<int> CountSecurityEventsForUserAsync(Guid userId, DateTimeOffset since, CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT COUNT(*)::int
            FROM ashlar_security_events
            WHERE user_id = @UserId AND occurred_at >= @Since
            """;

        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        var command = new CommandDefinition(sql, new { UserId = userId, Since = since }, cancellationToken: cancellationToken);
        return await connection.ExecuteScalarAsync<int>(command);
    }

    protected override async Task PersistAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT INTO ashlar_security_events (
                id, event_type, occurred_at, user_id, tenant_id, actor_user_id, session_id,
                provider_type, provider_name, ip_address, user_agent,
                correlation_id, outcome, failure_reason, properties
            ) VALUES (
                @Id, @EventType, @OccurredAt, @UserId, @TenantId, @ActorUserId, @SessionId,
                @ProviderType, @ProviderName, @IpAddress, @UserAgent,
                @CorrelationId, @Outcome, @FailureReason, @Properties::jsonb
            )
            """;

        var record = SecurityEventStorageRecord.From(securityEvent);
        var parameters = new
        {
            record.Id,
            record.EventType,
            record.OccurredAt,
            record.UserId,
            record.TenantId,
            record.ActorUserId,
            record.SessionId,
            record.ProviderType,
            record.ProviderName,
            record.IpAddress,
            record.UserAgent,
            record.CorrelationId,
            record.Outcome,
            record.FailureReason,
            Properties = record.PropertiesJson
        };

        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        var command = new CommandDefinition(sql, parameters, cancellationToken: cancellationToken);
        await connection.ExecuteAsync(command);
    }
}
