using Dapper;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Ashlar.Postgres.Auditing;

internal sealed class PostgresSecurityEventSink(IPostgresConnectionProvider connectionProvider, ILogger<PostgresSecurityEventSink>? logger = null) : PersistentSecurityEventSink(logger ?? NullLogger<PostgresSecurityEventSink>.Instance)
{
    private readonly IPostgresConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));

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

        await using var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        var command = new CommandDefinition(sql, parameters, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
        await connectionHandle.Connection.ExecuteAsync(command);
    }
}

internal sealed class PostgresUserSecurityEventSummaryRepository(IPostgresConnectionProvider connectionProvider) : IUserSecurityEventSummaryRepository
{
    public async Task<int> CountSecurityEventsForUserAsync(Guid userId, DateTimeOffset since, CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT COUNT(*)::int
            FROM ashlar_security_events
            WHERE user_id = @UserId AND occurred_at >= @Since
            """;

        await using var connectionHandle = await connectionProvider.GetConnectionAsync(cancellationToken);
        var command = new CommandDefinition(sql, new { UserId = userId, Since = since }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
        return await connectionHandle.Connection.ExecuteScalarAsync<int>(command);
    }
}
