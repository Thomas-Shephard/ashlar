using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Ashlar.Sqlite.Auditing;

/// <summary>
/// A SQLite-backed security event sink that persists audit events to the ashlar_security_events table.
/// </summary>
internal sealed class SqliteSecurityEventSink : PersistentSecurityEventSink, IUserSecurityEventSummaryRepository
{
    private const string IdParameter = "$id";
    private const string EventTypeParameter = "$eventType";
    private const string OccurredAtParameter = "$occurredAt";
    private const string UserIdParameter = "$userId";
    private const string TenantIdParameter = "$tenantId";
    private const string ActorUserIdParameter = "$actorUserId";
    private const string SessionIdParameter = "$sessionId";
    private const string ProviderTypeParameter = "$providerType";
    private const string ProviderNameParameter = "$providerName";
    private const string IpAddressParameter = "$ipAddress";
    private const string UserAgentParameter = "$userAgent";
    private const string CorrelationIdParameter = "$correlationId";
    private const string OutcomeParameter = "$outcome";
    private const string FailureReasonParameter = "$failureReason";
    private const string PropertiesParameter = "$properties";
    private const string SinceParameter = "$since";

    private readonly ISqliteConnectionProvider _connectionProvider;

    public SqliteSecurityEventSink(ISqliteConnectionProvider connectionProvider, ILogger<SqliteSecurityEventSink>? logger = null)
        : base(logger ?? NullLogger<SqliteSecurityEventSink>.Instance)
    {
        _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));
    }

    public async Task<int> CountSecurityEventsForUserAsync(Guid userId, DateTimeOffset since, CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT COUNT(*)
            FROM ashlar_security_events
            WHERE user_id = $userId AND occurred_at >= $since;
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddGuidParameter(UserIdParameter, userId);
        command.AddDateTimeOffsetParameter(SinceParameter, since);

        var result = await command.ExecuteScalarAsync(cancellationToken);
        return Convert.ToInt32(result, System.Globalization.CultureInfo.InvariantCulture);
    }

    protected override async Task PersistAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT INTO ashlar_security_events (
                id, event_type, occurred_at, user_id, tenant_id, actor_user_id, session_id,
                provider_type, provider_name, ip_address, user_agent,
                correlation_id, outcome, failure_reason, properties
            ) VALUES (
                $id, $eventType, $occurredAt, $userId, $tenantId, $actorUserId, $sessionId,
                $providerType, $providerName, $ipAddress, $userAgent,
                $correlationId, $outcome, $failureReason, $properties
            );
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        var record = SecurityEventStorageRecord.From(securityEvent);
        command.CommandText = sql;
        command.AddGuidParameter(IdParameter, record.Id);
        command.AddParameter(EventTypeParameter, record.EventType);
        command.AddDateTimeOffsetParameter(OccurredAtParameter, record.OccurredAt);
        command.AddNullableGuidParameter(UserIdParameter, record.UserId);
        command.AddNullableGuidParameter(TenantIdParameter, record.TenantId);
        command.AddNullableGuidParameter(ActorUserIdParameter, record.ActorUserId);
        command.AddNullableGuidParameter(SessionIdParameter, record.SessionId);
        command.AddParameter(ProviderTypeParameter, record.ProviderType);
        command.AddParameter(ProviderNameParameter, record.ProviderName);
        command.AddParameter(IpAddressParameter, record.IpAddress);
        command.AddParameter(UserAgentParameter, record.UserAgent);
        command.AddParameter(CorrelationIdParameter, record.CorrelationId);
        command.AddParameter(OutcomeParameter, record.Outcome);
        command.AddParameter(FailureReasonParameter, record.FailureReason);
        command.AddParameter(PropertiesParameter, record.PropertiesJson);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
