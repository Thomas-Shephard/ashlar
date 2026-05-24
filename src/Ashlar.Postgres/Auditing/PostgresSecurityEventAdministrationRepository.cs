using Dapper;

namespace Ashlar.Postgres.Auditing;

/// <summary>
/// Provides PostgreSQL-backed administrator security event reads.
/// </summary>
/// <param name="connectionProvider">The connection provider value.</param>
public sealed class PostgresSecurityEventAdministrationRepository(IPostgresConnectionProvider connectionProvider) : ISecurityEventAdministrationRepository
{
    private readonly IPostgresConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));

    /// <summary>
    /// Searches recorded security events using safe administrator-display fields.
    /// </summary>
    /// <param name="request">The search request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The matching security events.</returns>
    public async Task<IReadOnlyList<SecurityEventSummary>> SearchSecurityEventsAsync(SearchSecurityEventsRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var sql = SelectSql + " WHERE 1 = 1";
        var parameters = new DynamicParameters();

        AddFilters(request, ref sql, parameters);

        sql += " ORDER BY occurred_at DESC, id DESC LIMIT @Limit OFFSET @Offset";
        parameters.Add("Limit", request.Limit);
        parameters.Add("Offset", request.Offset);

        var rows = await PostgresAdminQuery.QueryAsync<SecurityEventRow>(_connectionProvider, sql, parameters, cancellationToken);
        return rows.Select(static row => row.ToStorageRecord().ToSummary()).ToList().AsReadOnly();
    }

    /// <summary>
    /// Gets a recorded security event by id.
    /// </summary>
    /// <param name="eventId">The event id value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The security event, or <see langword="null" /> when it does not exist.</returns>
    public async Task<SecurityEventSummary?> GetSecurityEventAsync(Guid eventId, CancellationToken cancellationToken = default)
    {
        var sql = SelectSql + " WHERE id = @EventId";
        var row = await PostgresAdminQuery.QuerySingleAsync<SecurityEventRow>(_connectionProvider, sql, new { EventId = eventId }, cancellationToken);
        return row?.ToStorageRecord().ToSummary();
    }

    private const string SelectSql = """
        SELECT id AS EventId, event_type AS EventType, occurred_at AS OccurredAt,
               user_id AS UserId, tenant_id AS TenantId, actor_user_id AS ActorUserId,
               session_id AS SessionId, provider_type AS ProviderType, provider_name AS ProviderName,
               ip_address AS IpAddress, user_agent AS UserAgent, correlation_id AS CorrelationId,
               outcome AS Outcome, failure_reason AS FailureReason, properties::text AS PropertiesJson
        FROM ashlar_security_events
        """;

    private static void AddFilters(SearchSecurityEventsRequest request, ref string sql, DynamicParameters parameters)
    {
        PostgresAdminQuery.AddTenantFilter(request.Tenant, "tenant_id", "TenantId", ref sql, parameters);

        if (request.UserId.HasValue)
        {
            sql += " AND user_id = @UserId";
            parameters.Add("UserId", request.UserId.Value);
        }

        if (request.ActorUserId.HasValue)
        {
            sql += " AND actor_user_id = @ActorUserId";
            parameters.Add("ActorUserId", request.ActorUserId.Value);
        }

        if (request.SessionId.HasValue)
        {
            sql += " AND session_id = @SessionId";
            parameters.Add("SessionId", request.SessionId.Value);
        }

        var eventTypes = request.EventTypes?.Where(eventType => !string.IsNullOrWhiteSpace(eventType)).ToArray();
        if (eventTypes?.Length > 0)
        {
            sql += " AND event_type = ANY(@EventTypes)";
            parameters.Add("EventTypes", eventTypes);
        }

        if (!string.IsNullOrWhiteSpace(request.Outcome))
        {
            sql += " AND outcome = @Outcome";
            parameters.Add("Outcome", request.Outcome);
        }

        if (!string.IsNullOrWhiteSpace(request.FailureReason))
        {
            sql += " AND failure_reason = @FailureReason";
            parameters.Add("FailureReason", request.FailureReason);
        }

        PostgresAdminQuery.AddProviderFilter(request.Provider, "provider_type", "provider_name", "ProviderType", "ProviderName", ref sql, parameters);

        PostgresAdminQuery.AddDateRange(request.OccurredFrom, request.OccurredTo, "occurred_at", "OccurredFrom", "OccurredTo", ref sql, parameters);
    }

    private sealed record SecurityEventRow(
        Guid EventId,
        string EventType,
        DateTime OccurredAt,
        Guid? UserId,
        Guid? TenantId,
        Guid? ActorUserId,
        Guid? SessionId,
        string? ProviderType,
        string? ProviderName,
        string? IpAddress,
        string? UserAgent,
        string? CorrelationId,
        string? Outcome,
        string? FailureReason,
        string? PropertiesJson)
    {
        public SecurityEventStorageRecord ToStorageRecord()
        {
            return new SecurityEventStorageRecord(
                EventId,
                EventType,
                PostgresAdminQuery.ToDateTimeOffset(OccurredAt),
                UserId,
                TenantId,
                ActorUserId,
                SessionId,
                ProviderType,
                ProviderName,
                IpAddress,
                UserAgent,
                CorrelationId,
                Outcome,
                FailureReason,
                PropertiesJson);
        }

    }
}
