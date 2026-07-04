using Microsoft.Data.Sqlite;

namespace Ashlar.Sqlite.Auditing;

internal sealed class SqliteSecurityEventAdministrationRepository(ISqliteConnectionProvider connectionProvider) : ISecurityEventAdministrationRepository
{
    private readonly ISqliteConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));

    public async Task<IReadOnlyList<SecurityEventSummary>> SearchSecurityEventsAsync(SearchSecurityEventsRequest request, CancellationToken cancellationToken = default)
    {
        SearchSecurityEventsRequest.ThrowIfInvalid(request);

        return await SqliteQuery.QueryAsync(_connectionProvider, command =>
        {
            var sql = SelectSql + " WHERE 1 = 1";
            AddFilters(request, ref sql, command);
            sql += " ORDER BY occurred_at DESC, id DESC LIMIT $limit OFFSET $offset;";
            command.AddParameter("$limit", request.Limit);
            command.AddParameter("$offset", request.Offset);

            return sql;
        }, static reader => ReadStorageRecord(reader).ToSummary(), cancellationToken);
    }

    public async Task<SecurityEventSummary?> GetSecurityEventAsync(SecurityEventAdministrationDetailRequest request, CancellationToken cancellationToken = default)
    {
        SecurityEventAdministrationDetailRequest.ThrowIfInvalid(request);

        return await SqliteQuery.QuerySingleAsync(_connectionProvider, command =>
        {
            command.AddGuidParameter("$eventId", request.EventId);
            var sql = SelectSql + " WHERE id = $eventId";
            command.AddTenantFilter(request.Tenant, "tenant_id", "$tenantId", ref sql);
            return sql + ";";
        }, static reader => ReadStorageRecord(reader).ToSummary(), cancellationToken);
    }

    private const string SelectSql = """
        SELECT id, event_type, occurred_at, user_id, tenant_id, actor_user_id, session_id,
               provider_type, provider_name, ip_address, user_agent, correlation_id,
               outcome, failure_reason, properties
        FROM ashlar_security_events
        """;

    private static void AddFilters(SearchSecurityEventsRequest request, ref string sql, SqliteCommand command)
    {
        command.AddTenantFilter(request.Tenant, "tenant_id", "$tenantId", ref sql);

        if (request.UserId.HasValue)
        {
            sql += " AND user_id = $userId";
            command.AddGuidParameter("$userId", request.UserId.Value);
        }

        if (request.ActorUserId.HasValue)
        {
            sql += " AND actor_user_id = $actorUserId";
            command.AddGuidParameter("$actorUserId", request.ActorUserId.Value);
        }

        if (request.SessionId.HasValue)
        {
            sql += " AND session_id = $sessionId";
            command.AddGuidParameter("$sessionId", request.SessionId.Value);
        }

        var eventTypes = request.EventTypes?.Where(eventType => !string.IsNullOrWhiteSpace(eventType)).ToArray();
        if (eventTypes?.Length > 0)
        {
            var parameterNames = new List<string>();
            for (var i = 0; i < eventTypes.Length; i++)
            {
                var parameterName = "$eventType" + i.ToString(System.Globalization.CultureInfo.InvariantCulture);
                parameterNames.Add(parameterName);
                command.AddParameter(parameterName, eventTypes[i]);
            }

            sql += " AND event_type IN (" + string.Join(", ", parameterNames) + ")";
        }

        if (!string.IsNullOrWhiteSpace(request.Outcome))
        {
            sql += " AND outcome = $outcome";
            command.AddParameter("$outcome", request.Outcome);
        }

        if (!string.IsNullOrWhiteSpace(request.FailureReason))
        {
            sql += " AND failure_reason = $failureReason";
            command.AddParameter("$failureReason", request.FailureReason);
        }

        command.AddProviderFilter(request.Provider, "provider_type", "provider_name", "$providerType", "$providerName", ref sql);

        command.AddDateRange(request.OccurredFrom, request.OccurredTo, "occurred_at", "$occurredFrom", "$occurredTo", ref sql);
    }

    private static SecurityEventStorageRecord ReadStorageRecord(SqliteDataReader reader)
    {
        return new SecurityEventStorageRecord(
            reader.GetGuidFromText("id"),
            reader.GetString(reader.GetOrdinal("event_type")),
            reader.GetDateTimeOffsetFromText("occurred_at"),
            reader.GetNullableGuidFromText("user_id"),
            reader.GetNullableGuidFromText("tenant_id"),
            reader.GetNullableGuidFromText("actor_user_id"),
            reader.GetNullableGuidFromText("session_id"),
            reader.GetNullableString("provider_type"),
            reader.GetNullableString("provider_name"),
            reader.GetNullableString("ip_address"),
            reader.GetNullableString("user_agent"),
            reader.GetNullableString("correlation_id"),
            reader.GetNullableString("outcome"),
            reader.GetNullableString("failure_reason"),
            reader.GetNullableString("properties"));
    }
}
