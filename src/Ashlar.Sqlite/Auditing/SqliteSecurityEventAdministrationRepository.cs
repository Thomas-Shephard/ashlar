using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Ashlar.Sqlite.Auditing;

/// <summary>
/// Provides SQLite-backed administrator security event reads.
/// </summary>
/// <param name="connectionProvider">The connection provider value.</param>
public sealed class SqliteSecurityEventAdministrationRepository(ISqliteConnectionProvider connectionProvider) : ISecurityEventAdministrationRepository
{
    private readonly ISqliteConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));

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

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;

        AddFilters(request, ref sql, command);

        sql += " ORDER BY occurred_at DESC, id DESC LIMIT $limit OFFSET $offset;";
        command.CommandText = sql;
        command.AddParameter("$limit", request.Limit);
        command.AddParameter("$offset", request.Offset);

        var events = new List<SecurityEventSummary>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            events.Add(ReadSummary(reader));
        }

        return events.AsReadOnly();
    }

    /// <summary>
    /// Gets a recorded security event by id.
    /// </summary>
    /// <param name="eventId">The event id value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The security event, or <see langword="null" /> when it does not exist.</returns>
    public async Task<SecurityEventSummary?> GetSecurityEventAsync(Guid eventId, CancellationToken cancellationToken = default)
    {
        var sql = SelectSql + " WHERE id = $eventId;";

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddGuidParameter("$eventId", eventId);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadSummary(reader) : null;
    }

    private const string SelectSql = """
        SELECT id, event_type, occurred_at, user_id, tenant_id, actor_user_id, session_id,
               provider_type, provider_name, ip_address, user_agent, correlation_id,
               outcome, failure_reason, properties
        FROM ashlar_security_events
        """;

    private static void AddFilters(SearchSecurityEventsRequest request, ref string sql, SqliteCommand command)
    {
        if (request.Tenant != null)
        {
            if (request.Tenant.TenantId == null)
            {
                sql += " AND tenant_id IS NULL";
            }
            else
            {
                sql += " AND tenant_id = $tenantId";
                command.AddNullableGuidParameter("$tenantId", request.Tenant.TenantId);
            }
        }

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

        if (request.Provider.HasValue)
        {
            sql += " AND provider_type = $providerType AND provider_name = $providerName";
            command.AddParameter("$providerType", request.Provider.Value.TypeValueOrUnknown);
            command.AddParameter("$providerName", request.Provider.Value.Name);
        }

        if (request.OccurredFrom.HasValue)
        {
            sql += " AND occurred_at >= $occurredFrom";
            command.AddDateTimeOffsetParameter("$occurredFrom", request.OccurredFrom.Value);
        }

        if (request.OccurredTo.HasValue)
        {
            sql += " AND occurred_at <= $occurredTo";
            command.AddDateTimeOffsetParameter("$occurredTo", request.OccurredTo.Value);
        }
    }

    private static SecurityEventSummary ReadSummary(SqliteDataReader reader)
    {
        return new SecurityEventSummary(
            reader.GetGuidFromText("id"),
            reader.GetString(reader.GetOrdinal("event_type")),
            reader.GetDateTimeOffsetFromText("occurred_at"),
            reader.GetNullableGuidFromText("user_id"),
            reader.GetNullableGuidFromText("tenant_id"),
            reader.GetNullableGuidFromText("actor_user_id"),
            reader.GetNullableGuidFromText("session_id"),
            ToProvider(reader.GetNullableString("provider_type"), reader.GetNullableString("provider_name")),
            reader.GetNullableString("ip_address"),
            reader.GetNullableString("user_agent"),
            reader.GetNullableString("correlation_id"),
            reader.GetNullableString("outcome"),
            reader.GetNullableString("failure_reason"),
            ParseProperties(reader.GetNullableString("properties")));
    }

    private static AuthenticationProviderKey? ToProvider(string? providerType, string? providerName)
    {
        return string.IsNullOrWhiteSpace(providerType) || string.IsNullOrWhiteSpace(providerName)
            ? null
            : new AuthenticationProviderKey((ProviderType)providerType, providerName);
    }

    internal static Dictionary<string, string>? ParseProperties(string? propertiesJson)
    {
        if (string.IsNullOrWhiteSpace(propertiesJson))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(propertiesJson);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            var properties = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var property in document.RootElement.EnumerateObject())
            {
                if (property.Value.ValueKind == JsonValueKind.String)
                {
                    properties[property.Name] = property.Value.ToString();
                }
            }

            return properties.Count == 0 ? null : properties;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
