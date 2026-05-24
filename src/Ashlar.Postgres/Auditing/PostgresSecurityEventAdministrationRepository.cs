using System.Text.Json;
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

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, parameters, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var rows = await connectionHandle.Connection.QueryAsync<SecurityEventRow>(command);
            return rows.Select(ToSummary).ToList().AsReadOnly();
        }
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
        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new { EventId = eventId }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var row = await connectionHandle.Connection.QueryFirstOrDefaultAsync<SecurityEventRow>(command);
            return row == null ? null : ToSummary(row);
        }
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
        if (request.Tenant != null)
        {
            sql += request.Tenant.TenantId == null ? " AND tenant_id IS NULL" : " AND tenant_id = @TenantId";
            parameters.Add("TenantId", request.Tenant.TenantId);
        }

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

        if (request.Provider.HasValue)
        {
            sql += " AND provider_type = @ProviderType AND provider_name = @ProviderName";
            parameters.Add("ProviderType", request.Provider.Value.TypeValueOrUnknown);
            parameters.Add("ProviderName", request.Provider.Value.Name);
        }

        if (request.OccurredFrom.HasValue)
        {
            sql += " AND occurred_at >= @OccurredFrom";
            parameters.Add("OccurredFrom", request.OccurredFrom.Value);
        }

        if (request.OccurredTo.HasValue)
        {
            sql += " AND occurred_at <= @OccurredTo";
            parameters.Add("OccurredTo", request.OccurredTo.Value);
        }
    }

    private static SecurityEventSummary ToSummary(SecurityEventRow row)
    {
        return new SecurityEventSummary(
            row.EventId,
            row.EventType,
            ToDateTimeOffset(row.OccurredAt),
            row.UserId,
            row.TenantId,
            row.ActorUserId,
            row.SessionId,
            ToProvider(row.ProviderType, row.ProviderName),
            row.IpAddress,
            row.UserAgent,
            row.CorrelationId,
            row.Outcome,
            row.FailureReason,
            ParseProperties(row.PropertiesJson));
    }

    private static DateTimeOffset ToDateTimeOffset(DateTime value)
    {
        return new DateTimeOffset(DateTime.SpecifyKind(value, DateTimeKind.Utc));
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
        string? PropertiesJson);
}
