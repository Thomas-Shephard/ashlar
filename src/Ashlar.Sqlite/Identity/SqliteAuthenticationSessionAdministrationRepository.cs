using Microsoft.Data.Sqlite;

namespace Ashlar.Sqlite.Identity;

/// <summary>
/// Provides SQLite-backed administrator authentication session reads.
/// </summary>
/// <param name="connectionProvider">The connection provider value.</param>
public sealed class SqliteAuthenticationSessionAdministrationRepository(ISqliteConnectionProvider connectionProvider) : IAuthenticationSessionAdministrationRepository
{
    private readonly ISqliteConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));

    /// <summary>
    /// Searches authentication sessions using safe administrator-display fields.
    /// </summary>
    /// <param name="request">The search request value.</param>
    /// <param name="now">The timestamp used for active-state filtering and projection.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The matching authentication sessions.</returns>
    public async Task<IReadOnlyList<AuthenticationSessionAdministrationSummary>> SearchAuthenticationSessionsAsync(SearchAuthenticationSessionsRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var sql = SelectSql + " WHERE 1 = 1";

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;

        AddFilters(request, now, ref sql, command);

        sql += " ORDER BY last_seen_at IS NULL ASC, last_seen_at DESC, created_at DESC, id DESC LIMIT $limit OFFSET $offset;";
        command.CommandText = sql;
        command.AddParameter("$limit", request.Limit);
        command.AddParameter("$offset", request.Offset);
        command.AddDateTimeOffsetParameter("$now", now);

        var sessions = new List<AuthenticationSessionAdministrationSummary>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            sessions.Add(ReadSummary(reader));
        }

        return sessions.AsReadOnly();
    }

    /// <summary>
    /// Gets an authentication session by id.
    /// </summary>
    /// <param name="sessionId">The session id value.</param>
    /// <param name="now">The timestamp used for active-state projection.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The authentication session, or <see langword="null" /> when it does not exist.</returns>
    public async Task<AuthenticationSessionAdministrationDetail?> GetAuthenticationSessionAsync(Guid sessionId, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        var sql = SelectSql + " WHERE id = $id;";

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddGuidParameter("$id", sessionId);
        command.AddDateTimeOffsetParameter("$now", now);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadDetail(reader) : null;
    }

    private const string SelectSql = """
        SELECT id, user_id, tenant_id, created_at, authenticated_at, primary_provider_type, primary_provider_name,
               additional_verification_at, additional_verification_provider_type, additional_verification_provider_name,
               additional_verification_factor, expires_at, last_seen_at, revoked_at, revocation_reason, ip_address, user_agent,
               CASE WHEN revoked_at IS NULL AND expires_at > $now THEN 1 ELSE 0 END AS is_active
        FROM ashlar_sessions
        """;

    private static void AddFilters(SearchAuthenticationSessionsRequest request, DateTimeOffset now, ref string sql, SqliteCommand command)
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

        if (request.PrimaryProvider.HasValue)
        {
            sql += " AND primary_provider_type = $primaryProviderType AND primary_provider_name = $primaryProviderName";
            command.AddParameter("$primaryProviderType", request.PrimaryProvider.Value.TypeValueOrUnknown);
            command.AddParameter("$primaryProviderName", request.PrimaryProvider.Value.Name);
        }

        if (request.Active.HasValue)
        {
            sql += request.Active.Value
                ? " AND revoked_at IS NULL AND expires_at > $now"
                : " AND (revoked_at IS NOT NULL OR expires_at <= $now)";
        }

        if (request.Revoked.HasValue)
        {
            sql += request.Revoked.Value ? " AND revoked_at IS NOT NULL" : " AND revoked_at IS NULL";
        }

        AddDateRange(request.CreatedFrom, request.CreatedTo, "created_at", "$createdFrom", "$createdTo", ref sql, command);
        AddDateRange(request.ExpiresFrom, request.ExpiresTo, "expires_at", "$expiresFrom", "$expiresTo", ref sql, command);
        AddDateRange(request.LastSeenFrom, request.LastSeenTo, "last_seen_at", "$lastSeenFrom", "$lastSeenTo", ref sql, command);
    }

    private static void AddDateRange(DateTimeOffset? from, DateTimeOffset? to, string column, string fromParameter, string toParameter, ref string sql, SqliteCommand command)
    {
        if (from.HasValue)
        {
            sql += $" AND {column} >= {fromParameter}";
            command.AddDateTimeOffsetParameter(fromParameter, from.Value);
        }

        if (to.HasValue)
        {
            sql += $" AND {column} <= {toParameter}";
            command.AddDateTimeOffsetParameter(toParameter, to.Value);
        }
    }

    private static AuthenticationSessionAdministrationSummary ReadSummary(SqliteDataReader reader)
    {
        return new AuthenticationSessionAdministrationSummary(
            reader.GetGuidFromText("id"),
            reader.GetGuidFromText("user_id"),
            reader.GetNullableGuidFromText("tenant_id"),
            reader.GetDateTimeOffsetFromText("created_at"),
            reader.GetNullableDateTimeOffsetFromText("authenticated_at"),
            CreateProvider(reader.GetNullableString("primary_provider_type"), reader.GetNullableString("primary_provider_name")),
            reader.GetNullableDateTimeOffsetFromText("additional_verification_at"),
            CreateProvider(reader.GetNullableString("additional_verification_provider_type"), reader.GetNullableString("additional_verification_provider_name")),
            reader.GetNullableString("additional_verification_factor"),
            reader.GetDateTimeOffsetFromText("expires_at"),
            reader.GetNullableDateTimeOffsetFromText("last_seen_at"),
            reader.GetNullableDateTimeOffsetFromText("revoked_at"),
            reader.GetNullableString("revocation_reason"),
            reader.GetNullableString("ip_address"),
            reader.GetNullableString("user_agent"),
            reader.GetInt32(reader.GetOrdinal("is_active")) == 1);
    }

    private static AuthenticationSessionAdministrationDetail ReadDetail(SqliteDataReader reader)
    {
        var summary = ReadSummary(reader);
        return new AuthenticationSessionAdministrationDetail(
            summary.Id,
            summary.UserId,
            summary.TenantId,
            summary.CreatedAt,
            summary.AuthenticatedAt,
            summary.PrimaryProvider,
            summary.AdditionalVerificationAt,
            summary.AdditionalVerificationProvider,
            summary.AdditionalVerificationFactor,
            summary.ExpiresAt,
            summary.LastSeenAt,
            summary.RevokedAt,
            summary.RevocationReason,
            summary.IpAddress,
            summary.UserAgent,
            summary.IsActive);
    }

    private static AuthenticationProviderKey? CreateProvider(string? type, string? name)
    {
        if (string.IsNullOrWhiteSpace(type) || string.IsNullOrWhiteSpace(name))
        {
            return null;
        }

        ProviderType providerType = type;
        return new AuthenticationProviderKey(providerType, name);
    }
}
