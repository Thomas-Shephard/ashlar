using Microsoft.Data.Sqlite;

namespace Ashlar.Sqlite.Identity;

/// <summary>
/// Provides SQLite-backed administrator credential reads.
/// </summary>
/// <param name="connectionProvider">The connection provider value.</param>
public sealed class SqliteCredentialAdministrationRepository(ISqliteConnectionProvider connectionProvider) : ICredentialAdministrationRepository
{
    private readonly ISqliteConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));

    /// <summary>
    /// Searches credentials using safe administrator-display fields.
    /// </summary>
    /// <param name="request">The search request value.</param>
    /// <param name="now">The timestamp used for availability filtering and projection.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The matching credentials.</returns>
    public async Task<IReadOnlyList<CredentialAdministrationSummary>> SearchCredentialsAsync(SearchCredentialsRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        return await SqliteQuery.QueryAsync(_connectionProvider, command =>
        {
            var sql = SelectSql + " WHERE 1 = 1";
            AddFilters(request, ref sql, command);
            sql += " ORDER BY c.last_used_at IS NULL ASC, c.last_used_at DESC, c.created_at DESC, c.id DESC LIMIT $limit OFFSET $offset;";
            command.AddParameter("$limit", request.Limit);
            command.AddParameter("$offset", request.Offset);
            command.AddDateTimeOffsetParameter("$now", now);

            return sql;
        }, ReadSummary, cancellationToken);
    }

    /// <summary>
    /// Gets safe credential detail by credential id.
    /// </summary>
    /// <param name="credentialId">The credential id value.</param>
    /// <param name="now">The timestamp used for availability projection.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The credential, or <see langword="null" /> when it does not exist.</returns>
    public async Task<CredentialAdministrationDetail?> GetCredentialAsync(Guid credentialId, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        return await SqliteQuery.QuerySingleAsync(_connectionProvider, command =>
        {
            command.AddGuidParameter("$credentialId", credentialId);
            command.AddDateTimeOffsetParameter("$now", now);

            return SelectSql + " WHERE c.id = $credentialId;";
        }, ReadDetail, cancellationToken);
    }

    private const string SelectSql = """
        SELECT c.id, c.user_id, u.tenant_id, c.provider_type, c.provider_name, c.purpose, c.status,
               c.created_at, c.updated_at, c.last_used_at, c.expires_at, c.revoked_at,
               CASE WHEN c.status = 0 AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at > $now) THEN 1 ELSE 0 END AS is_available
        FROM ashlar_credentials c
        JOIN ashlar_users u ON u.id = c.user_id
        """;

    private static void AddFilters(SearchCredentialsRequest request, ref string sql, SqliteCommand command)
    {
        command.AddTenantFilter(request.Tenant, "u.tenant_id", "$tenantId", ref sql);

        if (request.UserId.HasValue)
        {
            sql += " AND c.user_id = $userId";
            command.AddGuidParameter("$userId", request.UserId.Value);
        }

        command.AddProviderFilter(request.Provider, "c.provider_type", "c.provider_name", "$providerType", "$providerName", ref sql);

        if (!string.IsNullOrWhiteSpace(request.Purpose))
        {
            sql += " AND c.purpose = $purpose";
            command.AddParameter("$purpose", request.Purpose.Trim());
        }

        if (request.Status.HasValue)
        {
            sql += " AND c.status = $status";
            command.AddParameter("$status", (int)request.Status.Value);
        }

        if (request.Available.HasValue)
        {
            sql += request.Available.Value
                ? " AND c.status = 0 AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at > $now)"
                : " AND (c.status <> 0 OR c.revoked_at IS NOT NULL OR c.expires_at <= $now)";
        }

        if (request.Revoked.HasValue)
        {
            sql += request.Revoked.Value ? " AND c.revoked_at IS NOT NULL" : " AND c.revoked_at IS NULL";
        }

        command.AddDateRange(request.CreatedFrom, request.CreatedTo, "c.created_at", "$createdFrom", "$createdTo", ref sql);
        command.AddDateRange(request.UpdatedFrom, request.UpdatedTo, "c.updated_at", "$updatedFrom", "$updatedTo", ref sql);
        command.AddDateRange(request.LastUsedFrom, request.LastUsedTo, "c.last_used_at", "$lastUsedFrom", "$lastUsedTo", ref sql);
        command.AddDateRange(request.ExpiresFrom, request.ExpiresTo, "c.expires_at", "$expiresFrom", "$expiresTo", ref sql);
    }

    private static CredentialAdministrationSummary ReadSummary(SqliteDataReader reader)
    {
        return new CredentialAdministrationSummary(
            reader.GetGuidFromText("id"),
            reader.GetGuidFromText("user_id"),
            reader.GetNullableGuidFromText("tenant_id"),
            CreateProvider(reader.GetString(reader.GetOrdinal("provider_type")), reader.GetString(reader.GetOrdinal("provider_name"))),
            reader.GetNullableString("purpose"),
            (CredentialStatus)reader.GetInt32ByName("status"),
            reader.GetInt32(reader.GetOrdinal("is_available")) == 1,
            reader.GetDateTimeOffsetFromText("created_at"),
            reader.GetNullableDateTimeOffsetFromText("updated_at"),
            reader.GetNullableDateTimeOffsetFromText("last_used_at"),
            reader.GetNullableDateTimeOffsetFromText("expires_at"),
            reader.GetNullableDateTimeOffsetFromText("revoked_at"));
    }

    private static CredentialAdministrationDetail ReadDetail(SqliteDataReader reader)
    {
        var summary = ReadSummary(reader);
        return new CredentialAdministrationDetail(
            summary.CredentialId,
            summary.UserId,
            summary.TenantId,
            summary.Provider,
            summary.Purpose,
            summary.Status,
            summary.IsAvailable,
            summary.CreatedAt,
            summary.UpdatedAt,
            summary.LastUsedAt,
            summary.ExpiresAt,
            summary.RevokedAt);
    }

    private static AuthenticationProviderKey CreateProvider(string type, string name)
    {
        ProviderType providerType = type;
        return new AuthenticationProviderKey(providerType, name);
    }
}
