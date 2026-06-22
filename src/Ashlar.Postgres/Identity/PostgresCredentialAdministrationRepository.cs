using Dapper;

namespace Ashlar.Postgres.Identity;

/// <summary>
/// Provides PostgreSQL-backed administrator credential reads.
/// </summary>
/// <param name="connectionProvider">The connection provider value.</param>
public sealed class PostgresCredentialAdministrationRepository(IPostgresConnectionProvider connectionProvider) : ICredentialAdministrationRepository
{
    private readonly IPostgresConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));

    /// <summary>
    /// Searches credentials using safe administrator-display fields.
    /// </summary>
    /// <param name="request">The search request value.</param>
    /// <param name="now">The timestamp used for availability filtering and projection.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The matching credentials.</returns>
    public async Task<IReadOnlyList<CredentialAdministrationSummary>> SearchCredentialsAsync(SearchCredentialsRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        SearchCredentialsRequest.ThrowIfInvalid(request);

        var sql = SelectSql + " WHERE 1 = 1";
        var parameters = new DynamicParameters();
        parameters.Add("Now", now);

        AddFilters(request, ref sql, parameters);

        sql += " ORDER BY c.last_used_at DESC NULLS LAST, c.created_at DESC, c.id DESC LIMIT @Limit OFFSET @Offset";
        parameters.Add("Limit", request.Limit);
        parameters.Add("Offset", request.Offset);

        var rows = await PostgresAdminQuery.QueryAsync<CredentialAdministrationRow>(_connectionProvider, sql, parameters, cancellationToken);
        return rows.Select(static row => row.ToSummary()).ToList().AsReadOnly();
    }

    /// <summary>
    /// Gets a safe credential projection by credential id.
    /// </summary>
    /// <param name="request">The lookup request value.</param>
    /// <param name="now">The timestamp used for availability projection.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The credential, or <see langword="null" /> when it does not exist.</returns>
    public async Task<CredentialAdministrationSummary?> GetCredentialAsync(CredentialAdministrationLookupRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        CredentialAdministrationLookupRequest.ThrowIfInvalid(request);

        var sql = SelectSql + " WHERE c.id = @CredentialId";
        var parameters = new DynamicParameters();
        parameters.Add("CredentialId", request.CredentialId);
        parameters.Add("Now", now);
        PostgresAdminQuery.AddTenantFilter(request.Tenant, "u.tenant_id", "TenantId", ref sql, parameters);

        var row = await PostgresAdminQuery.QuerySingleAsync<CredentialAdministrationRow>(_connectionProvider, sql, parameters, cancellationToken);
        return row?.ToSummary();
    }

    private const string SelectSql = """
        SELECT c.id AS CredentialId, c.user_id AS UserId, u.tenant_id AS TenantId,
               c.provider_type AS ProviderType, c.provider_name AS ProviderName, c.purpose AS Purpose,
               c.status AS Status, c.created_at AS CreatedAt, c.updated_at AS UpdatedAt,
               c.last_used_at AS LastUsedAt, c.expires_at AS ExpiresAt, c.revoked_at AS RevokedAt,
               c.status = 0 AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at > @Now) AS IsAvailable
        FROM ashlar_credentials c
        JOIN ashlar_users u ON u.id = c.user_id
        """;

    private static void AddFilters(SearchCredentialsRequest request, ref string sql, DynamicParameters parameters)
    {
        PostgresAdminQuery.AddTenantFilter(request.Tenant, "u.tenant_id", "TenantId", ref sql, parameters);

        if (request.UserId.HasValue)
        {
            sql += " AND c.user_id = @UserId";
            parameters.Add("UserId", request.UserId.Value);
        }

        PostgresAdminQuery.AddProviderFilter(request.Provider, "c.provider_type", "c.provider_name", "ProviderType", "ProviderName", ref sql, parameters);

        if (!string.IsNullOrWhiteSpace(request.Purpose))
        {
            sql += " AND c.purpose = @Purpose";
            parameters.Add("Purpose", request.Purpose.Trim());
        }

        if (request.Status.HasValue)
        {
            sql += " AND c.status = @Status";
            parameters.Add("Status", (int)request.Status.Value);
        }

        if (request.Available.HasValue)
        {
            sql += request.Available.Value
                ? " AND c.status = 0 AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at > @Now)"
                : " AND (c.status <> 0 OR c.revoked_at IS NOT NULL OR c.expires_at <= @Now)";
        }

        if (request.Revoked.HasValue)
        {
            sql += request.Revoked.Value ? " AND c.revoked_at IS NOT NULL" : " AND c.revoked_at IS NULL";
        }

        PostgresAdminQuery.AddDateRange(request.CreatedFrom, request.CreatedTo, "c.created_at", "CreatedFrom", "CreatedTo", ref sql, parameters);
        PostgresAdminQuery.AddDateRange(request.UpdatedFrom, request.UpdatedTo, "c.updated_at", "UpdatedFrom", "UpdatedTo", ref sql, parameters);
        PostgresAdminQuery.AddDateRange(request.LastUsedFrom, request.LastUsedTo, "c.last_used_at", "LastUsedFrom", "LastUsedTo", ref sql, parameters);
        PostgresAdminQuery.AddDateRange(request.ExpiresFrom, request.ExpiresTo, "c.expires_at", "ExpiresFrom", "ExpiresTo", ref sql, parameters);
    }

    private sealed record CredentialAdministrationRow(
        Guid CredentialId,
        Guid UserId,
        Guid? TenantId,
        string ProviderType,
        string ProviderName,
        string? Purpose,
        int Status,
        DateTime CreatedAt,
        DateTime? UpdatedAt,
        DateTime? LastUsedAt,
        DateTime? ExpiresAt,
        DateTime? RevokedAt,
        bool IsAvailable)
    {
        public CredentialAdministrationSummary ToSummary()
        {
            return new CredentialAdministrationSummary(
                CredentialId,
                UserId,
                TenantId,
                CreateProvider(),
                Purpose,
                (CredentialStatus)Status,
                IsAvailable,
                PostgresAdminQuery.ToDateTimeOffset(CreatedAt),
                PostgresAdminQuery.ToNullableDateTimeOffset(UpdatedAt),
                PostgresAdminQuery.ToNullableDateTimeOffset(LastUsedAt),
                PostgresAdminQuery.ToNullableDateTimeOffset(ExpiresAt),
                PostgresAdminQuery.ToNullableDateTimeOffset(RevokedAt));
        }

        private AuthenticationProviderKey CreateProvider()
        {
            Ashlar.Identity.Models.Authentication.ProviderType providerType = ProviderType;
            return new AuthenticationProviderKey(providerType, ProviderName);
        }

    }
}
