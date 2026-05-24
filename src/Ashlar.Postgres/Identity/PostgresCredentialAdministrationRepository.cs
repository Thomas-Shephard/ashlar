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
        ArgumentNullException.ThrowIfNull(request);

        var sql = SelectSql + " WHERE 1 = 1";
        var parameters = new DynamicParameters();
        parameters.Add("Now", now);

        AddFilters(request, ref sql, parameters);

        sql += " ORDER BY c.last_used_at DESC NULLS LAST, c.created_at DESC, c.id DESC LIMIT @Limit OFFSET @Offset";
        parameters.Add("Limit", request.Limit);
        parameters.Add("Offset", request.Offset);

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, parameters, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var rows = await connectionHandle.Connection.QueryAsync<CredentialAdministrationRow>(command);
            return rows.Select(static row => row.ToSummary()).ToList().AsReadOnly();
        }
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
        var sql = SelectSql + " WHERE c.id = @CredentialId";

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new { CredentialId = credentialId, Now = now }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var row = await connectionHandle.Connection.QueryFirstOrDefaultAsync<CredentialAdministrationRow>(command);
            return row?.ToDetail();
        }
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
        if (request.Tenant != null)
        {
            sql += request.Tenant.TenantId == null ? " AND u.tenant_id IS NULL" : " AND u.tenant_id = @TenantId";
            parameters.Add("TenantId", request.Tenant.TenantId);
        }

        if (request.UserId.HasValue)
        {
            sql += " AND c.user_id = @UserId";
            parameters.Add("UserId", request.UserId.Value);
        }

        if (request.Provider.HasValue)
        {
            sql += " AND c.provider_type = @ProviderType AND c.provider_name = @ProviderName";
            parameters.Add("ProviderType", request.Provider.Value.TypeValueOrUnknown);
            parameters.Add("ProviderName", request.Provider.Value.Name);
        }

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

        AddDateRange(request.CreatedFrom, request.CreatedTo, "c.created_at", "CreatedFrom", "CreatedTo", ref sql, parameters);
        AddDateRange(request.UpdatedFrom, request.UpdatedTo, "c.updated_at", "UpdatedFrom", "UpdatedTo", ref sql, parameters);
        AddDateRange(request.LastUsedFrom, request.LastUsedTo, "c.last_used_at", "LastUsedFrom", "LastUsedTo", ref sql, parameters);
        AddDateRange(request.ExpiresFrom, request.ExpiresTo, "c.expires_at", "ExpiresFrom", "ExpiresTo", ref sql, parameters);
    }

    private static void AddDateRange(DateTimeOffset? from, DateTimeOffset? to, string column, string fromParameter, string toParameter, ref string sql, DynamicParameters parameters)
    {
        if (from.HasValue)
        {
            sql += $" AND {column} >= @{fromParameter}";
            parameters.Add(fromParameter, from.Value);
        }

        if (to.HasValue)
        {
            sql += $" AND {column} <= @{toParameter}";
            parameters.Add(toParameter, to.Value);
        }
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
                ToDateTimeOffset(CreatedAt),
                ToNullableDateTimeOffset(UpdatedAt),
                ToNullableDateTimeOffset(LastUsedAt),
                ToNullableDateTimeOffset(ExpiresAt),
                ToNullableDateTimeOffset(RevokedAt));
        }

        public CredentialAdministrationDetail ToDetail()
        {
            var summary = ToSummary();
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

        private AuthenticationProviderKey CreateProvider()
        {
            Ashlar.Identity.Models.Authentication.ProviderType providerType = ProviderType;
            return new AuthenticationProviderKey(providerType, ProviderName);
        }

        private static DateTimeOffset ToDateTimeOffset(DateTime value)
        {
            return new DateTimeOffset(DateTime.SpecifyKind(value, DateTimeKind.Utc));
        }

        private static DateTimeOffset? ToNullableDateTimeOffset(DateTime? value)
        {
            return value == null ? null : ToDateTimeOffset(value.Value);
        }
    }
}
