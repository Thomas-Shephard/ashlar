using Dapper;

namespace Ashlar.Postgres.Identity;

/// <summary>
/// Provides PostgreSQL-backed administrator authentication session reads.
/// </summary>
/// <param name="connectionProvider">The connection provider value.</param>
public sealed class PostgresAuthenticationSessionAdministrationRepository(IPostgresConnectionProvider connectionProvider) : IAuthenticationSessionAdministrationRepository
{
    private readonly IPostgresConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));

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
        var parameters = new DynamicParameters();
        parameters.Add("Now", now);

        AddFilters(request, ref sql, parameters);

        sql += " ORDER BY last_seen_at DESC NULLS LAST, created_at DESC, id DESC LIMIT @Limit OFFSET @Offset";
        parameters.Add("Limit", request.Limit);
        parameters.Add("Offset", request.Offset);

        var rows = await PostgresAdminQuery.QueryAsync<AuthenticationSessionAdministrationRow>(_connectionProvider, sql, parameters, cancellationToken);
        return rows.Select(static row => row.ToSummary()).ToList().AsReadOnly();
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
        var sql = SelectSql + " WHERE id = @Id";
        var row = await PostgresAdminQuery.QuerySingleAsync<AuthenticationSessionAdministrationRow>(_connectionProvider, sql, new { Id = sessionId, Now = now }, cancellationToken);
        return row?.ToDetail();
    }

    private const string SelectSql = """
        SELECT id AS Id, user_id AS UserId, tenant_id AS TenantId, created_at AS CreatedAt,
               authenticated_at AS AuthenticatedAt, primary_provider_type AS PrimaryProviderType, primary_provider_name AS PrimaryProviderName,
               additional_verification_at AS AdditionalVerificationAt, additional_verification_provider_type AS AdditionalVerificationProviderType,
               additional_verification_provider_name AS AdditionalVerificationProviderName, additional_verification_factor AS AdditionalVerificationFactor,
               expires_at AS ExpiresAt, last_seen_at AS LastSeenAt, revoked_at AS RevokedAt, revocation_reason AS RevocationReason,
               ip_address AS IpAddress, user_agent AS UserAgent, revoked_at IS NULL AND expires_at > @Now AS IsActive
        FROM ashlar_sessions
        """;

    private static void AddFilters(SearchAuthenticationSessionsRequest request, ref string sql, DynamicParameters parameters)
    {
        PostgresAdminQuery.AddTenantFilter(request.Tenant, "tenant_id", "TenantId", ref sql, parameters);

        if (request.UserId.HasValue)
        {
            sql += " AND user_id = @UserId";
            parameters.Add("UserId", request.UserId.Value);
        }

        PostgresAdminQuery.AddProviderFilter(request.PrimaryProvider, "primary_provider_type", "primary_provider_name", "PrimaryProviderType", "PrimaryProviderName", ref sql, parameters);

        if (request.Active.HasValue)
        {
            sql += request.Active.Value
                ? " AND revoked_at IS NULL AND expires_at > @Now"
                : " AND (revoked_at IS NOT NULL OR expires_at <= @Now)";
        }

        if (request.Revoked.HasValue)
        {
            sql += request.Revoked.Value ? " AND revoked_at IS NOT NULL" : " AND revoked_at IS NULL";
        }

        PostgresAdminQuery.AddDateRange(request.CreatedFrom, request.CreatedTo, "created_at", "CreatedFrom", "CreatedTo", ref sql, parameters);
        PostgresAdminQuery.AddDateRange(request.ExpiresFrom, request.ExpiresTo, "expires_at", "ExpiresFrom", "ExpiresTo", ref sql, parameters);
        PostgresAdminQuery.AddDateRange(request.LastSeenFrom, request.LastSeenTo, "last_seen_at", "LastSeenFrom", "LastSeenTo", ref sql, parameters);
    }

    private sealed record AuthenticationSessionAdministrationRow(
        Guid Id,
        Guid UserId,
        Guid? TenantId,
        DateTime CreatedAt,
        DateTime? AuthenticatedAt,
        string? PrimaryProviderType,
        string? PrimaryProviderName,
        DateTime? AdditionalVerificationAt,
        string? AdditionalVerificationProviderType,
        string? AdditionalVerificationProviderName,
        string? AdditionalVerificationFactor,
        DateTime ExpiresAt,
        DateTime? LastSeenAt,
        DateTime? RevokedAt,
        string? RevocationReason,
        string? IpAddress,
        string? UserAgent,
        bool IsActive)
    {
        public AuthenticationSessionAdministrationSummary ToSummary()
        {
            return new AuthenticationSessionAdministrationSummary(
                Id,
                UserId,
                TenantId,
                PostgresAdminQuery.ToDateTimeOffset(CreatedAt),
                PostgresAdminQuery.ToNullableDateTimeOffset(AuthenticatedAt),
                CreateProvider(PrimaryProviderType, PrimaryProviderName),
                PostgresAdminQuery.ToNullableDateTimeOffset(AdditionalVerificationAt),
                CreateProvider(AdditionalVerificationProviderType, AdditionalVerificationProviderName),
                AdditionalVerificationFactor,
                PostgresAdminQuery.ToDateTimeOffset(ExpiresAt),
                PostgresAdminQuery.ToNullableDateTimeOffset(LastSeenAt),
                PostgresAdminQuery.ToNullableDateTimeOffset(RevokedAt),
                RevocationReason,
                IpAddress,
                UserAgent,
                IsActive);
        }

        public AuthenticationSessionAdministrationDetail ToDetail()
        {
            var summary = ToSummary();
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
}
