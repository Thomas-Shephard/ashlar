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

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, parameters, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var rows = await connectionHandle.Connection.QueryAsync<AuthenticationSessionAdministrationRow>(command);
            return rows.Select(static row => row.ToSummary()).ToList().AsReadOnly();
        }
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
        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new { Id = sessionId, Now = now }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var row = await connectionHandle.Connection.QueryFirstOrDefaultAsync<AuthenticationSessionAdministrationRow>(command);
            return row?.ToDetail();
        }
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

        if (request.PrimaryProvider.HasValue)
        {
            sql += " AND primary_provider_type = @PrimaryProviderType AND primary_provider_name = @PrimaryProviderName";
            parameters.Add("PrimaryProviderType", request.PrimaryProvider.Value.TypeValueOrUnknown);
            parameters.Add("PrimaryProviderName", request.PrimaryProvider.Value.Name);
        }

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

        AddDateRange(request.CreatedFrom, request.CreatedTo, "created_at", "CreatedFrom", "CreatedTo", ref sql, parameters);
        AddDateRange(request.ExpiresFrom, request.ExpiresTo, "expires_at", "ExpiresFrom", "ExpiresTo", ref sql, parameters);
        AddDateRange(request.LastSeenFrom, request.LastSeenTo, "last_seen_at", "LastSeenFrom", "LastSeenTo", ref sql, parameters);
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
                ToDateTimeOffset(CreatedAt),
                ToNullableDateTimeOffset(AuthenticatedAt),
                CreateProvider(PrimaryProviderType, PrimaryProviderName),
                ToNullableDateTimeOffset(AdditionalVerificationAt),
                CreateProvider(AdditionalVerificationProviderType, AdditionalVerificationProviderName),
                AdditionalVerificationFactor,
                ToDateTimeOffset(ExpiresAt),
                ToNullableDateTimeOffset(LastSeenAt),
                ToNullableDateTimeOffset(RevokedAt),
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

        private static DateTimeOffset ToDateTimeOffset(DateTime value)
        {
            return new DateTimeOffset(DateTime.SpecifyKind(value, DateTimeKind.Utc));
        }

        private static DateTimeOffset? ToNullableDateTimeOffset(DateTime? value)
        {
            return value == null ? null : ToDateTimeOffset(value.Value);
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
