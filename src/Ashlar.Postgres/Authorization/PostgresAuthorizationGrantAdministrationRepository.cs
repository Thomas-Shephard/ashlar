using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Dapper;

namespace Ashlar.Postgres.Authorization;

/// <summary>
/// Provides PostgreSQL authorization grant administration query behavior.
/// </summary>
/// <param name="connectionProvider">Connection provider used to query authorization grant records.</param>
public sealed class PostgresAuthorizationGrantAdministrationRepository(IPostgresConnectionProvider connectionProvider)
    : IAuthorizationGrantAdministrationRepository
{
    private readonly IPostgresConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));

    /// <summary>
    /// Searches authorization grants using safe administrator-display fields.
    /// </summary>
    /// <param name="request">Search filters and tenant scope supplied by an authorized administrator flow.</param>
    /// <param name="now">The timestamp used for status filtering and projection.</param>
    /// <param name="cancellationToken">A token that can cancel the search.</param>
    /// <returns>The matching authorization grants.</returns>
    public Task<IReadOnlyList<AuthorizationGrantAdministrationSummary>> SearchAuthorizationGrantsAsync(SearchAuthorizationGrantsRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var parameters = new DynamicParameters();
        var sql = SelectSql + " WHERE 1 = 1";
        PostgresAdminQuery.AddTenantFilter(request.Tenant, "tenant_id", "TenantId", ref sql, parameters);
        AddOptionalFilters(request, now, ref sql, parameters);
        sql += """
            
            ORDER BY created_at DESC, id
            LIMIT @Limit OFFSET @Offset
            """;
        parameters.Add("Limit", request.Limit);
        parameters.Add("Offset", request.Offset);

        return SearchAsync(sql, parameters, cancellationToken);
    }

    /// <summary>
    /// Gets an authorization grant by id.
    /// </summary>
    /// <param name="request">Grant identifier and tenant scope supplied by an authorized administrator flow.</param>
    /// <param name="now">The timestamp used for status projection.</param>
    /// <param name="cancellationToken">A token that can cancel lookup.</param>
    /// <returns>The authorization grant, or <see langword="null" /> when it does not exist.</returns>
    public Task<AuthorizationGrantAdministrationDetail?> GetAuthorizationGrantAsync(AuthorizationGrantAdministrationDetailRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var parameters = new DynamicParameters();
        parameters.Add("Id", request.GrantId);
        parameters.Add("Now", now);
        var sql = SelectSql + " WHERE id = @Id";
        PostgresAdminQuery.AddTenantFilter(request.Tenant, "tenant_id", "TenantId", ref sql, parameters);

        return GetAsync(sql, parameters, cancellationToken);
    }

    private async Task<IReadOnlyList<AuthorizationGrantAdministrationSummary>> SearchAsync(string sql, DynamicParameters parameters, CancellationToken cancellationToken)
    {
        var rows = await PostgresAdminQuery.QueryAsync<AuthorizationGrantAdministrationRow>(_connectionProvider, sql, parameters, cancellationToken);
        return rows.Select(row => row.ToSummary()).ToList().AsReadOnly();
    }

    private async Task<AuthorizationGrantAdministrationDetail?> GetAsync(string sql, DynamicParameters parameters, CancellationToken cancellationToken)
    {
        var row = await PostgresAdminQuery.QuerySingleAsync<AuthorizationGrantAdministrationRow>(_connectionProvider, sql, parameters, cancellationToken);
        return row?.ToDetail();
    }

    private static void AddOptionalFilters(SearchAuthorizationGrantsRequest request, DateTimeOffset now, ref string sql, DynamicParameters parameters)
    {
        parameters.Add("Now", now);
        AddOptional(request.UserId, "user_id", "UserId", ref sql, parameters);
        AddOptional(request.Role, "role", "Role", ref sql, parameters);
        AddOptional(request.Permission, "permission", "Permission", ref sql, parameters);
        AddOptional(request.ScopeType, "scope_type", "ScopeType", ref sql, parameters);
        AddOptional(request.ScopeId, "scope_id", "ScopeId", ref sql, parameters);
        PostgresAdminQuery.AddDateRange(request.CreatedFrom, request.CreatedTo, "created_at", "CreatedFrom", "CreatedTo", ref sql, parameters);
        PostgresAdminQuery.AddDateRange(request.ExpiresFrom, request.ExpiresTo, "expires_at", "ExpiresFrom", "ExpiresTo", ref sql, parameters);
        PostgresAdminQuery.AddDateRange(request.RevokedFrom, request.RevokedTo, "revoked_at", "RevokedFrom", "RevokedTo", ref sql, parameters);

        if (request.Status != null)
        {
            sql += " AND " + StatusExpression + " = @Status";
            parameters.Add("Status", (int)request.Status.Value);
        }
    }

    private static void AddOptional(object? value, string column, string parameterName, ref string sql, DynamicParameters parameters)
    {
        if (value == null)
        {
            return;
        }

        sql += $" AND {column} = @{parameterName}";
        parameters.Add(parameterName, value);
    }

    private const string StatusExpression = """
        CASE
            WHEN revoked_at IS NOT NULL THEN 1
            WHEN expires_at IS NOT NULL AND expires_at <= @Now THEN 2
            ELSE 0
        END
        """;

    private const string SelectSql = """
        SELECT id,
               user_id AS UserId,
               tenant_id AS TenantId,
               scope_type AS ScopeType,
               scope_id AS ScopeId,
               role,
               permission,
               created_at AS CreatedAt,
               expires_at AS ExpiresAt,
               revoked_at AS RevokedAt,
               CASE
                   WHEN revoked_at IS NOT NULL THEN 1
                   WHEN expires_at IS NOT NULL AND expires_at <= @Now THEN 2
                   ELSE 0
               END AS Status
        FROM ashlar_authorization_grants
        """;

    private sealed class AuthorizationGrantAdministrationRow
    {
        public Guid Id { get; init; }
        public Guid UserId { get; init; }
        public Guid? TenantId { get; init; }
        public string? ScopeType { get; init; }
        public string? ScopeId { get; init; }
        public string? Role { get; init; }
        public string? Permission { get; init; }
        public DateTimeOffset CreatedAt { get; init; }
        public DateTimeOffset? ExpiresAt { get; init; }
        public DateTimeOffset? RevokedAt { get; init; }
        public AuthorizationGrantAdministrationStatus Status { get; init; }

        public AuthorizationGrantAdministrationSummary ToSummary()
        {
            return new AuthorizationGrantAdministrationSummary(Id, UserId, TenantId, ScopeType, ScopeId, Role, Permission, CreatedAt, ExpiresAt, RevokedAt, Status);
        }

        public AuthorizationGrantAdministrationDetail ToDetail()
        {
            return new AuthorizationGrantAdministrationDetail(Id, UserId, TenantId, ScopeType, ScopeId, Role, Permission, CreatedAt, ExpiresAt, RevokedAt, Status);
        }
    }
}
