using Dapper;

namespace Ashlar.Postgres.Identity;

/// <summary>
/// Provides PostgreSQL-backed administrator user reads.
/// </summary>
/// <param name="connectionProvider">The connection provider value.</param>
public sealed class PostgresUserAdministrationRepository(IPostgresConnectionProvider connectionProvider) : IUserAdministrationRepository
{
    private readonly IPostgresConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));

    /// <summary>
    /// Searches users using safe administrator-display fields.
    /// </summary>
    /// <param name="request">The search request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<IReadOnlyList<UserSummary>> SearchUsersAsync(SearchUsersRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var sql = """
            SELECT id AS UserId, email, name, tenant_id AS TenantId, is_active AS IsActive,
                   (email_verified_at IS NOT NULL) AS IsEmailVerified, created_at AS CreatedAt, updated_at AS UpdatedAt
            FROM ashlar_users
            WHERE 1 = 1
            """;

        var parameters = new DynamicParameters();
        if (!string.IsNullOrWhiteSpace(request.Query))
        {
            sql += " AND (email ILIKE @Query OR name ILIKE @Query)";
            parameters.Add("Query", $"%{request.Query.Trim()}%");
        }

        PostgresAdminQuery.AddTenantFilter(request.Tenant, "tenant_id", "TenantId", ref sql, parameters);

        if (request.IsActive.HasValue)
        {
            sql += " AND is_active = @IsActive";
            parameters.Add("IsActive", request.IsActive.Value);
        }

        if (request.IsEmailVerified.HasValue)
        {
            sql += request.IsEmailVerified.Value
                ? " AND email_verified_at IS NOT NULL"
                : " AND email_verified_at IS NULL";
        }

        sql += " ORDER BY lower(email), id LIMIT @Limit OFFSET @Offset";
        parameters.Add("Limit", request.Limit);
        parameters.Add("Offset", request.Offset);

        var rows = await PostgresAdminQuery.QueryAsync<UserAdministrationUserRow>(_connectionProvider, sql, parameters, cancellationToken);
        return rows.Select(ToUserSummary).ToList().AsReadOnly();
    }

    /// <summary>
    /// Gets a user summary by id.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<UserSummary?> GetUserSummaryAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT id AS UserId, email, name, tenant_id AS TenantId, is_active AS IsActive,
                   (email_verified_at IS NOT NULL) AS IsEmailVerified, created_at AS CreatedAt, updated_at AS UpdatedAt
            FROM ashlar_users
            WHERE id = @UserId
            """;

        var row = await PostgresAdminQuery.QuerySingleAsync<UserAdministrationUserRow>(_connectionProvider, sql, new { UserId = userId }, cancellationToken);
        return row == null ? null : ToUserSummary(row);
    }

    private static UserSummary ToUserSummary(UserAdministrationUserRow row)
    {
        return new UserSummary(
            row.UserId,
            row.Email,
            row.Name,
            row.TenantId,
            row.IsActive,
            row.IsEmailVerified,
            PostgresAdminQuery.ToDateTimeOffset(row.CreatedAt),
            PostgresAdminQuery.ToNullableDateTimeOffset(row.UpdatedAt));
    }

    private sealed record UserAdministrationUserRow(
        Guid UserId,
        string Email,
        string? Name,
        Guid? TenantId,
        bool IsActive,
        bool IsEmailVerified,
        DateTime CreatedAt,
        DateTime? UpdatedAt);
}
