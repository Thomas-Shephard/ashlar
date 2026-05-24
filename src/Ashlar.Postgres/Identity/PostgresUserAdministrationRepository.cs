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

        if (request.Tenant != null)
        {
            sql += request.Tenant.TenantId == null
                ? " AND tenant_id IS NULL"
                : " AND tenant_id = @TenantId";
            parameters.Add("TenantId", request.Tenant.TenantId);
        }

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

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, parameters, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var result = await connectionHandle.Connection.QueryAsync<UserAdministrationUserRow>(command);
            return result.Select(ToUserSummary).ToList().AsReadOnly();
        }
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

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new { UserId = userId }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var row = await connectionHandle.Connection.QueryFirstOrDefaultAsync<UserAdministrationUserRow>(command);
            return row == null ? null : ToUserSummary(row);
        }
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
            ToDateTimeOffset(row.CreatedAt),
            row.UpdatedAt.HasValue ? ToDateTimeOffset(row.UpdatedAt.Value) : null);
    }

    private static DateTimeOffset ToDateTimeOffset(DateTime value)
    {
        return new DateTimeOffset(DateTime.SpecifyKind(value, DateTimeKind.Utc));
    }

    private sealed class UserAdministrationUserRow
    {
        public Guid UserId { get; init; }
        public string Email { get; init; } = string.Empty;
        public string? Name { get; init; }
        public Guid? TenantId { get; init; }
        public bool IsActive { get; init; }
        public bool IsEmailVerified { get; init; }
        public DateTime CreatedAt { get; init; }
        public DateTime? UpdatedAt { get; init; }
    }
}
