using Microsoft.Data.Sqlite;

namespace Ashlar.Sqlite.Identity;

/// <summary>
/// Provides SQLite-backed administrator user reads.
/// </summary>
/// <param name="connectionProvider">The connection provider value.</param>
public sealed class SqliteUserAdministrationRepository(ISqliteConnectionProvider connectionProvider) : IUserAdministrationRepository
{
    private readonly ISqliteConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));

    /// <summary>
    /// Searches users using safe administrator-display fields.
    /// </summary>
    /// <param name="request">The search request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<IReadOnlyList<UserSummary>> SearchUsersAsync(SearchUsersRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        return await SqliteQuery.QueryAsync(_connectionProvider, command =>
        {
            var sql = """
                SELECT id, email, name, tenant_id, is_active, email_verified_at, created_at, updated_at
                FROM ashlar_users
                WHERE 1 = 1
                """;

            if (!string.IsNullOrWhiteSpace(request.Query))
            {
                sql += " AND (instr(lower(email), lower($query)) > 0 OR instr(lower(coalesce(name, '')), lower($query)) > 0)";
                command.AddParameter("$query", request.Query.Trim());
            }

            command.AddTenantFilter(request.Tenant, "tenant_id", "$tenantId", ref sql);

            if (request.IsActive.HasValue)
            {
                sql += " AND is_active = $isActive";
                command.AddParameter("$isActive", request.IsActive.Value ? 1 : 0);
            }

            if (request.IsEmailVerified.HasValue)
            {
                sql += request.IsEmailVerified.Value
                    ? " AND email_verified_at IS NOT NULL"
                    : " AND email_verified_at IS NULL";
            }

            sql += " ORDER BY lower(email), id LIMIT $limit OFFSET $offset;";
            command.AddParameter("$limit", request.Limit);
            command.AddParameter("$offset", request.Offset);

            return sql;
        }, ReadUserSummary, cancellationToken);
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
            SELECT id, email, name, tenant_id, is_active, email_verified_at, created_at, updated_at
            FROM ashlar_users
            WHERE id = $userId;
            """;

        return await SqliteQuery.QuerySingleAsync(_connectionProvider, command =>
        {
            command.AddGuidParameter("$userId", userId);
            return sql;
        }, ReadUserSummary, cancellationToken);
    }

    private static UserSummary ReadUserSummary(SqliteDataReader reader)
    {
        return new UserSummary(
            reader.GetGuidFromText("id"),
            reader.GetString(reader.GetOrdinal("email")),
            reader.GetNullableString("name"),
            reader.GetNullableGuidFromText("tenant_id"),
            reader.GetBooleanFromInteger("is_active"),
            !reader.IsDBNull(reader.GetOrdinal("email_verified_at")),
            reader.GetDateTimeOffsetFromText("created_at"),
            reader.GetNullableDateTimeOffsetFromText("updated_at"));
    }
}
