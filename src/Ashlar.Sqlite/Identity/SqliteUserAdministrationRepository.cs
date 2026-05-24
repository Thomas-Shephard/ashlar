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

        var sql = """
            SELECT id, email, name, tenant_id, is_active, email_verified_at, created_at, updated_at
            FROM ashlar_users
            WHERE 1 = 1
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;

        if (!string.IsNullOrWhiteSpace(request.Query))
        {
            sql += " AND (instr(lower(email), lower($query)) > 0 OR instr(lower(coalesce(name, '')), lower($query)) > 0)";
            command.AddParameter("$query", request.Query.Trim());
        }

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
        command.CommandText = sql;
        command.AddParameter("$limit", request.Limit);
        command.AddParameter("$offset", request.Offset);

        var users = new List<UserSummary>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            users.Add(ReadUserSummary(reader));
        }

        return users.AsReadOnly();
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

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddGuidParameter("$userId", userId);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadUserSummary(reader) : null;
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
