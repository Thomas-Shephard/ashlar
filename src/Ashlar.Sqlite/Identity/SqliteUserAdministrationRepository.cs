using Microsoft.Data.Sqlite;

namespace Ashlar.Sqlite.Identity;

internal sealed class SqliteUserAdministrationRepository(ISqliteConnectionProvider connectionProvider) : IUserAdministrationRepository
{
    private readonly ISqliteConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));

    public async Task<IReadOnlyList<UserSummary>> SearchUsersAsync(SearchUsersRequest request, CancellationToken cancellationToken = default)
    {
        SearchUsersRequest.ThrowIfInvalid(request);

        return await SqliteQuery.QueryAsync(_connectionProvider, command =>
        {
            var sql = """
                SELECT id, display_email, name, tenant_id, account_state, email_verified_at, created_at, updated_at
                FROM ashlar_users
                WHERE 1 = 1
                """;

            if (!string.IsNullOrWhiteSpace(request.Query))
            {
                sql += " AND (normalized_email LIKE $normalizedEmailQuery OR instr(lower(coalesce(name, '')), lower($nameQuery)) > 0)";
                var query = request.Query.Trim();
                command.AddParameter("$normalizedEmailQuery", $"%{IdentityNormalization.NormalizeEmail(query)}%");
                command.AddParameter("$nameQuery", query);
            }

            command.AddTenantFilter(request.Tenant, "tenant_id", "$tenantId", ref sql);

            if (request.AccountState.HasValue)
            {
                sql += " AND account_state = $accountState";
                command.AddParameter("$accountState", request.AccountState.Value.ToStorageValue());
            }

            if (request.IsEmailVerified.HasValue)
            {
                sql += request.IsEmailVerified.Value
                    ? " AND email_verified_at IS NOT NULL"
                    : " AND email_verified_at IS NULL";
            }

            sql += " ORDER BY lower(display_email), id LIMIT $limit OFFSET $offset;";
            command.AddParameter("$limit", request.Limit);
            command.AddParameter("$offset", request.Offset);

            return sql;
        }, ReadUserSummary, cancellationToken);
    }

    public async Task<UserSummary?> GetUserSummaryAsync(UserAdministrationDetailRequest request, CancellationToken cancellationToken = default)
    {
        UserAdministrationDetailRequest.ThrowIfInvalid(request);

        return await SqliteQuery.QuerySingleAsync(_connectionProvider, command =>
        {
            var sql = """
            SELECT id, display_email, name, tenant_id, account_state, email_verified_at, created_at, updated_at
            FROM ashlar_users
            WHERE id = $userId
            """;

            command.AddGuidParameter("$userId", request.UserId);
            command.AddTenantFilter(request.Tenant, "tenant_id", "$tenantId", ref sql);
            return sql + ";";
        }, ReadUserSummary, cancellationToken);
    }

    private static UserSummary ReadUserSummary(SqliteDataReader reader)
    {
        var accountState = UserAccountStates.FromStorageValue(reader.GetString(reader.GetOrdinal("account_state")));
        return new UserSummary(
            reader.GetGuidFromText("id"),
            reader.GetString(reader.GetOrdinal("display_email")),
            reader.GetNullableString("name"),
            reader.GetNullableGuidFromText("tenant_id"),
            accountState,
            accountState.CanSignIn(),
            !reader.IsDBNull(reader.GetOrdinal("email_verified_at")),
            reader.GetDateTimeOffsetFromText("created_at"),
            reader.GetNullableDateTimeOffsetFromText("updated_at"));
    }
}
