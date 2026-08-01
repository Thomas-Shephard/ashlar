using Dapper;

namespace Ashlar.Postgres.Identity;

internal sealed class PostgresUserAdministrationRepository(IPostgresConnectionProvider connectionProvider) : IUserAdministrationRepository
{
    private readonly IPostgresConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));

    public async Task<IReadOnlyList<UserSummary>> SearchUsersAsync(SearchUsersRequest request, CancellationToken cancellationToken = default)
    {
        SearchUsersRequest.ThrowIfInvalid(request);

        var sql = """
            SELECT id AS UserId, display_email AS DisplayEmail, name, tenant_id AS TenantId, account_state AS AccountState,
                   (email_verified_at IS NOT NULL) AS IsEmailVerified, created_at AS CreatedAt, updated_at AS UpdatedAt
            FROM ashlar_users
            WHERE 1 = 1
            """;

        var parameters = new DynamicParameters();
        if (!string.IsNullOrWhiteSpace(request.Query))
        {
            sql += " AND (normalized_email LIKE @NormalizedEmailQuery OR name ILIKE @NameQuery)";
            var query = request.Query.Trim();
            parameters.Add("NormalizedEmailQuery", $"%{IdentityNormalization.NormalizeEmail(query)}%");
            parameters.Add("NameQuery", $"%{query}%");
        }

        PostgresAdminQuery.AddTenantFilter(request.Tenant, "tenant_id", "TenantId", ref sql, parameters);

        if (request.AccountState.HasValue)
        {
            sql += " AND account_state = @AccountState";
            parameters.Add("AccountState", request.AccountState.Value.ToStorageValue());
        }

        if (request.IsEmailVerified.HasValue)
        {
            sql += request.IsEmailVerified.Value
                ? " AND email_verified_at IS NOT NULL"
                : " AND email_verified_at IS NULL";
        }

        sql += " ORDER BY lower(display_email), id LIMIT @Limit OFFSET @Offset";
        parameters.Add("Limit", request.Limit);
        parameters.Add("Offset", request.Offset);

        var rows = await PostgresAdminQuery.QueryAsync<UserAdministrationUserRow>(_connectionProvider, sql, parameters, cancellationToken);
        return rows.Select(ToUserSummary).ToList().AsReadOnly();
    }

    public async Task<UserSummary?> GetUserSummaryAsync(UserAdministrationLookupRequest request, CancellationToken cancellationToken = default)
    {
        UserAdministrationLookupRequest.ThrowIfInvalid(request);

        var sql = """
            SELECT id AS UserId, display_email AS DisplayEmail, name, tenant_id AS TenantId, account_state AS AccountState,
                   (email_verified_at IS NOT NULL) AS IsEmailVerified, created_at AS CreatedAt, updated_at AS UpdatedAt
            FROM ashlar_users
            WHERE id = @UserId
            """;
        var parameters = new DynamicParameters();
        parameters.Add("UserId", request.UserId);
        PostgresAdminQuery.AddTenantFilter(request.Tenant, "tenant_id", "TenantId", ref sql, parameters);

        var row = await PostgresAdminQuery.QuerySingleAsync<UserAdministrationUserRow>(_connectionProvider, sql, parameters, cancellationToken);
        return row == null ? null : ToUserSummary(row);
    }

    private static UserSummary ToUserSummary(UserAdministrationUserRow row)
    {
        var accountState = UserAccountStates.FromStorageValue(row.AccountState);
        return new UserSummary(
            row.UserId,
            row.DisplayEmail,
            row.Name,
            row.TenantId,
            accountState,
            accountState.CanSignIn(),
            row.IsEmailVerified,
            PostgresAdminQuery.ToDateTimeOffset(row.CreatedAt),
            PostgresAdminQuery.ToNullableDateTimeOffset(row.UpdatedAt));
    }

    private sealed record UserAdministrationUserRow(
        Guid UserId,
        string DisplayEmail,
        string? Name,
        Guid? TenantId,
        string AccountState,
        bool IsEmailVerified,
        DateTime CreatedAt,
        DateTime? UpdatedAt);
}
