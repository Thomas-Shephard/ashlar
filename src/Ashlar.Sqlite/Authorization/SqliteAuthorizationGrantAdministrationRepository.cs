using Ashlar.Authorization;
using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Microsoft.Data.Sqlite;

namespace Ashlar.Sqlite.Authorization;

/// <summary>
/// Provides SQLite authorization grant administration query behavior.
/// </summary>
/// <param name="connectionProvider">Connection provider used to query authorization grant records.</param>
public sealed class SqliteAuthorizationGrantAdministrationRepository(ISqliteConnectionProvider connectionProvider)
    : IAuthorizationGrantAdministrationRepository
{
    private const string IdParameter = "$id";
    private const string UserIdParameter = "$userId";
    private const string RoleParameter = "$role";
    private const string PermissionParameter = "$permission";
    private const string ScopeTypeParameter = "$scopeType";
    private const string ScopeIdParameter = "$scopeId";
    private const string StatusParameter = "$status";
    private const string CreatedFromParameter = "$createdFrom";
    private const string CreatedToParameter = "$createdTo";
    private const string ExpiresFromParameter = "$expiresFrom";
    private const string ExpiresToParameter = "$expiresTo";
    private const string RevokedFromParameter = "$revokedFrom";
    private const string RevokedToParameter = "$revokedTo";
    private const string NowParameter = "$now";
    private const string LimitParameter = "$limit";
    private const string OffsetParameter = "$offset";
    private const string TenantIdParameter = "$tenantId";

    private readonly ISqliteConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));

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

        return SqliteQuery.QueryAsync(
            _connectionProvider,
            command => BuildSearchSql(command, request, now),
            reader => ReadSummary(reader, now),
            cancellationToken);
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

        return SqliteQuery.QuerySingleAsync(
            _connectionProvider,
            command => BuildDetailSql(command, request, now),
            reader => ReadDetail(reader, now),
            cancellationToken);
    }

    private static string BuildSearchSql(SqliteCommand command, SearchAuthorizationGrantsRequest request, DateTimeOffset now)
    {
        var sql = SelectSql + " WHERE 1 = 1";
        command.AddTenantFilter(request.Tenant, "tenant_id", TenantIdParameter, ref sql);
        AddOptionalFilters(command, request, now, ref sql);
        command.AddParameter(LimitParameter, request.Limit);
        command.AddParameter(OffsetParameter, request.Offset);

        return sql + """
            
            ORDER BY created_at DESC, id
            LIMIT $limit OFFSET $offset;
            """;
    }

    private static string BuildDetailSql(SqliteCommand command, AuthorizationGrantAdministrationDetailRequest request, DateTimeOffset now)
    {
        var sql = SelectSql + " WHERE id = $id";
        command.AddGuidParameter(IdParameter, request.GrantId);
        command.AddTenantFilter(request.Tenant, "tenant_id", TenantIdParameter, ref sql);
        command.AddDateTimeOffsetParameter(NowParameter, now);
        return sql + ";";
    }

    private static void AddOptionalFilters(SqliteCommand command, SearchAuthorizationGrantsRequest request, DateTimeOffset now, ref string sql)
    {
        command.AddDateTimeOffsetParameter(NowParameter, now);
        AddOptionalGuid(command, request.UserId, "user_id", UserIdParameter, ref sql);
        AddOptionalString(command, request.Role, "role", RoleParameter, ref sql);
        AddOptionalString(command, request.Permission, "permission", PermissionParameter, ref sql);
        AddOptionalString(command, request.ScopeType, "scope_type", ScopeTypeParameter, ref sql);
        AddOptionalString(command, request.ScopeId, "scope_id", ScopeIdParameter, ref sql);
        command.AddDateRange(request.CreatedFrom, request.CreatedTo, "created_at", CreatedFromParameter, CreatedToParameter, ref sql);
        command.AddDateRange(request.ExpiresFrom, request.ExpiresTo, "expires_at", ExpiresFromParameter, ExpiresToParameter, ref sql);
        command.AddDateRange(request.RevokedFrom, request.RevokedTo, "revoked_at", RevokedFromParameter, RevokedToParameter, ref sql);

        if (request.Status != null)
        {
            sql += " AND " + StatusExpression + " = " + StatusParameter;
            command.AddParameter(StatusParameter, (int)request.Status.Value);
        }
    }

    private static void AddOptionalGuid(SqliteCommand command, Guid? value, string column, string parameterName, ref string sql)
    {
        if (value == null)
        {
            return;
        }

        sql += $" AND {column} = {parameterName}";
        command.AddNullableGuidParameter(parameterName, value);
    }

    private static void AddOptionalString(SqliteCommand command, string? value, string column, string parameterName, ref string sql)
    {
        if (value == null)
        {
            return;
        }

        sql += $" AND {column} = {parameterName}";
        command.AddParameter(parameterName, value);
    }

    private const string StatusExpression = """
        CASE
            WHEN revoked_at IS NOT NULL THEN 1
            WHEN expires_at IS NOT NULL AND expires_at <= $now THEN 2
            ELSE 0
        END
        """;

    private const string SelectSql = """
        SELECT id, user_id, tenant_id, scope_type, scope_id, role, permission, created_at, expires_at, revoked_at
        FROM ashlar_authorization_grants
        """;

    private static AuthorizationGrantAdministrationSummary ReadSummary(SqliteDataReader reader, DateTimeOffset now)
    {
        var expiresAt = reader.GetNullableDateTimeOffsetFromText("expires_at");
        var revokedAt = reader.GetNullableDateTimeOffsetFromText("revoked_at");
        return new AuthorizationGrantAdministrationSummary(
            reader.GetGuidFromText("id"),
            reader.GetGuidFromText("user_id"),
            reader.GetNullableGuidFromText("tenant_id"),
            reader.GetNullableString("scope_type"),
            reader.GetNullableString("scope_id"),
            reader.GetNullableString("role"),
            reader.GetNullableString("permission"),
            reader.GetDateTimeOffsetFromText("created_at"),
            expiresAt,
            revokedAt,
            AuthorizationGrantAdministrationService.DeriveStatus(expiresAt, revokedAt, now));
    }

    private static AuthorizationGrantAdministrationDetail ReadDetail(SqliteDataReader reader, DateTimeOffset now)
    {
        var summary = ReadSummary(reader, now);
        return new AuthorizationGrantAdministrationDetail(
            summary.Id,
            summary.UserId,
            summary.TenantId,
            summary.ScopeType,
            summary.ScopeId,
            summary.Role,
            summary.Permission,
            summary.CreatedAt,
            summary.ExpiresAt,
            summary.RevokedAt,
            summary.Status);
    }
}
