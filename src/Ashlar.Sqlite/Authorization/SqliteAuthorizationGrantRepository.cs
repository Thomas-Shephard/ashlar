using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Microsoft.Data.Sqlite;

namespace Ashlar.Sqlite.Authorization;

/// <summary>
/// Provides SQLite authorization grant repository behavior.
/// </summary>
/// <param name="connectionProvider">The connection provider value.</param>
/// <param name="timeProvider">The time provider value.</param>
public sealed class SqliteAuthorizationGrantRepository(ISqliteConnectionProvider connectionProvider, TimeProvider? timeProvider = null)
    : IAuthorizationGrantRepository
{
    private const string IdParameter = "$id";
    private const string UserIdParameter = "$userId";
    private const string TenantIdParameter = "$tenantId";
    private const string TenantFilterParameter = "$tenantFilter";
    private const string ScopeTypeParameter = "$scopeType";
    private const string ScopeIdParameter = "$scopeId";
    private const string ScopeFilterParameter = "$scopeFilter";
    private const string ActiveOnlyParameter = "$activeOnly";
    private const string RoleParameter = "$role";
    private const string PermissionParameter = "$permission";
    private const string CreatedAtParameter = "$createdAt";
    private const string ExpiresAtParameter = "$expiresAt";
    private const string RevokedAtParameter = "$revokedAt";
    private const string MetadataParameter = "$metadata";
    private const string NowParameter = "$now";

    private readonly ISqliteConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    public async Task CreateGrantAsync(AuthorizationGrant grant, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(grant);

        const string sql = """
            INSERT INTO ashlar_authorization_grants
                (id, user_id, tenant_id, scope_type, scope_id, role, permission, created_at, expires_at, revoked_at, metadata)
            VALUES
                ($id, $userId, $tenantId, $scopeType, $scopeId, $role, $permission, $createdAt, $expiresAt, $revokedAt, $metadata);
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        AddGrantParameters(command, grant);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<AuthorizationGrant>> ListGrantsAsync(ListAuthorizationGrantsRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        const string sql = SelectSql + """
            
            WHERE user_id = $userId
              AND ($tenantFilter = 0 OR (($tenantId IS NULL AND tenant_id IS NULL) OR tenant_id = $tenantId))
              AND ($scopeFilter = 0 OR (($scopeType IS NULL AND scope_type IS NULL AND $scopeId IS NULL AND scope_id IS NULL)
                   OR (scope_type = $scopeType AND scope_id = $scopeId)))
              AND ($activeOnly = 0 OR (revoked_at IS NULL AND (expires_at IS NULL OR expires_at > $now)))
            ORDER BY created_at DESC, id;
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddGuidParameter(UserIdParameter, request.UserId);
        command.AddNullableGuidParameter(TenantIdParameter, request.TenantId);
        command.AddParameter(TenantFilterParameter, request.ExactMatch || request.TenantId.HasValue ? 1 : 0);
        command.AddParameter(ScopeTypeParameter, request.ScopeType);
        command.AddParameter(ScopeIdParameter, request.ScopeId);
        command.AddParameter(ScopeFilterParameter, request.ExactMatch || request.ScopeType != null || request.ScopeId != null ? 1 : 0);
        command.AddParameter(ActiveOnlyParameter, request.ActiveOnly ? 1 : 0);
        command.AddDateTimeOffsetParameter(NowParameter, _timeProvider.GetUtcNow());

        var grants = new List<AuthorizationGrant>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            grants.Add(ReadGrant(reader));
        }

        return grants.AsReadOnly();
    }

    public async Task<AuthorizationGrant?> GetGrantAsync(Guid grantId, CancellationToken cancellationToken = default)
    {
        const string sql = SelectSql + """
            
            WHERE id = $id;
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddGuidParameter(IdParameter, grantId);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadGrant(reader) : null;
    }

    public async Task<bool> RevokeGrantAsync(Guid grantId, Guid? tenantId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default)
    {
        const string sql = """
            UPDATE ashlar_authorization_grants
            SET revoked_at = $revokedAt
            WHERE id = $id AND revoked_at IS NULL
              AND (($tenantId IS NULL AND tenant_id IS NULL) OR tenant_id = $tenantId);
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddGuidParameter(IdParameter, grantId);
        command.AddNullableGuidParameter(TenantIdParameter, tenantId);
        command.AddDateTimeOffsetParameter(RevokedAtParameter, revokedAt);

        return await command.ExecuteNonQueryAsync(cancellationToken) > 0;
    }

    private const string SelectSql = """
        SELECT id, user_id, tenant_id, scope_type, scope_id, role, permission, created_at, expires_at, revoked_at, metadata
        FROM ashlar_authorization_grants
        """;

    private static void AddGrantParameters(SqliteCommand command, AuthorizationGrant grant)
    {
        command.AddGuidParameter(IdParameter, grant.Id);
        command.AddGuidParameter(UserIdParameter, grant.UserId);
        command.AddNullableGuidParameter(TenantIdParameter, grant.TenantId);
        command.AddParameter(ScopeTypeParameter, grant.ScopeType);
        command.AddParameter(ScopeIdParameter, grant.ScopeId);
        command.AddParameter(RoleParameter, grant.Role);
        command.AddParameter(PermissionParameter, grant.Permission);
        command.AddDateTimeOffsetParameter(CreatedAtParameter, grant.CreatedAt);
        command.AddNullableDateTimeOffsetParameter(ExpiresAtParameter, grant.ExpiresAt);
        command.AddNullableDateTimeOffsetParameter(RevokedAtParameter, grant.RevokedAt);
        command.AddParameter(MetadataParameter, grant.Metadata);
    }

    private static AuthorizationGrant ReadGrant(SqliteDataReader reader)
    {
        return new AuthorizationGrant
        {
            Id = reader.GetGuidFromText("id"),
            UserId = reader.GetGuidFromText("user_id"),
            TenantId = reader.GetNullableGuidFromText("tenant_id"),
            ScopeType = reader.GetNullableString("scope_type"),
            ScopeId = reader.GetNullableString("scope_id"),
            Role = reader.GetNullableString("role"),
            Permission = reader.GetNullableString("permission"),
            CreatedAt = reader.GetDateTimeOffsetFromText("created_at"),
            ExpiresAt = reader.GetNullableDateTimeOffsetFromText("expires_at"),
            RevokedAt = reader.GetNullableDateTimeOffsetFromText("revoked_at"),
            Metadata = reader.GetNullableString("metadata")
        };
    }
}
