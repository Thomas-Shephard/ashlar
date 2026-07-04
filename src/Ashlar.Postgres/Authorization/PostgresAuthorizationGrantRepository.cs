using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Dapper;

namespace Ashlar.Postgres.Authorization;

internal sealed class PostgresAuthorizationGrantRepository(IPostgresConnectionProvider connectionProvider, TimeProvider? timeProvider = null)
    : IAuthorizationGrantRepository
{
    private readonly IPostgresConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    public async Task CreateGrantAsync(AuthorizationGrant grant, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(grant);

        const string sql = """
            INSERT INTO ashlar_authorization_grants
                (id, user_id, tenant_id, scope_type, scope_id, role, permission, created_at, expires_at, revoked_at, metadata)
            VALUES
                (@Id, @UserId, @TenantId, @ScopeType, @ScopeId, @Role, @Permission, @CreatedAt, @ExpiresAt, @RevokedAt, CAST(@Metadata AS jsonb))
            """;

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, grant, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            await connectionHandle.Connection.ExecuteAsync(command);
        }
    }

    public async Task<IReadOnlyList<AuthorizationGrant>> ListGrantsAsync(ListAuthorizationGrantsRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrWhiteSpace(request.ScopeType) != string.IsNullOrWhiteSpace(request.ScopeId))
        {
            return [];
        }

        var now = _timeProvider.GetUtcNow();
        const string sql = """
            SELECT id, user_id AS UserId, tenant_id AS TenantId, scope_type AS ScopeType, scope_id AS ScopeId,
                   role, permission, created_at AS CreatedAt, expires_at AS ExpiresAt, revoked_at AS RevokedAt,
                   metadata::text AS Metadata
            FROM ashlar_authorization_grants
            WHERE user_id = @UserId
              AND tenant_id IS NOT DISTINCT FROM @TenantId
              AND (@ScopeFilter = FALSE
                   OR (@ScopeExact = TRUE AND ((@ScopeType IS NULL AND scope_type IS NULL AND @ScopeId IS NULL AND scope_id IS NULL)
                       OR (scope_type = @ScopeType AND scope_id = @ScopeId)))
                   OR (@ScopeExact = FALSE AND (scope_type IS NULL AND scope_id IS NULL OR (scope_type = @ScopeType AND scope_id = @ScopeId))))
              AND (@ActiveOnly = FALSE OR (revoked_at IS NULL AND (expires_at IS NULL OR expires_at > @Now)))
            ORDER BY created_at DESC, id
            """;

        var parameters = new
        {
            request.UserId,
            request.TenantId,
            ScopeFilter = request.ExactMatch || request.ScopeType != null || request.ScopeId != null,
            ScopeExact = request.ExactMatch,
            request.ScopeType,
            request.ScopeId,
            request.ActiveOnly,
            Now = now
        };

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, parameters, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var grants = await connectionHandle.Connection.QueryAsync<AuthorizationGrant>(command);
            return grants.AsList();
        }
    }

    public async Task<AuthorizationGrant?> GetGrantAsync(Guid grantId, Guid? tenantId, CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT id, user_id AS UserId, tenant_id AS TenantId, scope_type AS ScopeType, scope_id AS ScopeId,
                   role, permission, created_at AS CreatedAt, expires_at AS ExpiresAt, revoked_at AS RevokedAt,
                   metadata::text AS Metadata
            FROM ashlar_authorization_grants
            WHERE id = @Id
              AND tenant_id IS NOT DISTINCT FROM @TenantId
            """;

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new { Id = grantId, TenantId = tenantId }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            return await connectionHandle.Connection.QueryFirstOrDefaultAsync<AuthorizationGrant>(command);
        }
    }

    public async Task<bool> RevokeGrantAsync(Guid grantId, Guid? tenantId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default)
    {
        const string sql = """
            UPDATE ashlar_authorization_grants
            SET revoked_at = @RevokedAt
            WHERE id = @Id AND revoked_at IS NULL
              AND tenant_id IS NOT DISTINCT FROM @TenantId
            """;

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new { Id = grantId, TenantId = tenantId, RevokedAt = revokedAt }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            return await connectionHandle.Connection.ExecuteAsync(command) > 0;
        }
    }
}
