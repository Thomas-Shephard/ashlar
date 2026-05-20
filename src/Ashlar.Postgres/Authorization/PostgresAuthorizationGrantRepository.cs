using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Dapper;

namespace Ashlar.Postgres.Authorization;

/// <summary>
/// Provides postgres authorization grant repository behavior.
/// </summary>
/// <param name="connectionProvider">The connection provider value.</param>
/// <param name="timeProvider">The time provider value.</param>
public sealed class PostgresAuthorizationGrantRepository(IPostgresConnectionProvider connectionProvider, TimeProvider? timeProvider = null)
    : IAuthorizationGrantRepository
{
    private readonly IPostgresConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    /// <summary>
    /// Performs the create grant <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="grant">The grant value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
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

    /// <summary>
    /// Performs the list grants <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="request">The request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<IReadOnlyList<AuthorizationGrant>> ListGrantsAsync(ListAuthorizationGrantsRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var now = _timeProvider.GetUtcNow();
        const string sql = """
            SELECT id, user_id AS UserId, tenant_id AS TenantId, scope_type AS ScopeType, scope_id AS ScopeId,
                   role, permission, created_at AS CreatedAt, expires_at AS ExpiresAt, revoked_at AS RevokedAt,
                   metadata::text AS Metadata
            FROM ashlar_authorization_grants
            WHERE user_id = @UserId
              AND (@TenantFilter = FALSE OR ((@TenantId IS NULL AND tenant_id IS NULL) OR tenant_id = @TenantId))
              AND (@ScopeFilter = FALSE OR ((@ScopeType IS NULL AND scope_type IS NULL AND @ScopeId IS NULL AND scope_id IS NULL)
                   OR (scope_type = @ScopeType AND scope_id = @ScopeId)))
              AND (@ActiveOnly = FALSE OR (revoked_at IS NULL AND (expires_at IS NULL OR expires_at > @Now)))
            ORDER BY created_at DESC, id
            """;

        var parameters = new
        {
            request.UserId,
            TenantFilter = request.ExactMatch || request.TenantId.HasValue,
            request.TenantId,
            ScopeFilter = request.ExactMatch || request.ScopeType != null || request.ScopeId != null,
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

    /// <summary>
    /// Performs the get grant <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="grantId">The grant id value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<AuthorizationGrant?> GetGrantAsync(Guid grantId, CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT id, user_id AS UserId, tenant_id AS TenantId, scope_type AS ScopeType, scope_id AS ScopeId,
                   role, permission, created_at AS CreatedAt, expires_at AS ExpiresAt, revoked_at AS RevokedAt,
                   metadata::text AS Metadata
            FROM ashlar_authorization_grants
            WHERE id = @Id
            """;

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new { Id = grantId }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            return await connectionHandle.Connection.QueryFirstOrDefaultAsync<AuthorizationGrant>(command);
        }
    }

    /// <summary>
    /// Performs the revoke grant <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="grantId">The grant id value.</param>
    /// <param name="revokedAt">The revoked at value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<bool> RevokeGrantAsync(Guid grantId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default)
    {
        const string sql = """
            UPDATE ashlar_authorization_grants
            SET revoked_at = @RevokedAt
            WHERE id = @Id AND revoked_at IS NULL
            """;

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new { Id = grantId, RevokedAt = revokedAt }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            return await connectionHandle.Connection.ExecuteAsync(command) > 0;
        }
    }
}






