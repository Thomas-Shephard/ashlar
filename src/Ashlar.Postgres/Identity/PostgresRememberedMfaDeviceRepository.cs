using Dapper;
using Ashlar.Identity.Models.Tenants;

namespace Ashlar.Postgres.Identity;

/// <summary>
/// Provides PostgreSQL remembered MFA device repository behavior.
/// </summary>
/// <param name="connectionProvider">The connection provider.</param>
public sealed class PostgresRememberedMfaDeviceRepository(IPostgresConnectionProvider connectionProvider) : IRememberedMfaDeviceRepository
{
    private const string TenantFilterSql = " AND (@TenantFilter = FALSE OR tenant_id IS NOT DISTINCT FROM @TenantId)";
    private readonly IPostgresConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));

    public async Task CreateAsync(RememberedMfaDevice device, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(device);
        Validate(device);

        const string sql = """
            INSERT INTO ashlar_remembered_mfa_devices (
                id, user_id, tenant_id, token_selector, token_hash, display_name, created_at,
                last_used_at, expires_at, revoked_at, revocation_reason)
            VALUES (
                @Id, @UserId, @TenantId, @TokenSelector, @TokenHash, @DisplayName, @CreatedAt,
                @LastUsedAt, @ExpiresAt, @RevokedAt, @RevocationReason)
            """;

        var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (handle)
        {
            await handle.Connection.ExecuteAsync(new CommandDefinition(sql, device, handle.Transaction, cancellationToken: cancellationToken));
        }
    }

    public async Task<RememberedMfaDevice?> GetByTokenSelectorAsync(string tokenSelector, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenSelector);
        const string sql = SelectSql + " WHERE token_selector = @TokenSelector";
        var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (handle)
        {
            return await handle.Connection.QueryFirstOrDefaultAsync<RememberedMfaDevice>(new CommandDefinition(sql, new { TokenSelector = tokenSelector }, handle.Transaction, cancellationToken: cancellationToken));
        }
    }

    public async Task<RememberedMfaDevice?> GetAsync(Guid deviceId, CancellationToken cancellationToken = default)
    {
        const string sql = SelectSql + " WHERE id = @Id";
        var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (handle)
        {
            return await handle.Connection.QueryFirstOrDefaultAsync<RememberedMfaDevice>(new CommandDefinition(sql, new { Id = deviceId }, handle.Transaction, cancellationToken: cancellationToken));
        }
    }

    public async Task<bool> UpdateLastUsedAsync(Guid deviceId, DateTimeOffset lastUsedAt, CancellationToken cancellationToken = default)
    {
        const string sql = """
            UPDATE ashlar_remembered_mfa_devices
            SET last_used_at = CASE
                WHEN last_used_at IS NULL OR last_used_at < @LastUsedAt THEN @LastUsedAt
                ELSE last_used_at
            END
            WHERE id = @Id
              AND revoked_at IS NULL
              AND expires_at > @LastUsedAt
            """;
        var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (handle)
        {
            return await handle.Connection.ExecuteAsync(new CommandDefinition(sql, new { Id = deviceId, LastUsedAt = lastUsedAt }, handle.Transaction, cancellationToken: cancellationToken)) > 0;
        }
    }

    public async Task<IReadOnlyList<RememberedMfaDevice>> ListForUserAsync(Guid userId, TenantContext? tenant, bool activeOnly, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        var sql = SelectSql + " WHERE user_id = @UserId" + TenantFilterSql;
        if (activeOnly)
        {
            sql += " AND revoked_at IS NULL AND expires_at > @Now";
        }

        sql += " ORDER BY created_at DESC, id LIMIT 100";
        var parameters = CreateTenantParameters(tenant);
        parameters.Add("UserId", userId);
        parameters.Add("Now", now);

        var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (handle)
        {
            var rows = await handle.Connection.QueryAsync<RememberedMfaDevice>(new CommandDefinition(sql, parameters, handle.Transaction, cancellationToken: cancellationToken));
            return rows.ToList().AsReadOnly();
        }
    }

    public async Task<int> CountForUserAsync(Guid userId, TenantContext? tenant, bool activeOnly, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        var sql = "SELECT COUNT(*) FROM ashlar_remembered_mfa_devices WHERE user_id = @UserId" + TenantFilterSql;
        if (activeOnly)
        {
            sql += " AND revoked_at IS NULL AND expires_at > @Now";
        }

        var parameters = CreateTenantParameters(tenant);
        parameters.Add("UserId", userId);
        parameters.Add("Now", now);

        var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (handle)
        {
            return await handle.Connection.ExecuteScalarAsync<int>(new CommandDefinition(sql, parameters, handle.Transaction, cancellationToken: cancellationToken));
        }
    }

    public async Task<bool> RevokeAsync(Guid deviceId, Guid userId, DateTimeOffset revokedAt, string? reason = null, TenantContext? tenant = null, CancellationToken cancellationToken = default)
    {
        const string sql = """
            UPDATE ashlar_remembered_mfa_devices
            SET revoked_at = @RevokedAt, revocation_reason = @Reason
            WHERE id = @Id AND user_id = @UserId AND revoked_at IS NULL
            """;
        var parameters = CreateTenantParameters(tenant);
        parameters.Add("Id", deviceId);
        parameters.Add("UserId", userId);
        parameters.Add("RevokedAt", revokedAt);
        parameters.Add("Reason", reason);

        var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (handle)
        {
            return await handle.Connection.ExecuteAsync(new CommandDefinition(sql + TenantFilterSql, parameters, handle.Transaction, cancellationToken: cancellationToken)) > 0;
        }
    }

    public async Task<int> RevokeAllForUserAsync(Guid userId, DateTimeOffset revokedAt, string? reason = null, TenantContext? tenant = null, CancellationToken cancellationToken = default)
    {
        const string sql = """
            UPDATE ashlar_remembered_mfa_devices
            SET revoked_at = @RevokedAt, revocation_reason = @Reason
            WHERE user_id = @UserId AND revoked_at IS NULL
            """;
        var parameters = CreateTenantParameters(tenant);
        parameters.Add("UserId", userId);
        parameters.Add("RevokedAt", revokedAt);
        parameters.Add("Reason", reason);

        var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (handle)
        {
            return await handle.Connection.ExecuteAsync(new CommandDefinition(sql + TenantFilterSql, parameters, handle.Transaction, cancellationToken: cancellationToken));
        }
    }

    private const string SelectSql = """
        SELECT id AS Id, user_id AS UserId, tenant_id AS TenantId, token_selector AS TokenSelector,
               token_hash AS TokenHash, display_name AS DisplayName, created_at AS CreatedAt,
               last_used_at AS LastUsedAt, expires_at AS ExpiresAt, revoked_at AS RevokedAt,
               revocation_reason AS RevocationReason
        FROM ashlar_remembered_mfa_devices
        """;

    private static DynamicParameters CreateTenantParameters(TenantContext? tenant)
    {
        var parameters = new DynamicParameters();
        parameters.Add("TenantFilter", tenant != null);
        parameters.Add("TenantId", tenant?.TenantId);
        return parameters;
    }

    private static void Validate(RememberedMfaDevice device)
    {
        if (device.Id == Guid.Empty) throw new ArgumentException("Device ID cannot be empty.", nameof(device));
        if (device.UserId == Guid.Empty) throw new ArgumentException("User ID cannot be empty.", nameof(device));
        ArgumentException.ThrowIfNullOrWhiteSpace(device.TokenSelector);
        ArgumentException.ThrowIfNullOrWhiteSpace(device.TokenHash);
    }
}
