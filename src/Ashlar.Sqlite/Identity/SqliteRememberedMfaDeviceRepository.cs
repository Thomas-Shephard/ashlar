using System.Globalization;
using Ashlar.Identity.Models.Tenants;
using Microsoft.Data.Sqlite;

namespace Ashlar.Sqlite.Identity;

internal sealed class SqliteRememberedMfaDeviceRepository(ISqliteConnectionProvider connectionProvider) : IRememberedMfaDeviceRepository
{
    private const string TenantFilterSql = " AND ($tenantFilter = 0 OR (($tenantId IS NULL AND tenant_id IS NULL) OR tenant_id = $tenantId))";
    private const string UserIdParameter = "$userId";
    private readonly ISqliteConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));

    public async Task CreateAsync(RememberedMfaDevice device, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(device);
        Validate(device);

        const string sql = """
            INSERT INTO ashlar_remembered_mfa_devices (
                id, user_id, tenant_id, token_selector, token_hash, display_name, created_at,
                last_used_at, expires_at, revoked_at, revocation_reason)
            VALUES (
                $id, $userId, $tenantId, $tokenSelector, $tokenHash, $displayName, $createdAt,
                $lastUsedAt, $expiresAt, $revokedAt, $revocationReason);
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        AddDeviceParameters(command, device);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<RememberedMfaDevice?> GetByTokenSelectorAsync(string tokenSelector, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenSelector);
        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = SelectSql + " WHERE token_selector = $tokenSelector;";
        command.AddParameter("$tokenSelector", tokenSelector);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadDevice(reader) : null;
    }

    public async Task<RememberedMfaDevice?> GetAsync(Guid deviceId, CancellationToken cancellationToken = default)
    {
        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = SelectSql + " WHERE id = $id;";
        command.AddGuidParameter("$id", deviceId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadDevice(reader) : null;
    }

    public async Task<bool> UpdateLastUsedAsync(Guid deviceId, DateTimeOffset lastUsedAt, CancellationToken cancellationToken = default)
    {
        const string sql = """
            UPDATE ashlar_remembered_mfa_devices
            SET last_used_at = CASE
                WHEN last_used_at IS NULL OR last_used_at < $lastUsedAt THEN $lastUsedAt
                ELSE last_used_at
            END
            WHERE id = $id
              AND revoked_at IS NULL
              AND expires_at > $lastUsedAt;
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddGuidParameter("$id", deviceId);
        command.AddDateTimeOffsetParameter("$lastUsedAt", lastUsedAt);
        return await command.ExecuteNonQueryAsync(cancellationToken) > 0;
    }

    public async Task<IReadOnlyList<RememberedMfaDevice>> ListForUserAsync(Guid userId, TenantContext? tenant, bool activeOnly, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        var sql = SelectSql + " WHERE user_id = $userId" + TenantFilterSql;
        if (activeOnly)
        {
            sql += " AND revoked_at IS NULL AND expires_at > $now";
        }

        sql += " ORDER BY created_at DESC, id LIMIT 100;";
        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddGuidParameter(UserIdParameter, userId);
        command.AddDateTimeOffsetParameter("$now", now);
        AddTenantFilter(command, tenant);

        var devices = new List<RememberedMfaDevice>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            devices.Add(ReadDevice(reader));
        }

        return devices.AsReadOnly();
    }

    public async Task<int> CountForUserAsync(Guid userId, TenantContext? tenant, bool activeOnly, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        var sql = "SELECT COUNT(*) FROM ashlar_remembered_mfa_devices WHERE user_id = $userId" + TenantFilterSql;
        if (activeOnly)
        {
            sql += " AND revoked_at IS NULL AND expires_at > $now";
        }

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql + ";";
        command.AddGuidParameter(UserIdParameter, userId);
        command.AddDateTimeOffsetParameter("$now", now);
        AddTenantFilter(command, tenant);
        return Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture);
    }

    public async Task<bool> RevokeAsync(Guid deviceId, Guid userId, DateTimeOffset revokedAt, string? reason = null, TenantContext? tenant = null, CancellationToken cancellationToken = default)
    {
        const string sql = """
            UPDATE ashlar_remembered_mfa_devices
            SET revoked_at = $revokedAt, revocation_reason = $reason
            WHERE id = $id AND user_id = $userId AND revoked_at IS NULL
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql + TenantFilterSql + ";";
        command.AddGuidParameter("$id", deviceId);
        command.AddGuidParameter(UserIdParameter, userId);
        AddTenantFilter(command, tenant);
        AddRevocationParameters(command, revokedAt, reason);
        return await command.ExecuteNonQueryAsync(cancellationToken) > 0;
    }

    public async Task<int> RevokeAllForUserAsync(Guid userId, DateTimeOffset revokedAt, string? reason = null, TenantContext? tenant = null, CancellationToken cancellationToken = default)
    {
        const string sql = """
            UPDATE ashlar_remembered_mfa_devices
            SET revoked_at = $revokedAt, revocation_reason = $reason
            WHERE user_id = $userId AND revoked_at IS NULL
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql + TenantFilterSql + ";";
        command.AddGuidParameter(UserIdParameter, userId);
        AddTenantFilter(command, tenant);
        AddRevocationParameters(command, revokedAt, reason);
        return await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private const string SelectSql = """
        SELECT id, user_id, tenant_id, token_selector, token_hash, display_name, created_at,
               last_used_at, expires_at, revoked_at, revocation_reason
        FROM ashlar_remembered_mfa_devices
        """;

    private static void AddDeviceParameters(SqliteCommand command, RememberedMfaDevice device)
    {
        command.AddGuidParameter("$id", device.Id);
        command.AddGuidParameter(UserIdParameter, device.UserId);
        command.AddNullableGuidParameter("$tenantId", device.TenantId);
        command.AddParameter("$tokenSelector", device.TokenSelector);
        command.AddParameter("$tokenHash", device.TokenHash);
        command.AddParameter("$displayName", device.DisplayName);
        command.AddDateTimeOffsetParameter("$createdAt", device.CreatedAt);
        command.AddNullableDateTimeOffsetParameter("$lastUsedAt", device.LastUsedAt);
        command.AddDateTimeOffsetParameter("$expiresAt", device.ExpiresAt);
        command.AddNullableDateTimeOffsetParameter("$revokedAt", device.RevokedAt);
        command.AddParameter("$revocationReason", device.RevocationReason);
    }

    private static void AddTenantFilter(SqliteCommand command, TenantContext? tenant)
    {
        command.AddParameter("$tenantFilter", tenant == null ? 0 : 1);
        command.AddNullableGuidParameter("$tenantId", tenant?.TenantId);
    }

    private static void AddRevocationParameters(SqliteCommand command, DateTimeOffset revokedAt, string? reason)
    {
        command.AddDateTimeOffsetParameter("$revokedAt", revokedAt);
        command.AddParameter("$reason", reason);
    }

    private static RememberedMfaDevice ReadDevice(SqliteDataReader reader)
    {
        return new RememberedMfaDevice
        {
            Id = reader.GetGuidFromText("id"),
            UserId = reader.GetGuidFromText("user_id"),
            TenantId = reader.GetNullableGuidFromText("tenant_id"),
            TokenSelector = reader.GetString(reader.GetOrdinal("token_selector")),
            TokenHash = reader.GetString(reader.GetOrdinal("token_hash")),
            DisplayName = reader.GetNullableString("display_name"),
            CreatedAt = reader.GetDateTimeOffsetFromText("created_at"),
            LastUsedAt = reader.GetNullableDateTimeOffsetFromText("last_used_at"),
            ExpiresAt = reader.GetDateTimeOffsetFromText("expires_at"),
            RevokedAt = reader.GetNullableDateTimeOffsetFromText("revoked_at"),
            RevocationReason = reader.GetNullableString("revocation_reason")
        };
    }

    private static void Validate(RememberedMfaDevice device)
    {
        if (device.Id == Guid.Empty) throw new ArgumentException("Device ID cannot be empty.", nameof(device));
        if (device.UserId == Guid.Empty) throw new ArgumentException("User ID cannot be empty.", nameof(device));
        ArgumentException.ThrowIfNullOrWhiteSpace(device.TokenSelector);
        ArgumentException.ThrowIfNullOrWhiteSpace(device.TokenHash);
    }
}
