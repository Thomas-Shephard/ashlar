using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Ashlar.Sqlite.Identity;

/// <summary>
/// Provides SQLite authentication handshake repository behavior.
/// </summary>
/// <param name="connectionProvider">The connection provider value.</param>
/// <param name="timeProvider">The time provider value.</param>
public sealed class SqliteAuthenticationHandshakeRepository(ISqliteConnectionProvider connectionProvider, TimeProvider? timeProvider = null) : IAuthenticationHandshakeRepository
{
    private readonly ISqliteConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    public async Task CreateAsync(AuthenticationHandshake handshake, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handshake);

        const string sql = """
            INSERT INTO ashlar_mfa_handshakes (id, user_id, tenant_id, token_hash, created_at, expires_at, is_revoked, is_completed, revoked_at, completed_at, required_factors, verified_factors, metadata)
            VALUES ($id, $userId, $tenantId, $tokenHash, $createdAt, $expiresAt, $isRevoked, $isCompleted, $revokedAt, $completedAt, $requiredFactors, $verifiedFactors, $metadata);
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        AddParameters(command, handshake, _timeProvider.GetUtcNow());
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<AuthenticationHandshake?> FindByTokenHashAsync(string tokenHash, bool forUpdate = false, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenHash);
        _ = forUpdate; // SQLite write intent is provided by SqliteTransactionManager BEGIN IMMEDIATE root transactions.

        const string sql = """
            SELECT id, user_id, tenant_id, token_hash, created_at, expires_at, is_revoked, is_completed, revoked_at, completed_at, required_factors, verified_factors, metadata
            FROM ashlar_mfa_handshakes
            WHERE token_hash = $tokenHash;
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddParameter("$tokenHash", tokenHash);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadHandshake(reader) : null;
    }

    public async Task<bool> UpdateAsync(AuthenticationHandshake handshake, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handshake);

        const string sql = """
            UPDATE ashlar_mfa_handshakes
            SET is_revoked = $isRevoked,
                is_completed = $isCompleted,
                revoked_at = $revokedAt,
                completed_at = $completedAt,
                verified_factors = $verifiedFactors,
                metadata = $metadata
            WHERE id = $id
              AND is_completed = 0
              AND is_revoked = 0;
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        AddUpdateParameters(command, handshake, _timeProvider.GetUtcNow());
        var affectedRows = await command.ExecuteNonQueryAsync(cancellationToken);
        return affectedRows == 1;
    }

    private static void AddParameters(SqliteCommand command, AuthenticationHandshake handshake, DateTimeOffset now)
    {
        command.AddGuidParameter("$id", handshake.Id);
        command.AddGuidParameter("$userId", handshake.UserId);
        command.AddNullableGuidParameter("$tenantId", handshake.TenantId);
        command.AddParameter("$tokenHash", handshake.TokenHash);
        command.AddDateTimeOffsetParameter("$createdAt", handshake.CreatedAt);
        command.AddDateTimeOffsetParameter("$expiresAt", handshake.ExpiresAt);
        command.AddParameter("$isRevoked", handshake.IsRevoked ? 1 : 0);
        command.AddParameter("$isCompleted", handshake.IsCompleted ? 1 : 0);
        command.AddNullableDateTimeOffsetParameter("$revokedAt", handshake.IsRevoked ? handshake.RevokedAt ?? now : null);
        command.AddNullableDateTimeOffsetParameter("$completedAt", handshake.IsCompleted ? handshake.CompletedAt ?? now : null);
        command.AddParameter("$requiredFactors", JsonSerializer.Serialize(handshake.RequiredFactors));
        command.AddParameter("$verifiedFactors", JsonSerializer.Serialize(handshake.VerifiedFactors));
        command.AddParameter("$metadata", SerializeMetadata(handshake.Metadata));
    }

    private static void AddUpdateParameters(SqliteCommand command, AuthenticationHandshake handshake, DateTimeOffset now)
    {
        command.AddGuidParameter("$id", handshake.Id);
        command.AddParameter("$isRevoked", handshake.IsRevoked ? 1 : 0);
        command.AddParameter("$isCompleted", handshake.IsCompleted ? 1 : 0);
        command.AddNullableDateTimeOffsetParameter("$revokedAt", handshake.IsRevoked ? handshake.RevokedAt ?? now : null);
        command.AddNullableDateTimeOffsetParameter("$completedAt", handshake.IsCompleted ? handshake.CompletedAt ?? now : null);
        command.AddParameter("$verifiedFactors", JsonSerializer.Serialize(handshake.VerifiedFactors));
        command.AddParameter("$metadata", SerializeMetadata(handshake.Metadata));
    }

    private static AuthenticationHandshake ReadHandshake(SqliteDataReader reader)
    {
        var metadata = reader.GetNullableString("metadata");

        return new AuthenticationHandshake(
            reader.GetGuidFromText("id"),
            reader.GetGuidFromText("user_id"),
            reader.GetString(reader.GetOrdinal("token_hash")),
            reader.GetDateTimeOffsetFromText("created_at"),
            reader.GetDateTimeOffsetFromText("expires_at"),
            reader.GetBooleanFromInteger("is_revoked"),
            reader.GetBooleanFromInteger("is_completed"),
            DeserializeSet(reader.GetString(reader.GetOrdinal("required_factors"))),
            DeserializeSet(reader.GetString(reader.GetOrdinal("verified_factors"))),
            metadata == null ? null : JsonSerializer.Deserialize<Dictionary<string, string>>(metadata),
            reader.GetNullableDateTimeOffsetFromText("revoked_at"),
            reader.GetNullableDateTimeOffsetFromText("completed_at"))
        {
            TenantId = reader.GetNullableGuidFromText("tenant_id")
        };
    }

    private static HashSet<string> DeserializeSet(string value)
    {
        return JsonSerializer.Deserialize<HashSet<string>>(value) ?? [];
    }

    private static string? SerializeMetadata(IDictionary<string, string>? metadata)
    {
        return metadata == null ? null : JsonSerializer.Serialize(metadata);
    }
}
