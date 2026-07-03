using Dapper;
using System.Text.Json;

namespace Ashlar.Postgres.Identity;

/// <summary>
/// Provides postgres authentication handshake repository behavior.
/// </summary>
/// <param name="connectionProvider">The connection provider value.</param>
/// <param name="timeProvider">The time provider value.</param>
public sealed class PostgresAuthenticationHandshakeRepository(IPostgresConnectionProvider connectionProvider, TimeProvider? timeProvider = null) : IAuthenticationHandshakeRepository
{
    private readonly IPostgresConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    /// <summary>
    /// Performs the create <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="handshake">The handshake value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task CreateAsync(AuthenticationHandshake handshake, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handshake);

        const string sql = """
            INSERT INTO ashlar_mfa_handshakes (id, user_id, tenant_id, token_hash, created_at, expires_at, is_revoked, is_completed, revoked_at, completed_at, required_factors, verified_factors, metadata)
            VALUES (@Id, @UserId, @TenantId, @TokenHash, @CreatedAt, @ExpiresAt, @IsRevoked, @IsCompleted, @RevokedAt, @CompletedAt, @RequiredFactors::jsonb, @VerifiedFactors::jsonb, @Metadata::jsonb)
            """;

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new
            {
                handshake.Id,
                handshake.UserId,
                handshake.TenantId,
                handshake.TokenHash,
                handshake.CreatedAt,
                handshake.ExpiresAt,
                handshake.IsRevoked,
                handshake.IsCompleted,
                handshake.RevokedAt,
                handshake.CompletedAt,
                RequiredFactors = JsonSerializer.Serialize(handshake.RequiredFactors),
                VerifiedFactors = JsonSerializer.Serialize(handshake.VerifiedFactors),
                Metadata = SerializeMetadata(handshake.Metadata)
            }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            await connectionHandle.Connection.ExecuteAsync(command);
        }
    }

    /// <summary>
    /// Performs the find by token hash <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="tokenHash">The token hash value.</param>
    /// <param name="forUpdate">The for update value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<AuthenticationHandshake?> FindByTokenHashAsync(string tokenHash, bool forUpdate = false, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenHash);

        var sql = """
            SELECT id AS Id, user_id AS UserId, tenant_id AS TenantId, token_hash AS TokenHash, created_at AS CreatedAt, expires_at AS ExpiresAt,
                   is_revoked AS IsRevoked, is_completed AS IsCompleted, revoked_at AS RevokedAt, completed_at AS CompletedAt, required_factors AS RequiredFactorsRaw,
                   verified_factors AS VerifiedFactorsRaw, metadata AS MetadataRaw
            FROM ashlar_mfa_handshakes
            WHERE token_hash = @TokenHash
            """;
        if (forUpdate)
        {
            sql += " FOR UPDATE";
        }

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        AuthenticationHandshake? handshake;
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new { TokenHash = tokenHash }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            await using var reader = await connectionHandle.Connection.ExecuteReaderAsync(command);
            if (!await reader.ReadAsync(cancellationToken))
            {
                return null;
            }

            var metadataOrdinal = reader.GetOrdinal("MetadataRaw");
            var metadataRaw = await reader.IsDBNullAsync(metadataOrdinal, cancellationToken) ? null : reader.GetString(metadataOrdinal);

            handshake = new AuthenticationHandshake(
                reader.GetGuid(reader.GetOrdinal("Id")),
                reader.GetGuid(reader.GetOrdinal("UserId")),
                reader.GetString(reader.GetOrdinal("TokenHash")),
                await reader.GetFieldValueAsync<DateTimeOffset>(reader.GetOrdinal("CreatedAt"), cancellationToken),
                await reader.GetFieldValueAsync<DateTimeOffset>(reader.GetOrdinal("ExpiresAt"), cancellationToken),
                reader.GetBoolean(reader.GetOrdinal("IsRevoked")),
                reader.GetBoolean(reader.GetOrdinal("IsCompleted")),
                JsonSerializer.Deserialize<HashSet<string>>(reader.GetString(reader.GetOrdinal("RequiredFactorsRaw"))) ?? [],
                JsonSerializer.Deserialize<HashSet<string>>(reader.GetString(reader.GetOrdinal("VerifiedFactorsRaw"))) ?? [],
                metadataRaw == null ? null : JsonSerializer.Deserialize<Dictionary<string, string>>(metadataRaw),
                await GetNullableDateTimeOffsetAsync(reader, "RevokedAt", cancellationToken),
                await GetNullableDateTimeOffsetAsync(reader, "CompletedAt", cancellationToken)
            )
            {
                TenantId = await GetNullableGuidAsync(reader, "TenantId", cancellationToken)
            };
        }

        return handshake;
    }

    /// <summary>
    /// Performs the update <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="handshake">The handshake value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns><see langword="true" /> when the handshake was updated; otherwise, <see langword="false" />.</returns>
    public async Task<bool> UpdateAsync(AuthenticationHandshake handshake, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handshake);

        const string sql = """
            UPDATE ashlar_mfa_handshakes
            SET is_revoked = @IsRevoked,
                is_completed = @IsCompleted,
                revoked_at = @RevokedAt,
                completed_at = @CompletedAt,
                verified_factors = @VerifiedFactors::jsonb,
                metadata = @Metadata::jsonb
            WHERE id = @Id
              AND is_completed = false
              AND is_revoked = false
            """;

        var now = _timeProvider.GetUtcNow();
        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new
            {
                handshake.Id,
                handshake.IsRevoked,
                handshake.IsCompleted,
                RevokedAt = handshake.IsRevoked ? handshake.RevokedAt ?? now : (DateTimeOffset?)null,
                CompletedAt = handshake.IsCompleted ? handshake.CompletedAt ?? now : (DateTimeOffset?)null,
                VerifiedFactors = JsonSerializer.Serialize(handshake.VerifiedFactors),
                Metadata = SerializeMetadata(handshake.Metadata)
            }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var affectedRows = await connectionHandle.Connection.ExecuteAsync(command);
            return affectedRows == 1;
        }
    }

    private static string? SerializeMetadata(IDictionary<string, string>? metadata)
    {
        return metadata == null ? null : JsonSerializer.Serialize(metadata);
    }

    private static async Task<DateTimeOffset?> GetNullableDateTimeOffsetAsync(
        System.Data.Common.DbDataReader reader,
        string columnName,
        CancellationToken cancellationToken)
    {
        var ordinal = reader.GetOrdinal(columnName);
        return await reader.IsDBNullAsync(ordinal, cancellationToken)
            ? null
            : await reader.GetFieldValueAsync<DateTimeOffset>(ordinal, cancellationToken);
    }

    private static async Task<Guid?> GetNullableGuidAsync(
        System.Data.Common.DbDataReader reader,
        string columnName,
        CancellationToken cancellationToken)
    {
        var ordinal = reader.GetOrdinal(columnName);
        return await reader.IsDBNullAsync(ordinal, cancellationToken)
            ? null
            : reader.GetGuid(ordinal);
    }
}
