using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Dapper;
using System.Text.Json;

namespace Ashlar.Postgres;

public sealed class PostgresAuthenticationSessionRepository(IPostgresConnectionProvider connectionProvider) : IAuthenticationSessionRepository
{
    private readonly IPostgresConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));

    public async Task CreateSessionAsync(AuthenticationSession session, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        if (session.Id == Guid.Empty)
        {
            throw new ArgumentException("Session ID cannot be empty.", nameof(session));
        }

        if (session.UserId == Guid.Empty)
        {
            throw new ArgumentException("User ID cannot be empty.", nameof(session));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(session.TokenHash);
        ValidateMetadata(session.Metadata);

        const string sql = """
            INSERT INTO ashlar_sessions (id, user_id, token_hash, created_at, expires_at, last_seen_at, revoked_at, revocation_reason, ip_address, user_agent, metadata)
            VALUES (@Id, @UserId, @TokenHash, @CreatedAt, @ExpiresAt, @LastSeenAt, @RevokedAt, @RevocationReason, @IpAddress, @UserAgent, @Metadata::jsonb)
            """;

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, session, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            await connectionHandle.Connection.ExecuteAsync(command);
        }
    }

    public async Task<AuthenticationSession?> GetSessionByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenHash);

        const string sql = """
            SELECT id AS Id, user_id AS UserId, token_hash AS TokenHash, created_at AS CreatedAt, expires_at AS ExpiresAt,
                   last_seen_at AS LastSeenAt, revoked_at AS RevokedAt, revocation_reason AS RevocationReason,
                   ip_address AS IpAddress, user_agent AS UserAgent, metadata AS Metadata
            FROM ashlar_sessions
            WHERE token_hash = @TokenHash
            """;

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new { TokenHash = tokenHash }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            return await connectionHandle.Connection.QueryFirstOrDefaultAsync<AuthenticationSession>(command);
        }
    }

    public async Task<AuthenticationSession?> GetSessionAsync(Guid sessionId, CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT id AS Id, user_id AS UserId, token_hash AS TokenHash, created_at AS CreatedAt, expires_at AS ExpiresAt,
                   last_seen_at AS LastSeenAt, revoked_at AS RevokedAt, revocation_reason AS RevocationReason,
                   ip_address AS IpAddress, user_agent AS UserAgent, metadata AS Metadata
            FROM ashlar_sessions
            WHERE id = @Id
            """;

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new { Id = sessionId }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            return await connectionHandle.Connection.QueryFirstOrDefaultAsync<AuthenticationSession>(command);
        }
    }

    public async Task<bool> UpdateSessionLastSeenAsync(Guid sessionId, DateTimeOffset lastSeenAt, CancellationToken cancellationToken = default)
    {
        const string sql = """
            UPDATE ashlar_sessions
            SET last_seen_at = @LastSeenAt
            WHERE id = @Id AND (last_seen_at IS NULL OR last_seen_at < @LastSeenAt)
            """;

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new { Id = sessionId, LastSeenAt = lastSeenAt }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var rowsAffected = await connectionHandle.Connection.ExecuteAsync(command);
            return rowsAffected > 0;
        }
    }

    public async Task<bool> RevokeSessionAsync(Guid sessionId, DateTimeOffset revokedAt, string? reason = null, CancellationToken cancellationToken = default)
    {
        const string sql = """
            UPDATE ashlar_sessions
            SET revoked_at = @RevokedAt, revocation_reason = @Reason
            WHERE id = @Id AND revoked_at IS NULL
            """;

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new { Id = sessionId, RevokedAt = revokedAt, Reason = reason }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var rowsAffected = await connectionHandle.Connection.ExecuteAsync(command);
            return rowsAffected > 0;
        }
    }

    public async Task<int> RevokeSessionsForUserAsync(Guid userId, DateTimeOffset revokedAt, string? reason = null, CancellationToken cancellationToken = default)
    {
        const string sql = """
            UPDATE ashlar_sessions
            SET revoked_at = @RevokedAt, revocation_reason = @Reason
            WHERE user_id = @UserId AND revoked_at IS NULL
            """;

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new { UserId = userId, RevokedAt = revokedAt, Reason = reason }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            return await connectionHandle.Connection.ExecuteAsync(command);
        }
    }

    public async Task<IReadOnlyList<AuthenticationSession>> ListSessionsForUserAsync(Guid userId, bool activeOnly, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        var sql = """
            SELECT id AS Id, user_id AS UserId, token_hash AS TokenHash, created_at AS CreatedAt, expires_at AS ExpiresAt,
                   last_seen_at AS LastSeenAt, revoked_at AS RevokedAt, revocation_reason AS RevocationReason,
                   ip_address AS IpAddress, user_agent AS UserAgent, metadata AS Metadata
            FROM ashlar_sessions
            WHERE user_id = @UserId
            """;

        if (activeOnly)
        {
            sql += " AND revoked_at IS NULL AND expires_at > @Now";
        }

        sql += " ORDER BY created_at DESC LIMIT 100";

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new { UserId = userId, Now = now }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var result = await connectionHandle.Connection.QueryAsync<AuthenticationSession>(command);
            return result.ToList().AsReadOnly();
        }
    }

    public async Task<bool> RevokeSessionByIdAsync(Guid sessionId, Guid userId, DateTimeOffset revokedAt, string? reason = null, CancellationToken cancellationToken = default)
    {
        const string sql = """
            UPDATE ashlar_sessions
            SET revoked_at = @RevokedAt, revocation_reason = @Reason
            WHERE id = @Id AND user_id = @UserId AND revoked_at IS NULL
            """;

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new { Id = sessionId, UserId = userId, RevokedAt = revokedAt, Reason = reason }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var rowsAffected = await connectionHandle.Connection.ExecuteAsync(command);
            return rowsAffected > 0;
        }
    }

    public async Task<int> RevokeOtherSessionsForUserAsync(Guid userId, Guid excludedSessionId, DateTimeOffset revokedAt, string? reason = null, CancellationToken cancellationToken = default)
    {
        const string sql = """
            UPDATE ashlar_sessions
            SET revoked_at = @RevokedAt, revocation_reason = @Reason
            WHERE user_id = @UserId AND id <> @ExcludedSessionId AND revoked_at IS NULL
            """;

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new { UserId = userId, ExcludedSessionId = excludedSessionId, RevokedAt = revokedAt, Reason = reason }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            return await connectionHandle.Connection.ExecuteAsync(command);
        }
    }

    private static void ValidateMetadata(string? metadata)
    {
        if (metadata == null)
        {
            return;
        }

        try
        {
            using var _ = JsonDocument.Parse(metadata);
        }
        catch (JsonException exception)
        {
            throw new ArgumentException("Session metadata must be a valid JSON document.", nameof(metadata), exception);
        }
    }
}
