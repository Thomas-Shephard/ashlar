using System.Text.Json;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Microsoft.Data.Sqlite;

namespace Ashlar.Sqlite;

/// <summary>
/// Provides SQLite authentication session repository behavior.
/// </summary>
/// <param name="connectionProvider">The connection provider value.</param>
public sealed class SqliteAuthenticationSessionRepository(ISqliteConnectionProvider connectionProvider) : IAuthenticationSessionRepository
{
    private readonly ISqliteConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));

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
            INSERT INTO ashlar_sessions (
                id, user_id, tenant_id, token_hash, created_at, authenticated_at, primary_provider_type, primary_provider_name,
                additional_verification_at, additional_verification_provider_type, additional_verification_provider_name,
                additional_verification_factor, expires_at, last_seen_at, revoked_at, revocation_reason, ip_address, user_agent, metadata)
            VALUES (
                $id, $userId, $tenantId, $tokenHash, $createdAt, $authenticatedAt, $primaryProviderType, $primaryProviderName,
                $additionalVerificationAt, $additionalVerificationProviderType, $additionalVerificationProviderName,
                $additionalVerificationFactor, $expiresAt, $lastSeenAt, $revokedAt, $revocationReason, $ipAddress, $userAgent, $metadata);
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        AddParameters(command, session);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public Task<AuthenticationSession?> GetSessionByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenHash);
        return GetSingleAsync("WHERE token_hash = $tokenHash", command => command.AddParameter("$tokenHash", tokenHash), cancellationToken);
    }

    public Task<AuthenticationSession?> GetSessionAsync(Guid sessionId, CancellationToken cancellationToken = default)
    {
        return GetSingleAsync("WHERE id = $id", command => command.AddGuidParameter("$id", sessionId), cancellationToken);
    }

    public async Task<bool> UpdateSessionLastSeenAsync(Guid sessionId, DateTimeOffset lastSeenAt, CancellationToken cancellationToken = default)
    {
        const string sql = """
            UPDATE ashlar_sessions
            SET last_seen_at = $lastSeenAt
            WHERE id = $id
              AND revoked_at IS NULL
              AND expires_at > $lastSeenAt
              AND (last_seen_at IS NULL OR last_seen_at < $lastSeenAt);
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddGuidParameter("$id", sessionId);
        command.AddDateTimeOffsetParameter("$lastSeenAt", lastSeenAt);

        return await command.ExecuteNonQueryAsync(cancellationToken) > 0;
    }

    public async Task<AuthenticationSession?> MarkStepUpVerifiedAsync(
        Guid sessionId,
        Guid userId,
        DateTimeOffset verifiedAt,
        AuthenticationProviderKey verifiedProvider,
        string verifiedFactor,
        CancellationToken cancellationToken = default)
    {
        const string sql = """
            UPDATE ashlar_sessions
            SET additional_verification_at = $verifiedAt,
                additional_verification_provider_type = $verifiedProviderType,
                additional_verification_provider_name = $verifiedProviderName,
                additional_verification_factor = $verifiedFactor
            WHERE id = $id
              AND user_id = $userId
              AND revoked_at IS NULL
              AND expires_at > $verifiedAt
            RETURNING id, user_id, tenant_id, token_hash, created_at, authenticated_at, primary_provider_type, primary_provider_name,
                      additional_verification_at, additional_verification_provider_type, additional_verification_provider_name,
                      additional_verification_factor, expires_at, last_seen_at, revoked_at, revocation_reason, ip_address, user_agent, metadata;
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddGuidParameter("$id", sessionId);
        command.AddGuidParameter("$userId", userId);
        command.AddDateTimeOffsetParameter("$verifiedAt", verifiedAt);
        command.AddParameter("$verifiedProviderType", AuthenticationProviderKey.GetTypeValueOrNull(verifiedProvider));
        command.AddParameter("$verifiedProviderName", verifiedProvider.Name);
        command.AddParameter("$verifiedFactor", verifiedFactor);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadSession(reader) : null;
    }

    public Task<bool> RevokeSessionAsync(Guid sessionId, DateTimeOffset revokedAt, string? reason = null, CancellationToken cancellationToken = default)
    {
        return RevokeAsync("WHERE id = $id AND revoked_at IS NULL", command => command.AddGuidParameter("$id", sessionId), revokedAt, reason, cancellationToken);
    }

    public Task<int> RevokeSessionsForUserAsync(Guid userId, DateTimeOffset revokedAt, string? reason = null, CancellationToken cancellationToken = default)
    {
        return RevokeCountAsync("WHERE user_id = $userId AND revoked_at IS NULL", command => command.AddGuidParameter("$userId", userId), revokedAt, reason, cancellationToken);
    }

    public async Task<IReadOnlyList<AuthenticationSession>> ListSessionsForUserAsync(Guid userId, bool activeOnly, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        var sql = $"{SelectSql} " + """
            WHERE user_id = $userId
            """;

        if (activeOnly)
        {
            sql += " AND revoked_at IS NULL AND expires_at > $now";
        }

        sql += " ORDER BY created_at DESC, id LIMIT 100;";

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddGuidParameter("$userId", userId);
        command.AddDateTimeOffsetParameter("$now", now);

        var sessions = new List<AuthenticationSession>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            sessions.Add(ReadSession(reader));
        }

        return sessions.AsReadOnly();
    }

    public Task<bool> RevokeSessionByIdAsync(Guid sessionId, Guid userId, DateTimeOffset revokedAt, string? reason = null, CancellationToken cancellationToken = default)
    {
        return RevokeAsync(
            "WHERE id = $id AND user_id = $userId AND revoked_at IS NULL",
            command =>
            {
                command.AddGuidParameter("$id", sessionId);
                command.AddGuidParameter("$userId", userId);
            },
            revokedAt,
            reason,
            cancellationToken);
    }

    public Task<int> RevokeOtherSessionsForUserAsync(Guid userId, Guid excludedSessionId, DateTimeOffset revokedAt, string? reason = null, CancellationToken cancellationToken = default)
    {
        return RevokeCountAsync(
            "WHERE user_id = $userId AND id <> $excludedSessionId AND revoked_at IS NULL",
            command =>
            {
                command.AddGuidParameter("$userId", userId);
                command.AddGuidParameter("$excludedSessionId", excludedSessionId);
            },
            revokedAt,
            reason,
            cancellationToken);
    }

    private const string SelectSql = """
        SELECT id, user_id, tenant_id, token_hash, created_at, authenticated_at, primary_provider_type, primary_provider_name,
               additional_verification_at, additional_verification_provider_type, additional_verification_provider_name,
               additional_verification_factor, expires_at, last_seen_at, revoked_at, revocation_reason, ip_address, user_agent, metadata
        FROM ashlar_sessions
        """;

    private async Task<AuthenticationSession?> GetSingleAsync(string whereClause, Action<SqliteCommand> addParameters, CancellationToken cancellationToken)
    {
        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        return await ReadSingleAsync(handle.Connection, handle.Transaction, whereClause, addParameters, cancellationToken);
    }

    private async Task<bool> RevokeAsync(string whereClause, Action<SqliteCommand> addParameters, DateTimeOffset revokedAt, string? reason, CancellationToken cancellationToken)
    {
        return await RevokeCountAsync(whereClause, addParameters, revokedAt, reason, cancellationToken) > 0;
    }

    private async Task<int> RevokeCountAsync(string whereClause, Action<SqliteCommand> addParameters, DateTimeOffset revokedAt, string? reason, CancellationToken cancellationToken)
    {
        var sql = $"""
            UPDATE ashlar_sessions
            SET revoked_at = $revokedAt,
                revocation_reason = $reason
            {whereClause};
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        addParameters(command);
        command.AddDateTimeOffsetParameter("$revokedAt", revokedAt);
        command.AddParameter("$reason", reason);

        return await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<AuthenticationSession?> ReadSingleAsync(SqliteConnection connection, SqliteTransaction? transaction, string whereClause, Action<SqliteCommand> addParameters, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"{SelectSql} {whereClause};";
        addParameters(command);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadSession(reader) : null;
    }

    private static void AddParameters(SqliteCommand command, AuthenticationSession session)
    {
        command.AddGuidParameter("$id", session.Id);
        command.AddGuidParameter("$userId", session.UserId);
        command.AddNullableGuidParameter("$tenantId", session.TenantId);
        command.AddParameter("$tokenHash", session.TokenHash);
        command.AddDateTimeOffsetParameter("$createdAt", session.CreatedAt);
        command.AddNullableDateTimeOffsetParameter("$authenticatedAt", session.AuthenticatedAt);
        command.AddParameter("$primaryProviderType", AuthenticationProviderKey.GetTypeValueOrNull(session.PrimaryProvider));
        command.AddParameter("$primaryProviderName", session.PrimaryProvider?.Name);
        command.AddNullableDateTimeOffsetParameter("$additionalVerificationAt", session.AdditionalVerificationAt);
        command.AddParameter("$additionalVerificationProviderType", AuthenticationProviderKey.GetTypeValueOrNull(session.AdditionalVerificationProvider));
        command.AddParameter("$additionalVerificationProviderName", session.AdditionalVerificationProvider?.Name);
        command.AddParameter("$additionalVerificationFactor", session.AdditionalVerificationFactor);
        command.AddDateTimeOffsetParameter("$expiresAt", session.ExpiresAt);
        command.AddNullableDateTimeOffsetParameter("$lastSeenAt", session.LastSeenAt);
        command.AddNullableDateTimeOffsetParameter("$revokedAt", session.RevokedAt);
        command.AddParameter("$revocationReason", session.RevocationReason);
        command.AddParameter("$ipAddress", session.IpAddress);
        command.AddParameter("$userAgent", session.UserAgent);
        command.AddParameter("$metadata", session.Metadata);
    }

    private static AuthenticationSession ReadSession(SqliteDataReader reader)
    {
        var primaryType = reader.GetNullableString("primary_provider_type");
        var primaryName = reader.GetNullableString("primary_provider_name");
        var additionalType = reader.GetNullableString("additional_verification_provider_type");
        var additionalName = reader.GetNullableString("additional_verification_provider_name");

        return new AuthenticationSession
        {
            Id = reader.GetGuidFromText("id"),
            UserId = reader.GetGuidFromText("user_id"),
            TenantId = reader.GetNullableGuidFromText("tenant_id"),
            TokenHash = reader.GetString(reader.GetOrdinal("token_hash")),
            CreatedAt = reader.GetDateTimeOffsetFromText("created_at"),
            AuthenticatedAt = reader.GetNullableDateTimeOffsetFromText("authenticated_at"),
            PrimaryProvider = CreateProvider(primaryType, primaryName),
            AdditionalVerificationAt = reader.GetNullableDateTimeOffsetFromText("additional_verification_at"),
            AdditionalVerificationProvider = CreateProvider(additionalType, additionalName),
            AdditionalVerificationFactor = reader.GetNullableString("additional_verification_factor"),
            ExpiresAt = reader.GetDateTimeOffsetFromText("expires_at"),
            LastSeenAt = reader.GetNullableDateTimeOffsetFromText("last_seen_at"),
            RevokedAt = reader.GetNullableDateTimeOffsetFromText("revoked_at"),
            RevocationReason = reader.GetNullableString("revocation_reason"),
            IpAddress = reader.GetNullableString("ip_address"),
            UserAgent = reader.GetNullableString("user_agent"),
            Metadata = reader.GetNullableString("metadata")
        };
    }

    private static AuthenticationProviderKey? CreateProvider(string? type, string? name)
    {
        if (string.IsNullOrWhiteSpace(type) || string.IsNullOrWhiteSpace(name))
        {
            return null;
        }

        ProviderType providerType = type;
        return new AuthenticationProviderKey(providerType, name);
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
