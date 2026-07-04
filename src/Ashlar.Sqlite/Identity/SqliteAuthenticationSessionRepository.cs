using System.Text.Json;
using Ashlar.Identity.Models.Tenants;
using Microsoft.Data.Sqlite;

namespace Ashlar.Sqlite.Identity;

internal sealed class SqliteAuthenticationSessionRepository(ISqliteConnectionProvider connectionProvider) : IAuthenticationSessionRepository
{
    private const string IdParameter = "$id";
    private const string UserIdParameter = "$userId";
    private const string TokenHashParameter = "$tokenHash";
    private const string TenantIdParameter = "$tenantId";
    private const string LastSeenAtParameter = "$lastSeenAt";
    private const string VerifiedAtParameter = "$verifiedAt";
    private const string VerifiedProviderTypeParameter = "$verifiedProviderType";
    private const string VerifiedProviderNameParameter = "$verifiedProviderName";
    private const string VerifiedFactorParameter = "$verifiedFactor";
    private const string ExcludedSessionIdParameter = "$excludedSessionId";
    private const string NowParameter = "$now";
    private const string CreatedAtParameter = "$createdAt";
    private const string AuthenticatedAtParameter = "$authenticatedAt";
    private const string PrimaryProviderTypeParameter = "$primaryProviderType";
    private const string PrimaryProviderNameParameter = "$primaryProviderName";
    private const string AdditionalVerificationAtParameter = "$additionalVerificationAt";
    private const string AdditionalVerificationProviderTypeParameter = "$additionalVerificationProviderType";
    private const string AdditionalVerificationProviderNameParameter = "$additionalVerificationProviderName";
    private const string AdditionalVerificationFactorParameter = "$additionalVerificationFactor";
    private const string ExpiresAtParameter = "$expiresAt";
    private const string RevokedAtParameter = "$revokedAt";
    private const string RevocationReasonParameter = "$revocationReason";
    private const string IpAddressParameter = "$ipAddress";
    private const string UserAgentParameter = "$userAgent";
    private const string MetadataParameter = "$metadata";
    private const string ReasonParameter = "$reason";
    private const string TenantFilterParameter = "$tenantFilter";
    private const string TenantRevocationFilterSql = """
              AND ($tenantFilter = 0 OR (($tenantId IS NULL AND tenant_id IS NULL) OR tenant_id = $tenantId))
            """;

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

    public async Task<AuthenticationSession?> GetSessionByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenHash);

        const string sql = SelectSql + """
            
            WHERE token_hash = $tokenHash;
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddParameter(TokenHashParameter, tokenHash);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadSession(reader) : null;
    }

    public async Task<AuthenticationSession?> GetSessionAsync(Guid sessionId, CancellationToken cancellationToken = default)
    {
        const string sql = SelectSql + """
            
            WHERE id = $id;
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddGuidParameter(IdParameter, sessionId);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadSession(reader) : null;
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
        command.AddGuidParameter(IdParameter, sessionId);
        command.AddDateTimeOffsetParameter(LastSeenAtParameter, lastSeenAt);

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
        command.AddGuidParameter(IdParameter, sessionId);
        command.AddGuidParameter(UserIdParameter, userId);
        command.AddDateTimeOffsetParameter(VerifiedAtParameter, verifiedAt);
        command.AddParameter(VerifiedProviderTypeParameter, AuthenticationProviderKey.GetStorageTypeValue(verifiedProvider));
        command.AddParameter(VerifiedProviderNameParameter, verifiedProvider.Name);
        command.AddParameter(VerifiedFactorParameter, verifiedFactor);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadSession(reader) : null;
    }

    public async Task<bool> RevokeSessionAsync(Guid sessionId, DateTimeOffset revokedAt, string? reason = null, CancellationToken cancellationToken = default)
    {
        const string sql = """
            UPDATE ashlar_sessions
            SET revoked_at = $revokedAt,
                revocation_reason = $reason
            WHERE id = $id AND revoked_at IS NULL;
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddGuidParameter(IdParameter, sessionId);
        AddRevocationParameters(command, revokedAt, reason);

        return await command.ExecuteNonQueryAsync(cancellationToken) > 0;
    }

    public async Task<int> RevokeSessionsForUserAsync(Guid userId, DateTimeOffset revokedAt, string? reason = null, TenantContext? tenant = null, CancellationToken cancellationToken = default)
    {
        const string sql = """
            UPDATE ashlar_sessions
            SET revoked_at = $revokedAt,
                revocation_reason = $reason
            WHERE user_id = $userId
              AND revoked_at IS NULL
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql + TenantRevocationFilterSql + ";";
        command.AddGuidParameter(UserIdParameter, userId);
        AddTenantFilterParameters(command, tenant);
        AddRevocationParameters(command, revokedAt, reason);

        return await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<AuthenticationSession>> ListSessionsForUserAsync(Guid userId, bool activeOnly, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        const string listAllSql = SelectSql + """
            
            WHERE user_id = $userId
            ORDER BY created_at DESC, id LIMIT 100;
            """;
        const string listActiveSql = SelectSql + """
            
            WHERE user_id = $userId
              AND revoked_at IS NULL
              AND expires_at > $now
            ORDER BY created_at DESC, id LIMIT 100;
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = activeOnly ? listActiveSql : listAllSql;
        command.AddGuidParameter(UserIdParameter, userId);
        command.AddDateTimeOffsetParameter(NowParameter, now);

        var sessions = new List<AuthenticationSession>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            sessions.Add(ReadSession(reader));
        }

        return sessions.AsReadOnly();
    }

    public async Task<bool> RevokeSessionByIdAsync(Guid sessionId, Guid userId, DateTimeOffset revokedAt, string? reason = null, TenantContext? tenant = null, CancellationToken cancellationToken = default)
    {
        const string sql = """
            UPDATE ashlar_sessions
            SET revoked_at = $revokedAt,
                revocation_reason = $reason
            WHERE id = $id
              AND user_id = $userId
              AND revoked_at IS NULL
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql + TenantRevocationFilterSql + ";";
        command.AddGuidParameter(IdParameter, sessionId);
        command.AddGuidParameter(UserIdParameter, userId);
        AddTenantFilterParameters(command, tenant);
        AddRevocationParameters(command, revokedAt, reason);

        return await command.ExecuteNonQueryAsync(cancellationToken) > 0;
    }

    public async Task<int> RevokeOtherSessionsForUserAsync(Guid userId, Guid excludedSessionId, DateTimeOffset revokedAt, string? reason = null, TenantContext? tenant = null, CancellationToken cancellationToken = default)
    {
        const string sql = """
            UPDATE ashlar_sessions
            SET revoked_at = $revokedAt,
                revocation_reason = $reason
            WHERE user_id = $userId
              AND id <> $excludedSessionId
              AND revoked_at IS NULL
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql + TenantRevocationFilterSql + ";";
        command.AddGuidParameter(UserIdParameter, userId);
        command.AddGuidParameter(ExcludedSessionIdParameter, excludedSessionId);
        AddTenantFilterParameters(command, tenant);
        AddRevocationParameters(command, revokedAt, reason);

        return await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private const string SelectSql = """
        SELECT id, user_id, tenant_id, token_hash, created_at, authenticated_at, primary_provider_type, primary_provider_name,
               additional_verification_at, additional_verification_provider_type, additional_verification_provider_name,
               additional_verification_factor, expires_at, last_seen_at, revoked_at, revocation_reason, ip_address, user_agent, metadata
        FROM ashlar_sessions
        """;

    private static void AddRevocationParameters(SqliteCommand command, DateTimeOffset revokedAt, string? reason)
    {
        command.AddDateTimeOffsetParameter(RevokedAtParameter, revokedAt);
        command.AddParameter(ReasonParameter, reason);
    }

    private static void AddTenantFilterParameters(SqliteCommand command, TenantContext? tenant)
    {
        command.AddParameter(TenantFilterParameter, tenant == null ? 0 : 1);
        command.AddNullableGuidParameter(TenantIdParameter, tenant?.TenantId);
    }

    private static void AddParameters(SqliteCommand command, AuthenticationSession session)
    {
        command.AddGuidParameter(IdParameter, session.Id);
        command.AddGuidParameter(UserIdParameter, session.UserId);
        command.AddNullableGuidParameter(TenantIdParameter, session.TenantId);
        command.AddParameter(TokenHashParameter, session.TokenHash);
        command.AddDateTimeOffsetParameter(CreatedAtParameter, session.CreatedAt);
        command.AddNullableDateTimeOffsetParameter(AuthenticatedAtParameter, session.AuthenticatedAt);
        command.AddParameter(PrimaryProviderTypeParameter, AuthenticationProviderKey.GetStorageTypeValue(session.PrimaryProvider));
        command.AddParameter(PrimaryProviderNameParameter, session.PrimaryProvider?.Name);
        command.AddNullableDateTimeOffsetParameter(AdditionalVerificationAtParameter, session.AdditionalVerificationAt);
        command.AddParameter(AdditionalVerificationProviderTypeParameter, AuthenticationProviderKey.GetStorageTypeValue(session.AdditionalVerificationProvider));
        command.AddParameter(AdditionalVerificationProviderNameParameter, session.AdditionalVerificationProvider?.Name);
        command.AddParameter(AdditionalVerificationFactorParameter, session.AdditionalVerificationFactor);
        command.AddDateTimeOffsetParameter(ExpiresAtParameter, session.ExpiresAt);
        command.AddNullableDateTimeOffsetParameter(LastSeenAtParameter, session.LastSeenAt);
        command.AddNullableDateTimeOffsetParameter(RevokedAtParameter, session.RevokedAt);
        command.AddParameter(RevocationReasonParameter, session.RevocationReason);
        command.AddParameter(IpAddressParameter, session.IpAddress);
        command.AddParameter(UserAgentParameter, session.UserAgent);
        command.AddParameter(MetadataParameter, session.Metadata);
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
            PrimaryProvider = PersistedAuthenticationProviderKey.ToProviderKey(primaryType, primaryName),
            AdditionalVerificationAt = reader.GetNullableDateTimeOffsetFromText("additional_verification_at"),
            AdditionalVerificationProvider = PersistedAuthenticationProviderKey.ToProviderKey(additionalType, additionalName),
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
