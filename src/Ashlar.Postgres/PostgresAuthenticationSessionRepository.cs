using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Dapper;
using System.Text.Json;

namespace Ashlar.Postgres;

/// <summary>
/// Provides postgres authentication session repository behavior.
/// </summary>
/// <param name="connectionProvider">The connection provider value.</param>
public sealed class PostgresAuthenticationSessionRepository(IPostgresConnectionProvider connectionProvider) : IAuthenticationSessionRepository
{
    private readonly IPostgresConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));

    /// <summary>
    /// Performs the create session <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="session">The session value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
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
                @Id, @UserId, @TenantId, @TokenHash, @CreatedAt, @AuthenticatedAt, @PrimaryProviderType, @PrimaryProviderName,
                @AdditionalVerificationAt, @AdditionalVerificationProviderType, @AdditionalVerificationProviderName,
                @AdditionalVerificationFactor, @ExpiresAt, @LastSeenAt, @RevokedAt, @RevocationReason, @IpAddress, @UserAgent, @Metadata::jsonb)
            """;

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, ToParameters(session), transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            await connectionHandle.Connection.ExecuteAsync(command);
        }
    }

    /// <summary>
    /// Performs the get session by token hash <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="tokenHash">The token hash value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<AuthenticationSession?> GetSessionByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenHash);

        const string sql = """
            SELECT id AS Id, user_id AS UserId, tenant_id AS TenantId, token_hash AS TokenHash, created_at AS CreatedAt,
                   authenticated_at AS AuthenticatedAt, primary_provider_type AS PrimaryProviderType, primary_provider_name AS PrimaryProviderName,
                   additional_verification_at AS AdditionalVerificationAt, additional_verification_provider_type AS AdditionalVerificationProviderType,
                   additional_verification_provider_name AS AdditionalVerificationProviderName, additional_verification_factor AS AdditionalVerificationFactor,
                   expires_at AS ExpiresAt, last_seen_at AS LastSeenAt, revoked_at AS RevokedAt, revocation_reason AS RevocationReason,
                   ip_address AS IpAddress, user_agent AS UserAgent, metadata AS Metadata
            FROM ashlar_sessions
            WHERE token_hash = @TokenHash
            """;

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new { TokenHash = tokenHash }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var row = await connectionHandle.Connection.QueryFirstOrDefaultAsync<AuthenticationSessionRow>(command);
            return row?.ToSession();
        }
    }

    /// <summary>
    /// Performs the get session <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="sessionId">The session id value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<AuthenticationSession?> GetSessionAsync(Guid sessionId, CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT id AS Id, user_id AS UserId, tenant_id AS TenantId, token_hash AS TokenHash, created_at AS CreatedAt,
                   authenticated_at AS AuthenticatedAt, primary_provider_type AS PrimaryProviderType, primary_provider_name AS PrimaryProviderName,
                   additional_verification_at AS AdditionalVerificationAt, additional_verification_provider_type AS AdditionalVerificationProviderType,
                   additional_verification_provider_name AS AdditionalVerificationProviderName, additional_verification_factor AS AdditionalVerificationFactor,
                   expires_at AS ExpiresAt, last_seen_at AS LastSeenAt, revoked_at AS RevokedAt, revocation_reason AS RevocationReason,
                   ip_address AS IpAddress, user_agent AS UserAgent, metadata AS Metadata
            FROM ashlar_sessions
            WHERE id = @Id
            """;

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new { Id = sessionId }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var row = await connectionHandle.Connection.QueryFirstOrDefaultAsync<AuthenticationSessionRow>(command);
            return row?.ToSession();
        }
    }

    /// <summary>
    /// Performs the update session last seen <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="sessionId">The session id value.</param>
    /// <param name="lastSeenAt">The last seen at value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<bool> UpdateSessionLastSeenAsync(Guid sessionId, DateTimeOffset lastSeenAt, CancellationToken cancellationToken = default)
    {
        const string sql = """
            UPDATE ashlar_sessions
            SET last_seen_at = @LastSeenAt
            WHERE id = @Id
              AND revoked_at IS NULL
              AND expires_at > @LastSeenAt
              AND (last_seen_at IS NULL OR last_seen_at < @LastSeenAt)
            """;

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new { Id = sessionId, LastSeenAt = lastSeenAt }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var rowsAffected = await connectionHandle.Connection.ExecuteAsync(command);
            return rowsAffected > 0;
        }
    }

    /// <summary>
    /// Performs the revoke session <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="sessionId">The session id value.</param>
    /// <param name="revokedAt">The revoked at value.</param>
    /// <param name="reason">The reason value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
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

    /// <summary>
    /// Performs the revoke sessions for user <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="revokedAt">The revoked at value.</param>
    /// <param name="reason">The reason value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
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

    /// <summary>
    /// Performs the list sessions for user <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="activeOnly">The active only value.</param>
    /// <param name="now">The now value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<IReadOnlyList<AuthenticationSession>> ListSessionsForUserAsync(Guid userId, bool activeOnly, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        var sql = """
            SELECT id AS Id, user_id AS UserId, tenant_id AS TenantId, token_hash AS TokenHash, created_at AS CreatedAt,
                   authenticated_at AS AuthenticatedAt, primary_provider_type AS PrimaryProviderType, primary_provider_name AS PrimaryProviderName,
                   additional_verification_at AS AdditionalVerificationAt, additional_verification_provider_type AS AdditionalVerificationProviderType,
                   additional_verification_provider_name AS AdditionalVerificationProviderName, additional_verification_factor AS AdditionalVerificationFactor,
                   expires_at AS ExpiresAt, last_seen_at AS LastSeenAt, revoked_at AS RevokedAt, revocation_reason AS RevocationReason,
                   ip_address AS IpAddress, user_agent AS UserAgent, metadata AS Metadata
            FROM ashlar_sessions
            WHERE user_id = @UserId
            """;

        if (activeOnly)
        {
            sql += " AND revoked_at IS NULL AND expires_at > @Now";
        }

        sql += " ORDER BY created_at DESC, id LIMIT 100";

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new { UserId = userId, Now = now }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var result = await connectionHandle.Connection.QueryAsync<AuthenticationSessionRow>(command);
            return result.Select(row => row.ToSession()).ToList().AsReadOnly();
        }
    }

    /// <summary>
    /// Performs the revoke session by id <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="sessionId">The session id value.</param>
    /// <param name="userId">The user id value.</param>
    /// <param name="revokedAt">The revoked at value.</param>
    /// <param name="reason">The reason value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
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

    /// <summary>
    /// Performs the revoke other sessions for user <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="excludedSessionId">The excluded session id value.</param>
    /// <param name="revokedAt">The revoked at value.</param>
    /// <param name="reason">The reason value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
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

    private static object ToParameters(AuthenticationSession session)
    {
        return new
        {
            session.Id,
            session.UserId,
            session.TenantId,
            session.TokenHash,
            session.CreatedAt,
            session.AuthenticatedAt,
            PrimaryProviderType = AuthenticationProviderKey.GetTypeValueOrNull(session.PrimaryProvider),
            PrimaryProviderName = session.PrimaryProvider?.Name,
            session.AdditionalVerificationAt,
            AdditionalVerificationProviderType = AuthenticationProviderKey.GetTypeValueOrNull(session.AdditionalVerificationProvider),
            AdditionalVerificationProviderName = session.AdditionalVerificationProvider?.Name,
            session.AdditionalVerificationFactor,
            session.ExpiresAt,
            session.LastSeenAt,
            session.RevokedAt,
            session.RevocationReason,
            session.IpAddress,
            session.UserAgent,
            session.Metadata
        };
    }

    private sealed record AuthenticationSessionRow
    {
        public required Guid Id { get; init; }
        public required Guid UserId { get; init; }
        public Guid? TenantId { get; init; }
        public required string TokenHash { get; init; }
        public required DateTimeOffset CreatedAt { get; init; }
        public DateTimeOffset? AuthenticatedAt { get; init; }
        public string? PrimaryProviderType { get; init; }
        public string? PrimaryProviderName { get; init; }
        public DateTimeOffset? AdditionalVerificationAt { get; init; }
        public string? AdditionalVerificationProviderType { get; init; }
        public string? AdditionalVerificationProviderName { get; init; }
        public string? AdditionalVerificationFactor { get; init; }
        public required DateTimeOffset ExpiresAt { get; init; }
        public DateTimeOffset? LastSeenAt { get; init; }
        public DateTimeOffset? RevokedAt { get; init; }
        public string? RevocationReason { get; init; }
        public string? IpAddress { get; init; }
        public string? UserAgent { get; init; }
        public string? Metadata { get; init; }

        public AuthenticationSession ToSession()
        {
            return new AuthenticationSession
            {
                Id = Id,
                UserId = UserId,
                TenantId = TenantId,
                TokenHash = TokenHash,
                CreatedAt = CreatedAt,
                AuthenticatedAt = AuthenticatedAt,
                PrimaryProvider = CreateProvider(PrimaryProviderType, PrimaryProviderName),
                AdditionalVerificationAt = AdditionalVerificationAt,
                AdditionalVerificationProvider = CreateProvider(AdditionalVerificationProviderType, AdditionalVerificationProviderName),
                AdditionalVerificationFactor = AdditionalVerificationFactor,
                ExpiresAt = ExpiresAt,
                LastSeenAt = LastSeenAt,
                RevokedAt = RevokedAt,
                RevocationReason = RevocationReason,
                IpAddress = IpAddress,
                UserAgent = UserAgent,
                Metadata = Metadata
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
    }
}
