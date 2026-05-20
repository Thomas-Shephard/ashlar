using Dapper;
using System.Text.Json;

namespace Ashlar.Postgres.Identity;

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
            var row = await connectionHandle.Connection.QueryFirstOrDefaultAsync(command);
            return row == null ? null : ToSession(row);
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
            var row = await connectionHandle.Connection.QueryFirstOrDefaultAsync(command);
            return row == null ? null : ToSession(row);
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
    /// Performs the mark step up verified <see langword="async" /> operation and returns the updated session.
    /// </summary>
    /// <param name="sessionId">The session id value.</param>
    /// <param name="userId">The user id value.</param>
    /// <param name="verifiedAt">The verification timestamp value.</param>
    /// <param name="verifiedProvider">The verified provider value.</param>
    /// <param name="verifiedFactor">The verified factor value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The updated session, or <see langword="null" /> when no active owned session was updated.</returns>
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
            SET additional_verification_at = @VerifiedAt,
                additional_verification_provider_type = @VerifiedProviderType,
                additional_verification_provider_name = @VerifiedProviderName,
                additional_verification_factor = @VerifiedFactor
            WHERE id = @Id
              AND user_id = @UserId
              AND revoked_at IS NULL
              AND expires_at > @VerifiedAt
            RETURNING id AS Id, user_id AS UserId, tenant_id AS TenantId, token_hash AS TokenHash, created_at AS CreatedAt,
                      authenticated_at AS AuthenticatedAt, primary_provider_type AS PrimaryProviderType, primary_provider_name AS PrimaryProviderName,
                      additional_verification_at AS AdditionalVerificationAt, additional_verification_provider_type AS AdditionalVerificationProviderType,
                      additional_verification_provider_name AS AdditionalVerificationProviderName, additional_verification_factor AS AdditionalVerificationFactor,
                      expires_at AS ExpiresAt, last_seen_at AS LastSeenAt, revoked_at AS RevokedAt, revocation_reason AS RevocationReason,
                      ip_address AS IpAddress, user_agent AS UserAgent, metadata AS Metadata
            """;

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new
            {
                Id = sessionId,
                UserId = userId,
                VerifiedAt = verifiedAt,
                VerifiedProviderType = AuthenticationProviderKey.GetTypeValueOrNull(verifiedProvider),
                VerifiedProviderName = verifiedProvider.Name,
                VerifiedFactor = verifiedFactor
            }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var row = await connectionHandle.Connection.QueryFirstOrDefaultAsync(command);
            return row == null ? null : ToSession(row);
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
            var result = await connectionHandle.Connection.QueryAsync(command);
            return result.Select(ToSession).ToList().AsReadOnly();
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

    private static AuthenticationSession ToSession(dynamic row)
    {
        var values = new Dictionary<string, object?>((IDictionary<string, object?>)row, StringComparer.OrdinalIgnoreCase);
        string? primaryProviderType = ToNullableString(values["PrimaryProviderType"]);
        string? primaryProviderName = ToNullableString(values["PrimaryProviderName"]);
        string? additionalVerificationProviderType = ToNullableString(values["AdditionalVerificationProviderType"]);
        string? additionalVerificationProviderName = ToNullableString(values["AdditionalVerificationProviderName"]);

        return new AuthenticationSession
        {
            Id = (Guid)values["Id"]!,
            UserId = (Guid)values["UserId"]!,
            TenantId = ToNullableGuid(values["TenantId"]),
            TokenHash = (string)values["TokenHash"]!,
            CreatedAt = ToDateTimeOffset(values["CreatedAt"]!),
            AuthenticatedAt = ToNullableDateTimeOffset(values["AuthenticatedAt"]),
            PrimaryProvider = CreateProvider(primaryProviderType, primaryProviderName),
            AdditionalVerificationAt = ToNullableDateTimeOffset(values["AdditionalVerificationAt"]),
            AdditionalVerificationProvider = CreateProvider(additionalVerificationProviderType, additionalVerificationProviderName),
            AdditionalVerificationFactor = ToNullableString(values["AdditionalVerificationFactor"]),
            ExpiresAt = ToDateTimeOffset(values["ExpiresAt"]!),
            LastSeenAt = ToNullableDateTimeOffset(values["LastSeenAt"]),
            RevokedAt = ToNullableDateTimeOffset(values["RevokedAt"]),
            RevocationReason = ToNullableString(values["RevocationReason"]),
            IpAddress = ToNullableString(values["IpAddress"]),
            UserAgent = ToNullableString(values["UserAgent"]),
            Metadata = ToNullableString(values["Metadata"])
        };
    }

    private static DateTimeOffset ToDateTimeOffset(object value)
    {
        return new DateTimeOffset((DateTime)value);
    }

    private static DateTimeOffset? ToNullableDateTimeOffset(object? value)
    {
        return value == null ? null : ToDateTimeOffset(value);
    }

    private static Guid? ToNullableGuid(object? value)
    {
        return value == null ? null : (Guid)value;
    }

    private static string? ToNullableString(object? value)
    {
        return value as string;
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
