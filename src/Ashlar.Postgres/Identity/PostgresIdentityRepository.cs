using Ashlar.Postgres.Models;
using Dapper;

namespace Ashlar.Postgres.Identity;

/// <summary>
/// Provides postgres identity repository behavior.
/// </summary>
/// <param name="connectionProvider">The connection provider value.</param>
/// <param name="timeProvider">The time provider value.</param>
public sealed class PostgresIdentityRepository(IPostgresConnectionProvider connectionProvider, TimeProvider? timeProvider = null) : IIdentityRepository
{
    private const string InsertCredentialSql = """
        INSERT INTO ashlar_credentials (id, user_id, provider_type, provider_name, provider_key, version, credential_value, metadata, last_used_at, created_at, updated_at, expires_at, revoked_at, status, purpose)
        VALUES (@Id, @UserId, @ProviderType, @ProviderName, @ProviderKey, @Version, @CredentialValue, @Metadata, @LastUsedAt, @CreatedAt, @UpdatedAt, @ExpiresAt, @RevokedAt, @Status, @Purpose)
        """;

    private const string UpsertCredentialSql = $"""
        {InsertCredentialSql}
        ON CONFLICT (provider_type, provider_name, provider_key) DO UPDATE
        SET version = EXCLUDED.version,
            user_id = ashlar_credentials.user_id,
            credential_value = EXCLUDED.credential_value,
            metadata = EXCLUDED.metadata,
            last_used_at = COALESCE(EXCLUDED.last_used_at, ashlar_credentials.last_used_at),
            created_at = ashlar_credentials.created_at,
            updated_at = COALESCE(EXCLUDED.updated_at, @Now),
            expires_at = EXCLUDED.expires_at,
            revoked_at = EXCLUDED.revoked_at,
            status = EXCLUDED.status,
            purpose = EXCLUDED.purpose
        WHERE ashlar_credentials.user_id = EXCLUDED.user_id
        """;

    private readonly IPostgresConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    /// <summary>
    /// Performs the get user by email <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="email">The email value.</param>
    /// <param name="tenantId">The tenant id value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<IUser?> GetUserByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);

        const string sql = """
            SELECT id, email, name, is_active AS IsActive, tenant_id AS TenantId, email_verified_at AS EmailVerifiedAt, created_at AS CreatedAt, updated_at AS UpdatedAt
            FROM ashlar_users
            WHERE normalized_email = @NormalizedEmail AND ((@TenantId IS NULL AND tenant_id IS NULL) OR tenant_id = @TenantId)
            """;

        var parameters = new { NormalizedEmail = IdentityNormalization.NormalizeEmail(email), TenantId = tenantId };
        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, parameters, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            return await connectionHandle.Connection.QueryFirstOrDefaultAsync<AshlarPostgresUser>(command);
        }
    }

    /// <summary>
    /// Performs the get user by id <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<IUser?> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT id, email, name, is_active AS IsActive, tenant_id AS TenantId, email_verified_at AS EmailVerifiedAt, created_at AS CreatedAt, updated_at AS UpdatedAt
            FROM ashlar_users
            WHERE id = @Id
            """;

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new { Id = userId }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            return await connectionHandle.Connection.QueryFirstOrDefaultAsync<AshlarPostgresUser>(command);
        }
    }

    /// <summary>
    /// Performs the get credential for user <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="type">The type value.</param>
    /// <param name="providerName">The provider name value.</param>
    /// <param name="providerKey">The provider key value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<UserCredential?> GetCredentialForUserAsync(Guid userId, ProviderType type, string providerName, string? providerKey = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerName);

        const string sql = """
            SELECT id, user_id AS UserId, provider_type AS ProviderType, provider_name AS ProviderName, provider_key AS ProviderKey,
                   version, credential_value AS CredentialValue, metadata, last_used_at AS LastUsedAt, created_at AS CreatedAt,
                   updated_at AS UpdatedAt, expires_at AS ExpiresAt, revoked_at AS RevokedAt, status, purpose
            FROM ashlar_credentials
            WHERE user_id = @UserId AND provider_type = @Type AND provider_name = @ProviderName
              AND (@ProviderKey IS NULL OR provider_key = @ProviderKey)
              AND revoked_at IS NULL AND status = @ActiveStatus
            ORDER BY created_at DESC, id
            LIMIT 1
            """;

        var parameters = new { UserId = userId, Type = type.Value, ProviderName = providerName, ProviderKey = providerKey, ActiveStatus = (int)CredentialStatus.Active };
        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, parameters, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            return await connectionHandle.Connection.QueryFirstOrDefaultAsync<UserCredential>(command);
        }
    }

    /// <summary>
    /// Performs the get user by provider key <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="type">The type value.</param>
    /// <param name="providerName">The provider name value.</param>
    /// <param name="providerKey">The provider key value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<IUser?> GetUserByProviderKeyAsync(ProviderType type, string providerName, string providerKey, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerName);
        ArgumentException.ThrowIfNullOrWhiteSpace(providerKey);

        const string sql = """
            SELECT u.id, u.email, u.name, u.is_active AS IsActive, u.tenant_id AS TenantId, u.email_verified_at AS EmailVerifiedAt, u.created_at AS CreatedAt, u.updated_at AS UpdatedAt
            FROM ashlar_users u
            JOIN ashlar_credentials c ON u.id = c.user_id
            WHERE c.provider_type = @Type AND c.provider_name = @ProviderName AND c.provider_key = @ProviderKey
              AND c.revoked_at IS NULL AND c.status = @ActiveStatus
            """;

        var parameters = new { Type = type.Value, ProviderName = providerName, ProviderKey = providerKey, ActiveStatus = (int)CredentialStatus.Active };
        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, parameters, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            return await connectionHandle.Connection.QueryFirstOrDefaultAsync<AshlarPostgresUser>(command);
        }
    }

    /// <summary>
    /// Performs the list credentials for user <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="activeOnly">The active only value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<IReadOnlyList<UserCredential>> ListCredentialsForUserAsync(Guid userId, bool activeOnly = true, CancellationToken cancellationToken = default)
    {
        var sql = """
            SELECT id, user_id AS UserId, provider_type AS ProviderType, provider_name AS ProviderName, provider_key AS ProviderKey,
                   version, NULL AS CredentialValue, metadata, last_used_at AS LastUsedAt, created_at AS CreatedAt,
                   updated_at AS UpdatedAt, expires_at AS ExpiresAt, revoked_at AS RevokedAt, status, purpose
            FROM ashlar_credentials
            WHERE user_id = @UserId
            """;

        if (activeOnly)
        {
            sql += " AND revoked_at IS NULL AND status = @ActiveStatus";
        }

        sql += " ORDER BY provider_type, provider_name, created_at DESC, id LIMIT 100";

        var parameters = new { UserId = userId, ActiveStatus = (int)CredentialStatus.Active };
        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, parameters, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var result = await connectionHandle.Connection.QueryAsync<UserCredential>(command);
            return result.ToList().AsReadOnly();
        }
    }

    /// <summary>
    /// Performs the create user <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="user">The user value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task CreateUserAsync(IUser user, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrWhiteSpace(user.Email);

        const string sql = """
            INSERT INTO ashlar_users (id, email, normalized_email, name, is_active, tenant_id, email_verified_at, created_at)
            VALUES (@Id, @Email, @NormalizedEmail, @Name, @IsActive, @TenantId, @EmailVerifiedAt, @CreatedAt)
            """;

        var createdAt = user is not IHasAuditMetadata audit || audit.CreatedAt == default ? _timeProvider.GetUtcNow() : audit.CreatedAt;
        var tenantId = (user as ITenantUser)?.TenantId;

        var parameters = new
        {
            user.Id,
            user.Email,
            NormalizedEmail = IdentityNormalization.NormalizeEmail(user.Email),
            user.Name,
            user.IsActive,
            TenantId = tenantId,
            user.EmailVerifiedAt,
            CreatedAt = createdAt
        };

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, parameters, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            await connectionHandle.Connection.ExecuteAsync(command);
        }
    }

    /// <summary>
    /// Performs the update user <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="user">The user value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task UpdateUserAsync(IUser user, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrWhiteSpace(user.Email);

        const string sql = """
            UPDATE ashlar_users
            SET email = @Email, normalized_email = @NormalizedEmail, name = @Name, is_active = @IsActive, email_verified_at = @EmailVerifiedAt, updated_at = @UpdatedAt
            WHERE id = @Id AND ((@TenantId IS NULL AND tenant_id IS NULL) OR tenant_id = @TenantId)
            """;

        var now = _timeProvider.GetUtcNow();
        var tenantId = (user as ITenantUser)?.TenantId;

        var parameters = new
        {
            user.Id,
            user.Email,
            NormalizedEmail = IdentityNormalization.NormalizeEmail(user.Email),
            user.Name,
            user.IsActive,
            user.EmailVerifiedAt,
            TenantId = tenantId,
            UpdatedAt = now
        };

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, parameters, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var rowsAffected = await connectionHandle.Connection.ExecuteAsync(command);

            if (rowsAffected > 0 && user is IHasAuditMetadata auditMetadata)
            {
                auditMetadata.UpdatedAt = now;
            }
        }
    }

    /// <summary>
    /// Performs the create credential <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="credential">The credential value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task CreateCredentialAsync(UserCredential credential, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(InsertCredentialSql, ToCredentialParameters(credential), transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            await connectionHandle.Connection.ExecuteAsync(command);
        }
    }

    /// <summary>
    /// Performs the create or replace credential <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="credential">The credential value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task CreateOrReplaceCredentialAsync(UserCredential credential, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(UpsertCredentialSql, ToCredentialParameters(credential), transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var rowsAffected = await connectionHandle.Connection.ExecuteAsync(command);
            if (rowsAffected == 0)
            {
                throw new InvalidOperationException("Credential provider key is already linked to another user.");
            }
        }
    }

    /// <summary>
    /// Performs the update credential <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="credential">The credential value.</param>
    /// <param name="expectedVersion">The expected version value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<bool> UpdateCredentialAsync(UserCredential credential, string expectedVersion, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedVersion);

        const string sql = """
            UPDATE ashlar_credentials
            SET version = @NewVersion, credential_value = @CredentialValue, metadata = @Metadata, last_used_at = @LastUsedAt,
                updated_at = @UpdatedAt, expires_at = @ExpiresAt, revoked_at = @RevokedAt, status = @Status, purpose = @Purpose
            WHERE id = @Id AND version = @ExpectedVersion
            """;

        var newVersion = Guid.NewGuid().ToString();
        var now = _timeProvider.GetUtcNow();

        var parameters = new
        {
            credential.Id,
            ExpectedVersion = expectedVersion,
            NewVersion = newVersion,
            credential.CredentialValue,
            credential.Metadata,
            credential.LastUsedAt,
            UpdatedAt = now,
            credential.ExpiresAt,
            credential.RevokedAt,
            Status = (int)credential.Status,
            credential.Purpose
        };

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, parameters, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var rowsAffected = await connectionHandle.Connection.ExecuteAsync(command);

            if (rowsAffected > 0)
            {
                credential.Version = newVersion;
                credential.UpdatedAt = now;
                return true;
            }

            return false;
        }
    }

    /// <summary>
    /// Performs the consume credential <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="credentialId">The credential id value.</param>
    /// <param name="expectedVersion">The expected version value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<bool> ConsumeCredentialAsync(Guid credentialId, string expectedVersion, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedVersion);

        const string sql = "DELETE FROM ashlar_credentials WHERE id = @Id AND version = @ExpectedVersion";

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new { Id = credentialId, ExpectedVersion = expectedVersion }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var rowsAffected = await connectionHandle.Connection.ExecuteAsync(command);

            return rowsAffected > 0;
        }
    }

    /// <summary>
    /// Performs the revoke credentials <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="type">The type value.</param>
    /// <param name="providerName">The provider name value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<int> RevokeCredentialsAsync(Guid userId, ProviderType type, string providerName, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerName);

        const string sql = """
            UPDATE ashlar_credentials 
            SET status = @RevokedStatus, revoked_at = @RevokedAt, updated_at = @RevokedAt, version = @NewVersion
            WHERE user_id = @UserId AND provider_type = @Type AND provider_name = @Name AND revoked_at IS NULL AND status = @ActiveStatus
            """;

        var revokedAt = _timeProvider.GetUtcNow();
        var parameters = new { UserId = userId, Type = type.Value, Name = providerName, RevokedAt = revokedAt, NewVersion = Guid.NewGuid().ToString(), RevokedStatus = (int)CredentialStatus.Revoked, ActiveStatus = (int)CredentialStatus.Active };

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, parameters, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            return await connectionHandle.Connection.ExecuteAsync(command);
        }
    }

    private object ToCredentialParameters(UserCredential credential)
    {
        return new
        {
            credential.Id,
            credential.UserId,
            ProviderType = credential.ProviderType.Value,
            credential.ProviderName,
            credential.ProviderKey,
            credential.Version,
            credential.CredentialValue,
            credential.Metadata,
            credential.LastUsedAt,
            credential.CreatedAt,
            credential.UpdatedAt,
            credential.ExpiresAt,
            credential.RevokedAt,
            Status = (int)credential.Status,
            credential.Purpose,
            Now = _timeProvider.GetUtcNow()
        };
    }
}






