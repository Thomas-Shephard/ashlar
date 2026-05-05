using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Postgres.Models;
using Dapper;

namespace Ashlar.Postgres;

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
            user_id = EXCLUDED.user_id,
            credential_value = EXCLUDED.credential_value,
            metadata = EXCLUDED.metadata,
            last_used_at = COALESCE(EXCLUDED.last_used_at, ashlar_credentials.last_used_at),
            created_at = ashlar_credentials.created_at,
            updated_at = COALESCE(EXCLUDED.updated_at, @Now),
            expires_at = EXCLUDED.expires_at,
            revoked_at = EXCLUDED.revoked_at,
            status = EXCLUDED.status,
            purpose = EXCLUDED.purpose
        """;

    private readonly IPostgresConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    public async Task<IUser?> GetUserByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);

        const string sql = """
            SELECT id, email, name, is_active AS IsActive, tenant_id AS TenantId, created_at AS CreatedAt, updated_at AS UpdatedAt
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

    public async Task<IUser?> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT id, email, name, is_active AS IsActive, tenant_id AS TenantId, created_at AS CreatedAt, updated_at AS UpdatedAt
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
            ORDER BY created_at DESC
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

    public async Task<IUser?> GetUserByProviderKeyAsync(ProviderType type, string providerName, string providerKey, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerName);
        ArgumentException.ThrowIfNullOrWhiteSpace(providerKey);

        const string sql = """
            SELECT u.id, u.email, u.name, u.is_active AS IsActive, u.tenant_id AS TenantId, u.created_at AS CreatedAt, u.updated_at AS UpdatedAt
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

    public async Task CreateUserAsync(IUser user, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrWhiteSpace(user.Email);

        const string sql = """
            INSERT INTO ashlar_users (id, email, normalized_email, name, is_active, tenant_id, created_at)
            VALUES (@Id, @Email, @NormalizedEmail, @Name, @IsActive, @TenantId, @CreatedAt)
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
            CreatedAt = createdAt
        };

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, parameters, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            await connectionHandle.Connection.ExecuteAsync(command);
        }
    }

    public async Task UpdateUserAsync(IUser user, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrWhiteSpace(user.Email);

        const string sql = """
            UPDATE ashlar_users
            SET email = @Email, normalized_email = @NormalizedEmail, name = @Name, is_active = @IsActive, updated_at = @UpdatedAt
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

    public async Task CreateOrReplaceCredentialAsync(UserCredential credential, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(UpsertCredentialSql, ToCredentialParameters(credential), transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            await connectionHandle.Connection.ExecuteAsync(command);
        }
    }

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

    public async Task<int> RevokeCredentialsAsync(Guid userId, ProviderType type, string providerName, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerName);

        const string sql = """
            UPDATE ashlar_credentials 
            SET status = @RevokedStatus, revoked_at = @RevokedAt, updated_at = @RevokedAt, version = @NewVersion
            WHERE user_id = @UserId AND provider_type = @Type AND provider_name = @Name AND revoked_at IS NULL AND status = @ActiveStatus
            """;

        var revokedAt = _timeProvider.GetUtcNow();
        var parameters = new { UserId = userId, Type = type.Value, Name = providerName, RevokedAt = revokedAt, NewVersion = Guid.NewGuid().ToString("N"), RevokedStatus = (int)CredentialStatus.Revoked, ActiveStatus = (int)CredentialStatus.Active };
        
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
