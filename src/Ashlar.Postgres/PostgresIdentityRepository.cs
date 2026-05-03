using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Postgres.Models;
using Dapper;
using Npgsql;

namespace Ashlar.Postgres;

public sealed class PostgresIdentityRepository(NpgsqlDataSource dataSource) : IIdentityRepository
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
            updated_at = COALESCE(EXCLUDED.updated_at, NOW()),
            expires_at = EXCLUDED.expires_at,
            revoked_at = EXCLUDED.revoked_at,
            status = EXCLUDED.status,
            purpose = EXCLUDED.purpose
        """;

    private readonly NpgsqlDataSource _dataSource = dataSource ?? throw new ArgumentNullException(nameof(dataSource));

    public async Task<IUser?> GetUserByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);

        const string sql = """
            SELECT id, email, name, is_active AS IsActive, tenant_id AS TenantId, created_at AS CreatedAt, updated_at AS UpdatedAt
            FROM ashlar_users
            WHERE normalized_email = @NormalizedEmail AND ((@TenantId IS NULL AND tenant_id IS NULL) OR tenant_id = @TenantId)
            """;

        var parameters = new { NormalizedEmail = NormalizeEmail(email), TenantId = tenantId };
        var command = new CommandDefinition(sql, parameters, cancellationToken: cancellationToken);

        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        return await connection.QueryFirstOrDefaultAsync<AshlarPostgresUser>(command);
    }

    public async Task<IUser?> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT id, email, name, is_active AS IsActive, tenant_id AS TenantId, created_at AS CreatedAt, updated_at AS UpdatedAt
            FROM ashlar_users
            WHERE id = @Id
            """;

        var command = new CommandDefinition(sql, new { Id = userId }, cancellationToken: cancellationToken);

        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        return await connection.QueryFirstOrDefaultAsync<AshlarPostgresUser>(command);
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
            """;

        var parameters = new { UserId = userId, Type = type.Value, ProviderName = providerName, ProviderKey = providerKey };
        var command = new CommandDefinition(sql, parameters, cancellationToken: cancellationToken);

        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        return await connection.QueryFirstOrDefaultAsync<UserCredential>(command);
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
            """;

        var parameters = new { Type = type.Value, ProviderName = providerName, ProviderKey = providerKey };
        var command = new CommandDefinition(sql, parameters, cancellationToken: cancellationToken);

        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        return await connection.QueryFirstOrDefaultAsync<AshlarPostgresUser>(command);
    }

    public async Task CreateUserAsync(IUser user, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrWhiteSpace(user.Email);

        const string sql = """
            INSERT INTO ashlar_users (id, email, normalized_email, name, is_active, tenant_id, created_at)
            VALUES (@Id, @Email, @NormalizedEmail, @Name, @IsActive, @TenantId, @CreatedAt)
            """;

        var createdAt = user is not IHasAuditMetadata audit || audit.CreatedAt == default ? DateTimeOffset.UtcNow : audit.CreatedAt;
        var tenantId = (user as ITenantUser)?.TenantId;

        var parameters = new
        {
            user.Id,
            user.Email,
            NormalizedEmail = NormalizeEmail(user.Email),
            user.Name,
            user.IsActive,
            TenantId = tenantId,
            CreatedAt = createdAt
        };

        var command = new CommandDefinition(sql, parameters, cancellationToken: cancellationToken);

        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        await connection.ExecuteAsync(command);
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

        var now = DateTimeOffset.UtcNow;
        var tenantId = (user as ITenantUser)?.TenantId;

        var parameters = new
        {
            user.Id,
            user.Email,
            NormalizedEmail = NormalizeEmail(user.Email),
            user.Name,
            user.IsActive,
            TenantId = tenantId,
            UpdatedAt = now
        };

        var command = new CommandDefinition(sql, parameters, cancellationToken: cancellationToken);

        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        var rowsAffected = await connection.ExecuteAsync(command);

        if (rowsAffected > 0 && user is IHasAuditMetadata auditMetadata)
        {
            auditMetadata.UpdatedAt = now;
        }
    }

    public async Task CreateCredentialAsync(UserCredential credential, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);

        var command = new CommandDefinition(InsertCredentialSql, ToCredentialParameters(credential), cancellationToken: cancellationToken);

        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        await connection.ExecuteAsync(command);
    }

    public async Task CreateOrReplaceCredentialAsync(UserCredential credential, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);

        var command = new CommandDefinition(UpsertCredentialSql, ToCredentialParameters(credential), cancellationToken: cancellationToken);

        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        await connection.ExecuteAsync(command);
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
        var now = DateTimeOffset.UtcNow;

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

        var command = new CommandDefinition(sql, parameters, cancellationToken: cancellationToken);

        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        var rowsAffected = await connection.ExecuteAsync(command);

        if (rowsAffected > 0)
        {
            credential.Version = newVersion;
            credential.UpdatedAt = now;
            return true;
        }

        return false;
    }

    public async Task<bool> ConsumeCredentialAsync(Guid credentialId, string expectedVersion, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedVersion);

        const string sql = "DELETE FROM ashlar_credentials WHERE id = @Id AND version = @ExpectedVersion";

        var command = new CommandDefinition(sql, new { Id = credentialId, ExpectedVersion = expectedVersion }, cancellationToken: cancellationToken);

        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        var rowsAffected = await connection.ExecuteAsync(command);

        return rowsAffected > 0;
    }

    private static string NormalizeEmail(string email) => email.Trim().ToUpperInvariant();

    private static object ToCredentialParameters(UserCredential credential)
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
            credential.Purpose
        };
    }
}
