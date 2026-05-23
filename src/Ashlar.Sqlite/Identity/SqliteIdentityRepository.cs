using Ashlar.Sqlite.Models;
using Microsoft.Data.Sqlite;

namespace Ashlar.Sqlite.Identity;

/// <summary>
/// Provides SQLite identity repository behavior.
/// </summary>
/// <param name="connectionProvider">The connection provider value.</param>
/// <param name="timeProvider">The time provider value.</param>
public sealed class SqliteIdentityRepository(ISqliteConnectionProvider connectionProvider, TimeProvider? timeProvider = null) : IIdentityRepository
{
    private const string UserIdParameter = "$userId";
    private const string ProviderTypeParameter = "$providerType";
    private const string ProviderNameParameter = "$providerName";
    private const string ProviderKeyParameter = "$providerKey";
    private const string ActiveStatusParameter = "$activeStatus";
    private const string IdParameter = "$id";
    private const string NormalizedEmailParameter = "$normalizedEmail";
    private const string TenantIdParameter = "$tenantId";
    private const string CreatedAtParameter = "$createdAt";
    private const string UpdatedAtParameter = "$updatedAt";
    private const string ExpectedVersionParameter = "$expectedVersion";
    private const string NewVersionParameter = "$newVersion";
    private const string CredentialValueParameter = "$credentialValue";
    private const string MetadataParameter = "$metadata";
    private const string LastUsedAtParameter = "$lastUsedAt";
    private const string ExpiresAtParameter = "$expiresAt";
    private const string RevokedAtParameter = "$revokedAt";
    private const string StatusParameter = "$status";
    private const string PurposeParameter = "$purpose";

    private const string InsertCredentialSql = """
        INSERT INTO ashlar_credentials (id, user_id, provider_type, provider_name, provider_key, version, credential_value, metadata, last_used_at, created_at, updated_at, expires_at, revoked_at, status, purpose)
        VALUES ($id, $userId, $providerType, $providerName, $providerKey, $version, $credentialValue, $metadata, $lastUsedAt, $createdAt, $updatedAt, $expiresAt, $revokedAt, $status, $purpose);
        """;

    private readonly ISqliteConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    public async Task<IUser?> GetUserByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);

        const string sql = """
            SELECT id, email, name, is_active, tenant_id, email_verified_at, created_at, updated_at
            FROM ashlar_users
            WHERE normalized_email = $normalizedEmail AND (($tenantId IS NULL AND tenant_id IS NULL) OR tenant_id = $tenantId);
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddParameter(NormalizedEmailParameter, IdentityNormalization.NormalizeEmail(email));
        command.AddNullableGuidParameter(TenantIdParameter, tenantId);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadUser(reader) : null;
    }

    public async Task<IUser?> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT id, email, name, is_active, tenant_id, email_verified_at, created_at, updated_at
            FROM ashlar_users
            WHERE id = $id;
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddGuidParameter(IdParameter, userId);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadUser(reader) : null;
    }

    public async Task<UserCredential?> GetCredentialForUserAsync(Guid userId, ProviderType type, string providerName, string? providerKey = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerName);

        const string sql = """
            SELECT id, user_id, provider_type, provider_name, provider_key, version, credential_value, metadata, last_used_at,
                   created_at, updated_at, expires_at, revoked_at, status, purpose
            FROM ashlar_credentials
            WHERE user_id = $userId AND provider_type = $providerType AND provider_name = $providerName
              AND ($providerKey IS NULL OR provider_key = $providerKey)
              AND revoked_at IS NULL AND status = $activeStatus
            ORDER BY created_at DESC, id
            LIMIT 1;
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddGuidParameter(UserIdParameter, userId);
        command.AddParameter(ProviderTypeParameter, type.Value);
        command.AddParameter(ProviderNameParameter, providerName);
        command.AddParameter(ProviderKeyParameter, providerKey);
        command.AddParameter(ActiveStatusParameter, (int)CredentialStatus.Active);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadCredential(reader, includeSecret: true) : null;
    }

    public async Task<IUser?> GetUserByProviderKeyAsync(ProviderType type, string providerName, string providerKey, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerName);
        ArgumentException.ThrowIfNullOrWhiteSpace(providerKey);

        const string sql = """
            SELECT u.id, u.email, u.name, u.is_active, u.tenant_id, u.email_verified_at, u.created_at, u.updated_at
            FROM ashlar_users u
            JOIN ashlar_credentials c ON u.id = c.user_id
            WHERE c.provider_type = $providerType AND c.provider_name = $providerName AND c.provider_key = $providerKey
              AND c.revoked_at IS NULL AND c.status = $activeStatus;
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddParameter(ProviderTypeParameter, type.Value);
        command.AddParameter(ProviderNameParameter, providerName);
        command.AddParameter(ProviderKeyParameter, providerKey);
        command.AddParameter(ActiveStatusParameter, (int)CredentialStatus.Active);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadUser(reader) : null;
    }

    public async Task<IReadOnlyList<UserCredential>> ListCredentialsForUserAsync(Guid userId, bool activeOnly = true, CancellationToken cancellationToken = default)
    {
        var sql = """
            SELECT id, user_id, provider_type, provider_name, provider_key, version, NULL AS credential_value, metadata, last_used_at,
                   created_at, updated_at, expires_at, revoked_at, status, purpose
            FROM ashlar_credentials
            WHERE user_id = $userId
            """;

        if (activeOnly)
        {
            sql += " AND revoked_at IS NULL AND status = $activeStatus";
        }

        sql += " ORDER BY provider_type, provider_name, created_at DESC, id LIMIT 100;";

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddGuidParameter(UserIdParameter, userId);
        command.AddParameter(ActiveStatusParameter, (int)CredentialStatus.Active);

        var credentials = new List<UserCredential>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            credentials.Add(ReadCredential(reader, includeSecret: false));
        }

        return credentials.AsReadOnly();
    }

    public async Task CreateUserAsync(IUser user, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrWhiteSpace(user.Email);

        const string sql = """
            INSERT INTO ashlar_users (id, email, normalized_email, name, is_active, tenant_id, email_verified_at, created_at)
            VALUES ($id, $email, $normalizedEmail, $name, $isActive, $tenantId, $emailVerifiedAt, $createdAt);
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        AddUserParameters(command, user, includeUpdatedAt: false);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task UpdateUserAsync(IUser user, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrWhiteSpace(user.Email);

        const string sql = """
            UPDATE ashlar_users
            SET email = $email, normalized_email = $normalizedEmail, name = $name, is_active = $isActive,
                email_verified_at = $emailVerifiedAt, updated_at = $updatedAt
            WHERE id = $id AND (($tenantId IS NULL AND tenant_id IS NULL) OR tenant_id = $tenantId);
            """;

        var now = _timeProvider.GetUtcNow();

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        AddUserParameters(command, user, includeUpdatedAt: true, updatedAt: now);
        var rowsAffected = await command.ExecuteNonQueryAsync(cancellationToken);

        if (rowsAffected > 0 && user is IHasAuditMetadata auditMetadata)
        {
            auditMetadata.UpdatedAt = now;
        }
    }

    public async Task CreateCredentialAsync(UserCredential credential, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = InsertCredentialSql;
        AddCredentialParameters(command, credential);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    /// <summary>
    /// Atomically creates a credential or replaces the existing credential with the same provider identity.
    /// </summary>
    /// <param name="credential">The credential value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    /// <exception cref="CredentialProviderKeyConflictException">
    /// The credential provider key is already linked to a different user.
    /// </exception>
    public async Task CreateOrReplaceCredentialAsync(UserCredential credential, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);

        const string sql = """
            INSERT INTO ashlar_credentials (id, user_id, provider_type, provider_name, provider_key, version, credential_value, metadata, last_used_at, created_at, updated_at, expires_at, revoked_at, status, purpose)
            VALUES ($id, $userId, $providerType, $providerName, $providerKey, $version, $credentialValue, $metadata, $lastUsedAt, $createdAt, $updatedAt, $expiresAt, $revokedAt, $status, $purpose)
            ON CONFLICT(provider_type, provider_name, provider_key) DO UPDATE
            SET version = excluded.version,
                user_id = ashlar_credentials.user_id,
                credential_value = excluded.credential_value,
                metadata = excluded.metadata,
                last_used_at = COALESCE(excluded.last_used_at, ashlar_credentials.last_used_at),
                created_at = ashlar_credentials.created_at,
                updated_at = COALESCE(excluded.updated_at, $now),
                expires_at = excluded.expires_at,
                revoked_at = excluded.revoked_at,
                status = excluded.status,
                purpose = excluded.purpose
            WHERE ashlar_credentials.user_id = excluded.user_id;
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        AddCredentialParameters(command, credential);
        command.AddDateTimeOffsetParameter("$now", _timeProvider.GetUtcNow());
        var rowsAffected = await command.ExecuteNonQueryAsync(cancellationToken);
        if (rowsAffected == 0)
        {
            throw new CredentialProviderKeyConflictException();
        }
    }

    public async Task<bool> UpdateCredentialAsync(UserCredential credential, string expectedVersion, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedVersion);

        const string sql = """
            UPDATE ashlar_credentials
            SET version = $newVersion, credential_value = $credentialValue, metadata = $metadata, last_used_at = $lastUsedAt,
                updated_at = $updatedAt, expires_at = $expiresAt, revoked_at = $revokedAt, status = $status, purpose = $purpose
            WHERE id = $id AND version = $expectedVersion;
            """;

        var newVersion = Guid.NewGuid().ToString();
        var now = _timeProvider.GetUtcNow();

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddGuidParameter(IdParameter, credential.Id);
        command.AddParameter(ExpectedVersionParameter, expectedVersion);
        command.AddParameter(NewVersionParameter, newVersion);
        command.AddParameter(CredentialValueParameter, credential.CredentialValue);
        command.AddParameter(MetadataParameter, credential.Metadata);
        command.AddNullableDateTimeOffsetParameter(LastUsedAtParameter, credential.LastUsedAt);
        command.AddDateTimeOffsetParameter(UpdatedAtParameter, now);
        command.AddNullableDateTimeOffsetParameter(ExpiresAtParameter, credential.ExpiresAt);
        command.AddNullableDateTimeOffsetParameter(RevokedAtParameter, credential.RevokedAt);
        command.AddParameter(StatusParameter, (int)credential.Status);
        command.AddParameter(PurposeParameter, credential.Purpose);

        if (await command.ExecuteNonQueryAsync(cancellationToken) == 0)
        {
            return false;
        }

        credential.Version = newVersion;
        credential.UpdatedAt = now;
        return true;
    }

    public async Task<bool> ConsumeCredentialAsync(Guid credentialId, string expectedVersion, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedVersion);

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = "DELETE FROM ashlar_credentials WHERE id = $id AND version = $expectedVersion;";
        command.AddGuidParameter(IdParameter, credentialId);
        command.AddParameter(ExpectedVersionParameter, expectedVersion);

        return await command.ExecuteNonQueryAsync(cancellationToken) > 0;
    }

    public async Task<int> RevokeCredentialsAsync(Guid userId, ProviderType type, string providerName, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerName);

        const string sql = """
            UPDATE ashlar_credentials
            SET status = $revokedStatus, revoked_at = $revokedAt, updated_at = $revokedAt, version = $newVersion
            WHERE user_id = $userId AND provider_type = $providerType AND provider_name = $providerName
              AND revoked_at IS NULL AND status = $activeStatus;
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddGuidParameter(UserIdParameter, userId);
        command.AddParameter(ProviderTypeParameter, type.Value);
        command.AddParameter(ProviderNameParameter, providerName);
        command.AddParameter("$revokedStatus", (int)CredentialStatus.Revoked);
        command.AddParameter(ActiveStatusParameter, (int)CredentialStatus.Active);
        command.AddDateTimeOffsetParameter(RevokedAtParameter, _timeProvider.GetUtcNow());
        command.AddParameter(NewVersionParameter, Guid.NewGuid().ToString());

        return await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private void AddUserParameters(SqliteCommand command, IUser user, bool includeUpdatedAt, DateTimeOffset? updatedAt = null)
    {
        var createdAt = user is not IHasAuditMetadata audit || audit.CreatedAt == default ? _timeProvider.GetUtcNow() : audit.CreatedAt;
        var tenantId = (user as ITenantUser)?.TenantId;

        command.AddGuidParameter(IdParameter, user.Id);
        command.AddParameter("$email", user.Email);
        command.AddParameter(NormalizedEmailParameter, IdentityNormalization.NormalizeEmail(user.Email));
        command.AddParameter("$name", user.Name);
        command.AddParameter("$isActive", user.IsActive ? 1 : 0);
        command.AddNullableGuidParameter(TenantIdParameter, tenantId);
        command.AddNullableDateTimeOffsetParameter("$emailVerifiedAt", user.EmailVerifiedAt);
        command.AddDateTimeOffsetParameter(CreatedAtParameter, createdAt);
        if (includeUpdatedAt)
        {
            command.AddDateTimeOffsetParameter(UpdatedAtParameter, updatedAt.GetValueOrDefault());
        }
    }

    private static void AddCredentialParameters(SqliteCommand command, UserCredential credential)
    {
        command.AddGuidParameter(IdParameter, credential.Id);
        command.AddGuidParameter(UserIdParameter, credential.UserId);
        command.AddParameter(ProviderTypeParameter, credential.ProviderType.Value);
        command.AddParameter(ProviderNameParameter, credential.ProviderName);
        command.AddParameter(ProviderKeyParameter, credential.ProviderKey);
        command.AddParameter("$version", credential.Version);
        command.AddParameter(CredentialValueParameter, credential.CredentialValue);
        command.AddParameter(MetadataParameter, credential.Metadata);
        command.AddNullableDateTimeOffsetParameter(LastUsedAtParameter, credential.LastUsedAt);
        command.AddDateTimeOffsetParameter(CreatedAtParameter, credential.CreatedAt);
        command.AddNullableDateTimeOffsetParameter(UpdatedAtParameter, credential.UpdatedAt);
        command.AddNullableDateTimeOffsetParameter(ExpiresAtParameter, credential.ExpiresAt);
        command.AddNullableDateTimeOffsetParameter(RevokedAtParameter, credential.RevokedAt);
        command.AddParameter(StatusParameter, (int)credential.Status);
        command.AddParameter(PurposeParameter, credential.Purpose);
    }

    private static AshlarSqliteUser ReadUser(SqliteDataReader reader)
    {
        return new AshlarSqliteUser
        {
            Id = reader.GetGuidFromText("id"),
            Email = reader.GetString(reader.GetOrdinal("email")),
            Name = reader.GetNullableString("name"),
            IsActive = reader.GetBooleanFromInteger("is_active"),
            TenantId = reader.GetNullableGuidFromText("tenant_id"),
            EmailVerifiedAt = reader.GetNullableDateTimeOffsetFromText("email_verified_at"),
            CreatedAt = reader.GetDateTimeOffsetFromText("created_at"),
            UpdatedAt = reader.GetNullableDateTimeOffsetFromText("updated_at")
        };
    }

    private static UserCredential ReadCredential(SqliteDataReader reader, bool includeSecret)
    {
        return new UserCredential
        {
            Id = reader.GetGuidFromText("id"),
            UserId = reader.GetGuidFromText("user_id"),
            ProviderType = reader.GetString(reader.GetOrdinal("provider_type")),
            ProviderName = reader.GetString(reader.GetOrdinal("provider_name")),
            ProviderKey = reader.GetString(reader.GetOrdinal("provider_key")),
            Version = reader.GetString(reader.GetOrdinal("version")),
            CredentialValue = includeSecret ? reader.GetNullableString("credential_value") : null,
            Metadata = reader.GetNullableString("metadata"),
            LastUsedAt = reader.GetNullableDateTimeOffsetFromText("last_used_at"),
            CreatedAt = reader.GetDateTimeOffsetFromText("created_at"),
            UpdatedAt = reader.GetNullableDateTimeOffsetFromText("updated_at"),
            ExpiresAt = reader.GetNullableDateTimeOffsetFromText("expires_at"),
            RevokedAt = reader.GetNullableDateTimeOffsetFromText("revoked_at"),
            Status = (CredentialStatus)reader.GetInt32ByName("status"),
            Purpose = reader.GetNullableString("purpose")
        };
    }
}
