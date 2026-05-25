using Ashlar.Sqlite.Models;
using Microsoft.Data.Sqlite;

namespace Ashlar.Sqlite.Identity;

/// <summary>
/// Stores and retrieves users in SQLite.
/// </summary>
/// <param name="connectionProvider">Provides SQLite connections enlisted in the current Ashlar transaction.</param>
/// <param name="timeProvider">Supplies timestamps for created and updated users.</param>
public sealed class SqliteUserRepository(ISqliteConnectionProvider connectionProvider, TimeProvider? timeProvider = null) : IUserRepository
{
    private const string IdParameter = "$id";
    private const string NormalizedEmailParameter = "$normalizedEmail";
    private const string TenantIdParameter = "$tenantId";
    private const string CreatedAtParameter = "$createdAt";
    private const string UpdatedAtParameter = "$updatedAt";
    private const string ProviderTypeParameter = "$providerType";
    private const string ProviderNameParameter = "$providerName";
    private const string ProviderKeyParameter = "$providerKey";
    private const string ActiveStatusParameter = "$activeStatus";
    private const string ExactTenantFilterSql = "(($tenantId IS NULL AND tenant_id IS NULL) OR tenant_id = $tenantId)";

    private readonly ISqliteConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    public async Task<IUser?> GetUserByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);

        const string sql = """
            SELECT id, email, name, is_active, tenant_id, email_verified_at, created_at, updated_at
            FROM ashlar_users
            WHERE normalized_email = $normalizedEmail AND 
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql + ExactTenantFilterSql + ";";
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
            WHERE id = $id AND 
            """;

        var now = _timeProvider.GetUtcNow();

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql + ExactTenantFilterSql + ";";
        AddUserParameters(command, user, includeUpdatedAt: true, updatedAt: now);
        var rowsAffected = await command.ExecuteNonQueryAsync(cancellationToken);

        if (rowsAffected > 0 && user is IHasAuditMetadata auditMetadata)
        {
            auditMetadata.UpdatedAt = now;
        }
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
}
