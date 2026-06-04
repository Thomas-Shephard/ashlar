using Ashlar.Postgres.Models;
using Dapper;

namespace Ashlar.Postgres.Identity;

/// <summary>
/// Stores and retrieves users in PostgreSQL.
/// </summary>
/// <param name="connectionProvider">Provides PostgreSQL connections enlisted in the current Ashlar transaction.</param>
/// <param name="timeProvider">Supplies timestamps for created and updated users.</param>
public sealed class PostgresUserRepository(IPostgresConnectionProvider connectionProvider, TimeProvider? timeProvider = null) : IUserRepository
{
    private const string ExactTenantFilterSql = "((@TenantId IS NULL AND tenant_id IS NULL) OR tenant_id = @TenantId)";
    private readonly IPostgresConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    public async Task<IUser?> GetUserByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);

        const string sql = """
            SELECT id, email, name, account_state AS AccountState, tenant_id AS TenantId, email_verified_at AS EmailVerifiedAt, created_at AS CreatedAt, updated_at AS UpdatedAt
            FROM ashlar_users
            WHERE normalized_email = @NormalizedEmail AND 
            """;

        var parameters = new { NormalizedEmail = IdentityNormalization.NormalizeEmail(email), TenantId = tenantId };
        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql + ExactTenantFilterSql, parameters, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var row = await connectionHandle.Connection.QueryFirstOrDefaultAsync<UserRow>(command);
            return row == null ? null : ToUser(row);
        }
    }

    public async Task<IUser?> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT id, email, name, account_state AS AccountState, tenant_id AS TenantId, email_verified_at AS EmailVerifiedAt, created_at AS CreatedAt, updated_at AS UpdatedAt
            FROM ashlar_users
            WHERE id = @Id
            """;

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new { Id = userId }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var row = await connectionHandle.Connection.QueryFirstOrDefaultAsync<UserRow>(command);
            return row == null ? null : ToUser(row);
        }
    }

    public async Task<IUser?> GetUserByProviderKeyAsync(ProviderType type, string providerName, string providerKey, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerName);
        ArgumentException.ThrowIfNullOrWhiteSpace(providerKey);

        const string sql = """
            SELECT u.id, u.email, u.name, u.account_state AS AccountState, u.tenant_id AS TenantId, u.email_verified_at AS EmailVerifiedAt, u.created_at AS CreatedAt, u.updated_at AS UpdatedAt
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
            var row = await connectionHandle.Connection.QueryFirstOrDefaultAsync<UserRow>(command);
            return row == null ? null : ToUser(row);
        }
    }

    public async Task CreateUserAsync(IUser user, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrWhiteSpace(user.Email);

        const string sql = """
            INSERT INTO ashlar_users (id, email, normalized_email, name, account_state, tenant_id, email_verified_at, created_at)
            VALUES (@Id, @Email, @NormalizedEmail, @Name, @AccountState, @TenantId, @EmailVerifiedAt, @CreatedAt)
            """;

        var createdAt = user is not IHasAuditMetadata audit || audit.CreatedAt == default ? _timeProvider.GetUtcNow() : audit.CreatedAt;
        var tenantId = (user as ITenantUser)?.TenantId;

        var parameters = new
        {
            user.Id,
            user.Email,
            NormalizedEmail = IdentityNormalization.NormalizeEmail(user.Email),
            user.Name,
            AccountState = user.AccountState.ToStorageValue(),
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

    public async Task UpdateUserAsync(IUser user, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrWhiteSpace(user.Email);

        const string sql = """
            UPDATE ashlar_users
            SET email = @Email, normalized_email = @NormalizedEmail, name = @Name, account_state = @AccountState, email_verified_at = @EmailVerifiedAt, updated_at = @UpdatedAt
            WHERE id = @Id AND 
            """;

        var now = _timeProvider.GetUtcNow();
        var tenantId = (user as ITenantUser)?.TenantId;

        var parameters = new
        {
            user.Id,
            user.Email,
            NormalizedEmail = IdentityNormalization.NormalizeEmail(user.Email),
            user.Name,
            AccountState = user.AccountState.ToStorageValue(),
            user.EmailVerifiedAt,
            TenantId = tenantId,
            UpdatedAt = now
        };

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql + ExactTenantFilterSql, parameters, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var rowsAffected = await connectionHandle.Connection.ExecuteAsync(command);

            if (rowsAffected > 0 && user is IHasAuditMetadata auditMetadata)
            {
                auditMetadata.UpdatedAt = now;
            }
        }
    }

    private static AshlarPostgresUser ToUser(UserRow row)
    {
        return new AshlarPostgresUser
        {
            Id = row.Id,
            Email = row.Email,
            Name = row.Name,
            AccountState = UserAccountStates.FromStorageValue(row.AccountState),
            TenantId = row.TenantId,
            EmailVerifiedAt = PostgresAdminQuery.ToNullableDateTimeOffset(row.EmailVerifiedAt),
            CreatedAt = PostgresAdminQuery.ToDateTimeOffset(row.CreatedAt),
            UpdatedAt = PostgresAdminQuery.ToNullableDateTimeOffset(row.UpdatedAt)
        };
    }

    private sealed record UserRow(
        Guid Id,
        string Email,
        string? Name,
        string AccountState,
        Guid? TenantId,
        DateTime? EmailVerifiedAt,
        DateTime CreatedAt,
        DateTime? UpdatedAt);
}
