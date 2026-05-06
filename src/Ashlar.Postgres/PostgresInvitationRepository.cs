using System.Text.Json;
using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Dapper;

namespace Ashlar.Postgres;

public sealed class PostgresInvitationRepository(IPostgresConnectionProvider connectionProvider, TimeProvider? timeProvider = null) : IInvitationRepository
{
    private readonly IPostgresConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    public async Task CreateInvitationAsync(UserInvitation invitation, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(invitation);
        ValidateMetadata(invitation.Metadata);

        const string sql = """
            INSERT INTO ashlar_invitations (id, email, normalized_email, tenant_id, token_hash, created_at, updated_at, expires_at, metadata, version)
            VALUES (@Id, @Email, @NormalizedEmail, @TenantId, @TokenHash, @CreatedAt, @UpdatedAt, @ExpiresAt, @Metadata::jsonb, @Version)
            """;

        var parameters = new
        {
            invitation.Id,
            invitation.Email,
            NormalizedEmail = IdentityNormalization.NormalizeEmail(invitation.Email),
            invitation.TenantId,
            invitation.TokenHash,
            invitation.CreatedAt,
            invitation.UpdatedAt,
            invitation.ExpiresAt,
            invitation.Metadata,
            invitation.Version
        };

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, parameters, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            await connectionHandle.Connection.ExecuteAsync(command);
        }
    }

    public async Task<UserInvitation?> GetInvitationByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenHash);

        const string sql = """
            SELECT id, email, tenant_id AS TenantId, token_hash AS TokenHash, created_at AS CreatedAt, updated_at AS UpdatedAt,
                   expires_at AS ExpiresAt, accepted_at AS AcceptedAt, revoked_at AS RevokedAt, metadata, version
            FROM ashlar_invitations
            WHERE token_hash = @TokenHash
            """;

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new { TokenHash = tokenHash }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            return await connectionHandle.Connection.QueryFirstOrDefaultAsync<UserInvitation>(command);
        }
    }

    public async Task<bool> UpdateInvitationAsync(UserInvitation invitation, string expectedVersion, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(invitation);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedVersion);
        ValidateMetadata(invitation.Metadata);

        const string sql = """
            UPDATE ashlar_invitations
            SET accepted_at = @AcceptedAt, revoked_at = @RevokedAt, metadata = @Metadata::jsonb, version = @NewVersion, updated_at = @UpdatedAt
            WHERE id = @Id AND version = @ExpectedVersion
            """;

        var newVersion = Guid.NewGuid().ToString();
        var parameters = new
        {
            invitation.Id,
            invitation.AcceptedAt,
            invitation.RevokedAt,
            invitation.Metadata,
            NewVersion = newVersion,
            ExpectedVersion = expectedVersion,
            UpdatedAt = _timeProvider.GetUtcNow()
        };

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, parameters, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var rowsAffected = await connectionHandle.Connection.ExecuteAsync(command);

            if (rowsAffected > 0)
            {
                invitation.Version = newVersion;
                invitation.UpdatedAt = parameters.UpdatedAt;
                return true;
            }

            return false;
        }
    }

    public async Task<int> RevokeInvitationsByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);

        const string sql = """
            UPDATE ashlar_invitations
            SET revoked_at = @Now, version = @NewVersion, updated_at = @Now
            WHERE normalized_email = @NormalizedEmail AND ((@TenantId IS NULL AND tenant_id IS NULL) OR tenant_id = @TenantId)
              AND accepted_at IS NULL AND revoked_at IS NULL
            """;

        var now = _timeProvider.GetUtcNow();
        var parameters = new
        {
            NormalizedEmail = IdentityNormalization.NormalizeEmail(email),
            TenantId = tenantId,
            Now = now,
            NewVersion = Guid.NewGuid().ToString()
        };

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, parameters, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
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
            throw new ArgumentException("Invitation metadata must be a valid JSON document.", nameof(metadata), exception);
        }
    }
}
