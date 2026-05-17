using System.Text.Json;
using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Microsoft.Data.Sqlite;

namespace Ashlar.Sqlite;

/// <summary>
/// Provides SQLite invitation repository behavior.
/// </summary>
/// <param name="connectionProvider">The connection provider value.</param>
/// <param name="timeProvider">The time provider value.</param>
public sealed class SqliteInvitationRepository(ISqliteConnectionProvider connectionProvider, TimeProvider? timeProvider = null) : IInvitationRepository
{
    private readonly ISqliteConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    public async Task CreateInvitationAsync(UserInvitation invitation, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(invitation);
        ValidateMetadata(invitation.Metadata);

        const string sql = """
            INSERT INTO ashlar_invitations (id, email, normalized_email, tenant_id, token_hash, created_at, updated_at, expires_at, accepted_at, revoked_at, metadata, version)
            VALUES ($id, $email, $normalizedEmail, $tenantId, $tokenHash, $createdAt, $updatedAt, $expiresAt, $acceptedAt, $revokedAt, $metadata, $version);
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        AddParameters(command, invitation);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<UserInvitation?> GetInvitationByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenHash);

        const string sql = """
            SELECT id, email, tenant_id, token_hash, created_at, updated_at, expires_at, accepted_at, revoked_at, metadata, version
            FROM ashlar_invitations
            WHERE token_hash = $tokenHash;
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddParameter("$tokenHash", tokenHash);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadInvitation(reader) : null;
    }

    public async Task<bool> UpdateInvitationAsync(UserInvitation invitation, string expectedVersion, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(invitation);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedVersion);
        ValidateMetadata(invitation.Metadata);

        const string sql = """
            UPDATE ashlar_invitations
            SET accepted_at = $acceptedAt,
                revoked_at = $revokedAt,
                metadata = $metadata,
                version = $newVersion,
                updated_at = $updatedAt
            WHERE id = $id
              AND version = $expectedVersion
              AND accepted_at IS NULL
              AND revoked_at IS NULL
              AND expires_at > $now;
            """;

        var now = _timeProvider.GetUtcNow();
        var newVersion = Guid.NewGuid().ToString();

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddGuidParameter("$id", invitation.Id);
        command.AddNullableDateTimeOffsetParameter("$acceptedAt", invitation.AcceptedAt);
        command.AddNullableDateTimeOffsetParameter("$revokedAt", invitation.RevokedAt);
        command.AddParameter("$metadata", invitation.Metadata);
        command.AddParameter("$newVersion", newVersion);
        command.AddDateTimeOffsetParameter("$updatedAt", now);
        command.AddParameter("$expectedVersion", expectedVersion);
        command.AddDateTimeOffsetParameter("$now", now);

        if (await command.ExecuteNonQueryAsync(cancellationToken) == 0)
        {
            return false;
        }

        invitation.Version = newVersion;
        invitation.UpdatedAt = now;
        return true;
    }

    public async Task<int> RevokeInvitationsByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);

        const string sql = """
            UPDATE ashlar_invitations
            SET revoked_at = $now,
                version = $newVersion,
                updated_at = $now
            WHERE normalized_email = $normalizedEmail
              AND (($tenantId IS NULL AND tenant_id IS NULL) OR tenant_id = $tenantId)
              AND accepted_at IS NULL
              AND revoked_at IS NULL;
            """;

        var now = _timeProvider.GetUtcNow();
        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddParameter("$normalizedEmail", IdentityNormalization.NormalizeEmail(email));
        command.AddNullableGuidParameter("$tenantId", tenantId);
        command.AddDateTimeOffsetParameter("$now", now);
        command.AddParameter("$newVersion", Guid.NewGuid().ToString());

        return await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static void AddParameters(SqliteCommand command, UserInvitation invitation)
    {
        command.AddGuidParameter("$id", invitation.Id);
        command.AddParameter("$email", invitation.Email);
        command.AddParameter("$normalizedEmail", IdentityNormalization.NormalizeEmail(invitation.Email));
        command.AddNullableGuidParameter("$tenantId", invitation.TenantId);
        command.AddParameter("$tokenHash", invitation.TokenHash);
        command.AddDateTimeOffsetParameter("$createdAt", invitation.CreatedAt);
        command.AddNullableDateTimeOffsetParameter("$updatedAt", invitation.UpdatedAt);
        command.AddDateTimeOffsetParameter("$expiresAt", invitation.ExpiresAt);
        command.AddNullableDateTimeOffsetParameter("$acceptedAt", invitation.AcceptedAt);
        command.AddNullableDateTimeOffsetParameter("$revokedAt", invitation.RevokedAt);
        command.AddParameter("$metadata", invitation.Metadata);
        command.AddParameter("$version", invitation.Version);
    }

    private static UserInvitation ReadInvitation(SqliteDataReader reader)
    {
        return new UserInvitation
        {
            Id = reader.GetGuidFromText("id"),
            Email = reader.GetString(reader.GetOrdinal("email")),
            TenantId = reader.GetNullableGuidFromText("tenant_id"),
            TokenHash = reader.GetString(reader.GetOrdinal("token_hash")),
            CreatedAt = reader.GetDateTimeOffsetFromText("created_at"),
            UpdatedAt = reader.GetNullableDateTimeOffsetFromText("updated_at"),
            ExpiresAt = reader.GetDateTimeOffsetFromText("expires_at"),
            AcceptedAt = reader.GetNullableDateTimeOffsetFromText("accepted_at"),
            RevokedAt = reader.GetNullableDateTimeOffsetFromText("revoked_at"),
            Metadata = reader.GetNullableString("metadata"),
            Version = reader.GetString(reader.GetOrdinal("version"))
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
            throw new ArgumentException("Invitation metadata must be a valid JSON document.", nameof(metadata), exception);
        }
    }
}
