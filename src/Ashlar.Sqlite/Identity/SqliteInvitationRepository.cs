using System.Text.Json;
using Ashlar.Identity.Models.Tenants;
using Microsoft.Data.Sqlite;

namespace Ashlar.Sqlite.Identity;

/// <summary>
/// SQLite-backed invitation repository.
/// </summary>
/// <param name="connectionProvider">Connection provider used for invitation reads and writes.</param>
/// <param name="timeProvider">Clock used for invitation revocation and optimistic updates.</param>
public sealed class SqliteInvitationRepository(ISqliteConnectionProvider connectionProvider, TimeProvider? timeProvider = null) : IInvitationRepository
{
    private const string TenantIdColumn = "tenant_id";
    private const string CreatedAtColumn = "created_at";
    private const string ExpiresAtColumn = "expires_at";
    private const string AcceptedAtColumn = "accepted_at";
    private const string RevokedAtColumn = "revoked_at";

    private readonly ISqliteConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    public async Task CreateInvitationAsync(UserInvitation invitation, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(invitation);
        ValidateMetadata(invitation.Metadata);

        const string sql = """
            INSERT INTO ashlar_invitations (id, display_email, normalized_email, tenant_id, token_hash, created_at, updated_at, expires_at, accepted_at, revoked_at, metadata, version)
            VALUES ($id, $displayEmail, $normalizedEmail, $tenantId, $tokenHash, $createdAt, $updatedAt, $expiresAt, $acceptedAt, $revokedAt, $metadata, $version);
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
            SELECT id, display_email, tenant_id, token_hash, created_at, updated_at, expires_at, accepted_at, revoked_at, metadata, version
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

    public async Task<IReadOnlyList<InvitationAdministrationSummary>> SearchInvitationsAsync(SearchInvitationsRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        SearchInvitationsRequest.ThrowIfInvalid(request);

        var sql = $"""
            SELECT id,
                   display_email,
                   tenant_id,
                   {StatusSql("$now")} AS status,
                   created_at,
                   updated_at,
                   expires_at,
                   accepted_at,
                   revoked_at
            FROM ashlar_invitations
            WHERE 1 = 1
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.AddDateTimeOffsetParameter("$now", now);
        AddAdministrationFilters(command, request, ref sql);
        sql += " ORDER BY created_at DESC, id DESC LIMIT $limit OFFSET $offset;";
        command.AddParameter("$limit", request.Limit);
        command.AddParameter("$offset", request.Offset);
        command.CommandText = sql;

        var invitations = new List<InvitationAdministrationSummary>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            invitations.Add(ReadAdministrationSummary(reader));
        }

        return invitations;
    }

    public async Task<InvitationAdministrationSummary?> GetInvitationAsync(InvitationAdministrationLookupRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        InvitationAdministrationLookupRequest.ThrowIfInvalid(request);

        var sql = $"""
            SELECT id,
                   display_email,
                   tenant_id,
                   {StatusSql("$now")} AS status,
                   created_at,
                   updated_at,
                   expires_at,
                   accepted_at,
                   revoked_at
            FROM ashlar_invitations
            WHERE id = $invitationId
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.AddGuidParameter("$invitationId", request.InvitationId);
        command.AddDateTimeOffsetParameter("$now", now);
        AddScopeFilter(command, request.Tenant, request.IncludeAllTenants, ref sql);
        command.CommandText = sql;

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadAdministrationSummary(reader) : null;
    }

    public async Task<RevokeInvitationAdministrationResult?> RevokeInvitationAsync(RevokeInvitationAdministrationRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        RevokeInvitationAdministrationRequest.ThrowIfInvalid(request);

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);

        var before = await GetRevokeCandidateAsync(handle, request, now, cancellationToken);
        if (before == null)
        {
            return null;
        }

        if (before.Status != InvitationAdministrationStatus.Pending)
        {
            return before;
        }

        const string updateSql = """
            UPDATE ashlar_invitations
            SET revoked_at = $now,
                version = $newVersion,
                updated_at = $now
            WHERE id = $invitationId
              AND accepted_at IS NULL
              AND revoked_at IS NULL
              AND expires_at > $now;
            """;

        int rowsAffected;
        await using (var update = handle.Connection.CreateCommand())
        {
            update.Transaction = handle.Transaction;
            update.CommandText = updateSql;
            update.AddGuidParameter("$invitationId", request.InvitationId);
            update.AddDateTimeOffsetParameter("$now", now);
            update.AddParameter("$newVersion", Guid.NewGuid().ToString());
            rowsAffected = await update.ExecuteNonQueryAsync(cancellationToken);
        }

        if (rowsAffected > 0)
        {
            return before with
            {
                RevocationStatus = InvitationAdministrationRevocationStatus.Revoked,
                Status = InvitationAdministrationStatus.Revoked,
                RevokedAt = now
            };
        }

        return await GetRevokeCandidateAsync(handle, request, now, cancellationToken);
    }

    private static void AddParameters(SqliteCommand command, UserInvitation invitation)
    {
        command.AddGuidParameter("$id", invitation.Id);
        command.AddParameter("$displayEmail", invitation.DisplayEmail);
        command.AddParameter("$normalizedEmail", IdentityNormalization.NormalizeEmail(invitation.DisplayEmail));
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
            DisplayEmail = reader.GetString(reader.GetOrdinal("display_email")),
            TenantId = reader.GetNullableGuidFromText(TenantIdColumn),
            TokenHash = reader.GetString(reader.GetOrdinal("token_hash")),
            CreatedAt = reader.GetDateTimeOffsetFromText(CreatedAtColumn),
            UpdatedAt = reader.GetNullableDateTimeOffsetFromText("updated_at"),
            ExpiresAt = reader.GetDateTimeOffsetFromText(ExpiresAtColumn),
            AcceptedAt = reader.GetNullableDateTimeOffsetFromText(AcceptedAtColumn),
            RevokedAt = reader.GetNullableDateTimeOffsetFromText(RevokedAtColumn),
            Metadata = reader.GetNullableString("metadata"),
            Version = reader.GetString(reader.GetOrdinal("version"))
        };
    }

    private static async Task<RevokeInvitationAdministrationResult?> GetRevokeCandidateAsync(
        SqliteConnectionHandle handle,
        RevokeInvitationAdministrationRequest request,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var sql = $"""
            SELECT id AS invitation_id,
                   tenant_id,
                   {StatusSql("$now")} AS status,
                   revoked_at
            FROM ashlar_invitations
            WHERE id = $invitationId
            """;

        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.AddGuidParameter("$invitationId", request.InvitationId);
        command.AddDateTimeOffsetParameter("$now", now);
        AddScopeFilter(command, request.Tenant, request.IncludeAllTenants, ref sql);
        command.CommandText = sql;

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadRevokeResult(reader) : null;
    }

    private static string StatusSql(string nowParameter)
    {
        return $"""
            CASE
               WHEN accepted_at IS NOT NULL THEN 1
               WHEN revoked_at IS NOT NULL THEN 2
               WHEN expires_at <= {nowParameter} THEN 3
               ELSE 0
            END
            """;
    }

    private static void AddAdministrationFilters(SqliteCommand command, SearchInvitationsRequest request, ref string sql)
    {
        AddScopeFilter(command, request.Tenant, request.IncludeAllTenants, ref sql);

        if (!string.IsNullOrWhiteSpace(request.EmailQuery))
        {
            sql += " AND normalized_email LIKE $normalizedEmailQuery";
            command.AddParameter("$normalizedEmailQuery", $"%{IdentityNormalization.NormalizeEmail(request.EmailQuery)}%");
        }

        if (!string.IsNullOrWhiteSpace(request.Email))
        {
            sql += " AND normalized_email = $normalizedEmail";
            command.AddParameter("$normalizedEmail", IdentityNormalization.NormalizeEmail(request.Email));
        }

        if (request.Status != null)
        {
            sql += $" AND {StatusSql("$now")} = $status";
            command.AddParameter("$status", (int)request.Status.Value);
        }

        command.AddDateRange(request.CreatedFrom, request.CreatedTo, CreatedAtColumn, "$createdFrom", "$createdTo", ref sql);
        command.AddDateRange(request.AcceptedFrom, request.AcceptedTo, AcceptedAtColumn, "$acceptedFrom", "$acceptedTo", ref sql);
        command.AddDateRange(request.RevokedFrom, request.RevokedTo, RevokedAtColumn, "$revokedFrom", "$revokedTo", ref sql);
        command.AddDateRange(request.ExpiresFrom, request.ExpiresTo, ExpiresAtColumn, "$expiresFrom", "$expiresTo", ref sql);
    }

    private static void AddScopeFilter(SqliteCommand command, TenantContext? tenant, bool includeAllTenants, ref string sql)
    {
        if (includeAllTenants)
        {
            return;
        }

        if (tenant!.TenantId == null)
        {
            sql += $" AND {TenantIdColumn} IS NULL";
            return;
        }

        sql += $" AND {TenantIdColumn} = $tenantId";
        command.AddNullableGuidParameter("$tenantId", tenant.TenantId);
    }

    private static InvitationAdministrationSummary ReadAdministrationSummary(SqliteDataReader reader)
    {
        return new InvitationAdministrationSummary(
            reader.GetGuidFromText("id"),
            reader.GetString(reader.GetOrdinal("display_email")),
            reader.GetNullableGuidFromText(TenantIdColumn),
            (InvitationAdministrationStatus)reader.GetInt32ByName("status"),
            reader.GetDateTimeOffsetFromText(CreatedAtColumn),
            reader.GetNullableDateTimeOffsetFromText("updated_at"),
            reader.GetDateTimeOffsetFromText(ExpiresAtColumn),
            reader.GetNullableDateTimeOffsetFromText(AcceptedAtColumn),
            reader.GetNullableDateTimeOffsetFromText(RevokedAtColumn));
    }

    private static RevokeInvitationAdministrationResult ReadRevokeResult(SqliteDataReader reader)
    {
        var invitationId = reader.GetGuidFromText("invitation_id");
        var tenantId = reader.GetNullableGuidFromText(TenantIdColumn);
        var status = (InvitationAdministrationStatus)reader.GetInt32ByName("status");
        return new RevokeInvitationAdministrationResult(
            invitationId,
            tenantId,
            ToRevocationStatus(status),
            status,
            reader.GetNullableDateTimeOffsetFromText(RevokedAtColumn));
    }

    private static InvitationAdministrationRevocationStatus ToRevocationStatus(InvitationAdministrationStatus status)
    {
        return status switch
        {
            InvitationAdministrationStatus.Accepted => InvitationAdministrationRevocationStatus.AlreadyAccepted,
            InvitationAdministrationStatus.Revoked => InvitationAdministrationRevocationStatus.AlreadyRevoked,
            InvitationAdministrationStatus.Expired => InvitationAdministrationRevocationStatus.Expired,
            _ => InvitationAdministrationRevocationStatus.NotRevoked
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
