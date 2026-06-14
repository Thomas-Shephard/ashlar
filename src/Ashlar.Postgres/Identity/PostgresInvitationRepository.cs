using System.Text.Json;
using Dapper;
using Ashlar.Identity.Models.Tenants;

namespace Ashlar.Postgres.Identity;

/// <summary>
/// Provides postgres invitation repository behavior.
/// </summary>
/// <param name="connectionProvider">The connection provider value.</param>
/// <param name="timeProvider">The time provider value.</param>
public sealed class PostgresInvitationRepository(IPostgresConnectionProvider connectionProvider, TimeProvider? timeProvider = null) : IInvitationRepository
{
    private readonly IPostgresConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    /// <summary>
    /// Performs the create invitation <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="invitation">The invitation value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
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

    /// <summary>
    /// Performs the get invitation by token hash <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="tokenHash">The token hash value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
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

    /// <summary>
    /// Performs the update invitation <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="invitation">The invitation value.</param>
    /// <param name="expectedVersion">The expected version value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<bool> UpdateInvitationAsync(UserInvitation invitation, string expectedVersion, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(invitation);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedVersion);
        ValidateMetadata(invitation.Metadata);

        const string sql = """
            UPDATE ashlar_invitations
            SET accepted_at = @AcceptedAt, revoked_at = @RevokedAt, metadata = @Metadata::jsonb, version = @NewVersion, updated_at = @UpdatedAt
            WHERE id = @Id
              AND version = @ExpectedVersion
              AND accepted_at IS NULL
              AND revoked_at IS NULL
              AND expires_at > @Now
            """;

        var newVersion = Guid.NewGuid().ToString();
        var now = _timeProvider.GetUtcNow();
        var parameters = new
        {
            invitation.Id,
            invitation.AcceptedAt,
            invitation.RevokedAt,
            invitation.Metadata,
            NewVersion = newVersion,
            ExpectedVersion = expectedVersion,
            UpdatedAt = now,
            Now = now
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

    /// <summary>
    /// Performs the revoke invitations by email <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="email">The email value.</param>
    /// <param name="tenantId">The tenant id value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
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

    /// <summary>
    /// Searches invitations using display-safe administrator filters.
    /// </summary>
    /// <param name="request">Explicit tenant scope, filters, and paging options.</param>
    /// <param name="now">UTC time used to classify invitation status.</param>
    /// <param name="cancellationToken">A token that can cancel the search.</param>
    /// <returns>Invitation summaries without raw token, token hash, or provider version data.</returns>
    public async Task<IReadOnlyList<InvitationAdministrationSummary>> SearchInvitationsAsync(SearchInvitationsRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        SearchInvitationsRequest.ThrowIfInvalid(request);

        var sql = $"""
            SELECT id,
                   email,
                   tenant_id AS TenantId,
                   {StatusSql("@Now")} AS Status,
                   created_at AS CreatedAt,
                   updated_at AS UpdatedAt,
                   expires_at AS ExpiresAt,
                   accepted_at AS AcceptedAt,
                   revoked_at AS RevokedAt
            FROM ashlar_invitations
            WHERE 1 = 1
            """;

        var parameters = new DynamicParameters();
        parameters.Add("Now", now);
        AddAdministrationFilters(request, ref sql, parameters);
        sql += " ORDER BY created_at DESC, id DESC LIMIT @Limit OFFSET @Offset";
        parameters.Add("Limit", request.Limit);
        parameters.Add("Offset", request.Offset);

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, parameters, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var rows = await connectionHandle.Connection.QueryAsync<InvitationAdministrationSummaryRow>(command);
            return rows.Select(static row => row.ToSummary()).ToList();
        }
    }

    /// <summary>
    /// Gets display-safe invitation detail by identifier.
    /// </summary>
    /// <param name="request">Explicit tenant scope and invitation identifier.</param>
    /// <param name="now">UTC time used to classify invitation status.</param>
    /// <param name="cancellationToken">A token that can cancel the lookup.</param>
    /// <returns>The matching invitation detail, or <see langword="null" /> when no invitation exists in scope.</returns>
    public async Task<InvitationAdministrationDetail?> GetInvitationAsync(InvitationAdministrationDetailRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        InvitationAdministrationDetailRequest.ThrowIfInvalid(request);

        var sql = $"""
            SELECT id,
                   email,
                   tenant_id AS TenantId,
                   {StatusSql("@Now")} AS Status,
                   created_at AS CreatedAt,
                   updated_at AS UpdatedAt,
                   expires_at AS ExpiresAt,
                   accepted_at AS AcceptedAt,
                   revoked_at AS RevokedAt
            FROM ashlar_invitations
            WHERE id = @InvitationId
            """;

        var parameters = new DynamicParameters();
        parameters.Add("InvitationId", request.InvitationId);
        parameters.Add("Now", now);
        AddScopeFilter(request.Tenant, request.IncludeAllTenants, ref sql, parameters);

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, parameters, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var row = await connectionHandle.Connection.QueryFirstOrDefaultAsync<InvitationAdministrationDetailRow>(command);
            return row?.ToDetail();
        }
    }

    /// <summary>
    /// Revokes a pending invitation by identifier.
    /// </summary>
    /// <param name="request">Explicit tenant scope and invitation identifier.</param>
    /// <param name="now">UTC time to persist as the revocation timestamp.</param>
    /// <param name="cancellationToken">A token that can cancel revocation.</param>
    /// <returns>The invitation state after the operation, or <see langword="null" /> when no invitation exists in scope.</returns>
    public async Task<RevokeInvitationAdministrationResult?> RevokeInvitationAsync(RevokeInvitationAdministrationRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        RevokeInvitationAdministrationRequest.ThrowIfInvalid(request);

        var sql = $"""
            WITH candidate AS (
                SELECT id, tenant_id, accepted_at, revoked_at, expires_at
                FROM ashlar_invitations
                WHERE id = @InvitationId
            """;
        var parameters = new DynamicParameters();
        parameters.Add("InvitationId", request.InvitationId);
        parameters.Add("Now", now);
        parameters.Add("NewVersion", Guid.NewGuid().ToString());
        AddScopeFilter(request.Tenant, request.IncludeAllTenants, ref sql, parameters);
        sql += """
            ),
            updated AS (
                UPDATE ashlar_invitations
                SET revoked_at = @Now, updated_at = @Now, version = @NewVersion
                WHERE id IN (SELECT id FROM candidate)
                  AND accepted_at IS NULL
                  AND revoked_at IS NULL
                  AND expires_at > @Now
                RETURNING id, tenant_id, accepted_at, revoked_at, expires_at, TRUE AS revoked
            )
            SELECT id AS InvitationId,
                   tenant_id AS TenantId,
                   revoked AS Revoked,
                   CASE
                       WHEN accepted_at IS NOT NULL THEN 1
                       WHEN revoked_at IS NOT NULL THEN 2
                       WHEN expires_at <= @Now THEN 3
                       ELSE 0
                   END AS Status,
                   revoked_at AS RevokedAt
            FROM updated
            UNION ALL
            SELECT id AS InvitationId,
                   tenant_id AS TenantId,
                   FALSE AS Revoked,
                   CASE
                       WHEN accepted_at IS NOT NULL THEN 1
                       WHEN revoked_at IS NOT NULL THEN 2
                       WHEN expires_at <= @Now THEN 3
                       ELSE 0
                   END AS Status,
                   revoked_at AS RevokedAt
            FROM candidate
            WHERE NOT EXISTS (SELECT 1 FROM updated)
            """;

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, parameters, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var row = await connectionHandle.Connection.QueryFirstOrDefaultAsync<RevokeInvitationAdministrationResultRow>(command);
            return row?.ToResult();
        }
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

    private static void AddAdministrationFilters(SearchInvitationsRequest request, ref string sql, DynamicParameters parameters)
    {
        AddScopeFilter(request.Tenant, request.IncludeAllTenants, ref sql, parameters);

        if (!string.IsNullOrWhiteSpace(request.EmailQuery))
        {
            sql += " AND normalized_email ILIKE @EmailQuery";
            parameters.Add("EmailQuery", $"%{IdentityNormalization.NormalizeEmail(request.EmailQuery)}%");
        }

        if (!string.IsNullOrWhiteSpace(request.Email))
        {
            sql += " AND normalized_email = @Email";
            parameters.Add("Email", IdentityNormalization.NormalizeEmail(request.Email));
        }

        if (request.Status != null)
        {
            sql += $" AND {StatusSql("@Now")} = @Status";
            parameters.Add("Status", (int)request.Status.Value);
        }

        AddRangeFilter("created_at", request.CreatedFrom, request.CreatedTo, "Created", ref sql, parameters);
        AddRangeFilter("accepted_at", request.AcceptedFrom, request.AcceptedTo, "Accepted", ref sql, parameters);
        AddRangeFilter("revoked_at", request.RevokedFrom, request.RevokedTo, "Revoked", ref sql, parameters);
        AddRangeFilter("expires_at", request.ExpiresFrom, request.ExpiresTo, "Expires", ref sql, parameters);
    }

    private static void AddScopeFilter(TenantContext? tenant, bool includeAllTenants, ref string sql, DynamicParameters parameters)
    {
        if (includeAllTenants)
        {
            return;
        }

        sql += tenant!.TenantId == null ? " AND tenant_id IS NULL" : " AND tenant_id = @TenantId";
        parameters.Add("TenantId", tenant.TenantId);
    }

    private static void AddRangeFilter(
        string column,
        DateTimeOffset? from,
        DateTimeOffset? to,
        string prefix,
        ref string sql,
        DynamicParameters parameters)
    {
        if (from.HasValue)
        {
            sql += $" AND {column} >= @{prefix}From";
            parameters.Add($"{prefix}From", from.Value);
        }

        if (to.HasValue)
        {
            sql += $" AND {column} <= @{prefix}To";
            parameters.Add($"{prefix}To", to.Value);
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

    private sealed record InvitationAdministrationSummaryRow(
        Guid Id,
        string Email,
        Guid? TenantId,
        int Status,
        DateTime CreatedAt,
        DateTime? UpdatedAt,
        DateTime ExpiresAt,
        DateTime? AcceptedAt,
        DateTime? RevokedAt)
    {
        public InvitationAdministrationSummary ToSummary()
        {
            return new InvitationAdministrationSummary(
                Id,
                Email,
                TenantId,
                (InvitationAdministrationStatus)Status,
                PostgresAdminQuery.ToDateTimeOffset(CreatedAt),
                PostgresAdminQuery.ToNullableDateTimeOffset(UpdatedAt),
                PostgresAdminQuery.ToDateTimeOffset(ExpiresAt),
                PostgresAdminQuery.ToNullableDateTimeOffset(AcceptedAt),
                PostgresAdminQuery.ToNullableDateTimeOffset(RevokedAt));
        }
    }

    private sealed record InvitationAdministrationDetailRow(
        Guid Id,
        string Email,
        Guid? TenantId,
        int Status,
        DateTime CreatedAt,
        DateTime? UpdatedAt,
        DateTime ExpiresAt,
        DateTime? AcceptedAt,
        DateTime? RevokedAt)
    {
        public InvitationAdministrationDetail ToDetail()
        {
            return new InvitationAdministrationDetail(
                Id,
                Email,
                TenantId,
                (InvitationAdministrationStatus)Status,
                PostgresAdminQuery.ToDateTimeOffset(CreatedAt),
                PostgresAdminQuery.ToNullableDateTimeOffset(UpdatedAt),
                PostgresAdminQuery.ToDateTimeOffset(ExpiresAt),
                PostgresAdminQuery.ToNullableDateTimeOffset(AcceptedAt),
                PostgresAdminQuery.ToNullableDateTimeOffset(RevokedAt));
        }
    }

    private sealed record RevokeInvitationAdministrationResultRow(
        Guid InvitationId,
        Guid? TenantId,
        bool Revoked,
        int Status,
        DateTime? RevokedAt)
    {
        public RevokeInvitationAdministrationResult ToResult()
        {
            return new RevokeInvitationAdministrationResult(
                InvitationId,
                TenantId,
                Revoked,
                (InvitationAdministrationStatus)Status,
                PostgresAdminQuery.ToNullableDateTimeOffset(RevokedAt));
        }
    }
}
