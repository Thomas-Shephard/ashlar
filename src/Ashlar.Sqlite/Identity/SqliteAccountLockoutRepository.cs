using Microsoft.Data.Sqlite;

namespace Ashlar.Sqlite.Identity;

/// <summary>
/// Stores account lockout state in SQLite.
/// </summary>
/// <param name="connectionProvider">The connection provider.</param>
public sealed class SqliteAccountLockoutRepository(ISqliteConnectionProvider connectionProvider) : IAccountLockoutRepository
{
    private const string UserIdParameter = "$userId";
    private const string TenantIdParameter = "$tenantId";
    private const string ProviderTypeParameter = "$providerType";
    private const string ProviderNameParameter = "$providerName";
    private const string FailedAtParameter = "$failedAt";
    private const string FailureThresholdParameter = "$failureThreshold";
    private const string LockedUntilParameter = "$lockedUntil";
    private const string VersionParameter = "$version";
    private const string LimitParameter = "$limit";
    private const string OffsetParameter = "$offset";
    private readonly ISqliteConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));

    /// <summary>
    /// Searches stored automatic lockout state.
    /// </summary>
    /// <param name="request">The search request.</param>
    /// <param name="now">The timestamp used for active lockout filtering.</param>
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
    /// <returns>The matching lockout records.</returns>
    public async Task<IReadOnlyList<AccountLockoutRecord>> SearchAsync(SearchAccountLockoutsRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        SearchAccountLockoutsRequest.ThrowIfInvalid(request);

        var conditions = new List<string>();
        if (request.Tenant is { } tenant)
        {
            conditions.Add(tenant.TenantId.HasValue ? "tenant_id = $tenantId" : "tenant_id IS NULL");
        }

        if (request.UserId.HasValue)
        {
            conditions.Add("user_id = $userId");
        }

        if (request.Provider.HasValue)
        {
            conditions.Add("provider_type = $providerType");
            conditions.Add("provider_name = $providerName");
        }

        if (request.LockedOut is { } lockedOut)
        {
            conditions.Add(lockedOut ? "locked_until > $now" : "(locked_until IS NULL OR locked_until <= $now)");
        }

        var sql = SelectSql;
        if (conditions.Count > 0)
        {
            sql += $"{Environment.NewLine}WHERE {string.Join($"{Environment.NewLine}  AND ", conditions)}";
        }

        sql += """

            ORDER BY last_failed_at DESC, user_id, provider_type, provider_name
            LIMIT $limit OFFSET $offset;
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        AddSearchParameters(command, request, now);

        var records = new List<AccountLockoutRecord>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            records.Add(ReadRecord(reader));
        }

        return records.AsReadOnly();
    }

    /// <summary>
    /// Retrieves lockout state for a user, tenant, and provider.
    /// </summary>
    /// <param name="userId">The user id.</param>
    /// <param name="tenantId">The tenant id, or <see langword="null" /> for a global user.</param>
    /// <param name="provider">The provider key.</param>
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
    /// <returns>The matching lockout record, or <see langword="null" />.</returns>
    public async Task<AccountLockoutRecord?> GetAsync(Guid userId, Guid? tenantId, AuthenticationProviderKey provider, CancellationToken cancellationToken = default)
    {
        ValidateUserId(userId);
        AuthenticationProviderKey.ThrowIfUninitialized(provider, nameof(provider));

        var sql = SelectSql + """

            WHERE user_id = $userId
              AND provider_type = $providerType
              AND provider_name = $providerName
            """;
        sql += tenantId.HasValue ? "  AND tenant_id = $tenantId;" : "  AND tenant_id IS NULL;";

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        AddKeyParameters(command, userId, tenantId, provider);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadRecord(reader) : null;
    }

    /// <summary>
    /// Atomically records a failed credential verification.
    /// </summary>
    /// <param name="userId">The user id.</param>
    /// <param name="tenantId">The tenant id, or <see langword="null" /> for a global user.</param>
    /// <param name="provider">The provider key.</param>
    /// <param name="failedAt">The failure timestamp.</param>
    /// <param name="failureThreshold">The automatic lockout threshold.</param>
    /// <param name="lockoutDuration">The automatic lockout duration.</param>
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
    /// <returns>The updated lockout record and whether this write activated a new automatic lockout.</returns>
    public async Task<AccountLockoutRecordUpdate> RecordFailureAsync(
        Guid userId,
        Guid? tenantId,
        AuthenticationProviderKey provider,
        DateTimeOffset failedAt,
        int failureThreshold,
        TimeSpan lockoutDuration,
        CancellationToken cancellationToken = default)
    {
        ValidateUserId(userId);
        AuthenticationProviderKey.ThrowIfUninitialized(provider, nameof(provider));
        AccountLockoutOptions.ThrowIfInvalidPolicy(failureThreshold, lockoutDuration);

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = tenantId.HasValue ? RecordTenantScopedFailureSql : RecordGlobalFailureSql;
        AddKeyParameters(command, userId, tenantId, provider);
        command.AddDateTimeOffsetParameter(FailedAtParameter, failedAt);
        command.AddParameter(FailureThresholdParameter, failureThreshold);
        command.AddDateTimeOffsetParameter(LockedUntilParameter, failedAt.Add(lockoutDuration));
        command.AddParameter(VersionParameter, Guid.NewGuid().ToString("N"));
        command.AddParameter("$activationVersion", Guid.NewGuid().ToString("N"));

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        await reader.ReadAsync(cancellationToken);
        return ReadUpdate(reader);
    }

    /// <summary>
    /// Clears stored automatic lockout failures.
    /// </summary>
    /// <param name="userId">The user id.</param>
    /// <param name="tenantId">The tenant id, or <see langword="null" /> for a global user.</param>
    /// <param name="provider">The provider key.</param>
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
    /// <returns><see langword="true" /> when stored state was removed.</returns>
    public async Task<bool> ResetAsync(Guid userId, Guid? tenantId, AuthenticationProviderKey provider, CancellationToken cancellationToken = default)
    {
        ValidateUserId(userId);
        AuthenticationProviderKey.ThrowIfUninitialized(provider, nameof(provider));

        var sql = """
            DELETE FROM ashlar_account_lockouts
            WHERE user_id = $userId
              AND provider_type = $providerType
              AND provider_name = $providerName
            """;
        sql += tenantId.HasValue ? "  AND tenant_id = $tenantId;" : "  AND tenant_id IS NULL;";

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        AddKeyParameters(command, userId, tenantId, provider);
        return await command.ExecuteNonQueryAsync(cancellationToken) > 0;
    }

    private const string SelectSql = """
        SELECT user_id, tenant_id, provider_type, provider_name, failed_attempt_count, first_failed_at, last_failed_at, locked_until, version
        FROM ashlar_account_lockouts
        """;

    private const string RecordTenantScopedFailureSql = """
        INSERT INTO ashlar_account_lockouts (
            user_id, tenant_id, provider_type, provider_name, failed_attempt_count, first_failed_at, last_failed_at, locked_until, version)
        VALUES (
            $userId, $tenantId, $providerType, $providerName, 1, $failedAt, $failedAt,
            CASE WHEN $failureThreshold <= 1 THEN $lockedUntil ELSE NULL END,
            CASE WHEN $failureThreshold <= 1 THEN $activationVersion ELSE $version END)
        ON CONFLICT (user_id, tenant_id, provider_type, provider_name) WHERE tenant_id IS NOT NULL
        DO UPDATE SET
            failed_attempt_count = CASE
                WHEN locked_until IS NOT NULL AND locked_until <= $failedAt THEN 1
                ELSE failed_attempt_count + 1
            END,
            first_failed_at = CASE
                WHEN locked_until IS NOT NULL AND locked_until <= $failedAt THEN $failedAt
                ELSE first_failed_at
            END,
            last_failed_at = $failedAt,
            locked_until = CASE
                WHEN locked_until IS NOT NULL AND locked_until > $failedAt THEN locked_until
                WHEN (
                    CASE
                        WHEN locked_until IS NOT NULL AND locked_until <= $failedAt THEN 1
                        ELSE failed_attempt_count + 1
                    END
                ) >= $failureThreshold THEN $lockedUntil
                ELSE NULL
            END,
            version = CASE
                WHEN locked_until IS NOT NULL AND locked_until > $failedAt THEN $version
                WHEN (
                    CASE
                        WHEN locked_until IS NOT NULL AND locked_until <= $failedAt THEN 1
                        ELSE failed_attempt_count + 1
                    END
                ) >= $failureThreshold THEN $activationVersion
                ELSE $version
            END
        RETURNING user_id, tenant_id, provider_type, provider_name, failed_attempt_count, first_failed_at, last_failed_at, locked_until, version,
                  version = $activationVersion AS lockout_activated;
        """;

    private const string RecordGlobalFailureSql = """
        INSERT INTO ashlar_account_lockouts (
            user_id, tenant_id, provider_type, provider_name, failed_attempt_count, first_failed_at, last_failed_at, locked_until, version)
        VALUES (
            $userId, NULL, $providerType, $providerName, 1, $failedAt, $failedAt,
            CASE WHEN $failureThreshold <= 1 THEN $lockedUntil ELSE NULL END,
            CASE WHEN $failureThreshold <= 1 THEN $activationVersion ELSE $version END)
        ON CONFLICT (user_id, provider_type, provider_name) WHERE tenant_id IS NULL
        DO UPDATE SET
            failed_attempt_count = CASE
                WHEN locked_until IS NOT NULL AND locked_until <= $failedAt THEN 1
                ELSE failed_attempt_count + 1
            END,
            first_failed_at = CASE
                WHEN locked_until IS NOT NULL AND locked_until <= $failedAt THEN $failedAt
                ELSE first_failed_at
            END,
            last_failed_at = $failedAt,
            locked_until = CASE
                WHEN locked_until IS NOT NULL AND locked_until > $failedAt THEN locked_until
                WHEN (
                    CASE
                        WHEN locked_until IS NOT NULL AND locked_until <= $failedAt THEN 1
                        ELSE failed_attempt_count + 1
                    END
                ) >= $failureThreshold THEN $lockedUntil
                ELSE NULL
            END,
            version = CASE
                WHEN locked_until IS NOT NULL AND locked_until > $failedAt THEN $version
                WHEN (
                    CASE
                        WHEN locked_until IS NOT NULL AND locked_until <= $failedAt THEN 1
                        ELSE failed_attempt_count + 1
                    END
                ) >= $failureThreshold THEN $activationVersion
                ELSE $version
            END
        RETURNING user_id, tenant_id, provider_type, provider_name, failed_attempt_count, first_failed_at, last_failed_at, locked_until, version,
                  version = $activationVersion AS lockout_activated;
        """;

    private static void AddKeyParameters(SqliteCommand command, Guid userId, Guid? tenantId, AuthenticationProviderKey provider)
    {
        command.AddGuidParameter(UserIdParameter, userId);
        command.AddNullableGuidParameter(TenantIdParameter, tenantId);
        command.AddParameter(ProviderTypeParameter, provider.TypeValueOrUnknown);
        command.AddParameter(ProviderNameParameter, provider.Name);
    }

    private static void AddSearchParameters(SqliteCommand command, SearchAccountLockoutsRequest request, DateTimeOffset now)
    {
        command.AddParameter(LimitParameter, request.Limit);
        command.AddParameter(OffsetParameter, request.Offset);
        if (request.LockedOut.HasValue)
        {
            command.AddDateTimeOffsetParameter("$now", now);
        }

        if (request.Tenant?.TenantId is { } tenantId)
        {
            command.AddGuidParameter(TenantIdParameter, tenantId);
        }

        if (request.UserId is { } userId)
        {
            command.AddGuidParameter(UserIdParameter, userId);
        }

        if (request.Provider is { } provider)
        {
            command.AddParameter(ProviderTypeParameter, provider.TypeValueOrUnknown);
            command.AddParameter(ProviderNameParameter, provider.Name);
        }
    }

    private static AccountLockoutRecord ReadRecord(SqliteDataReader reader)
    {
        ProviderType providerType = reader.GetString(reader.GetOrdinal("provider_type"));
        return new AccountLockoutRecord(
            reader.GetGuidFromText("user_id"),
            reader.GetNullableGuidFromText("tenant_id"),
            new AuthenticationProviderKey(providerType, reader.GetString(reader.GetOrdinal("provider_name"))),
            reader.GetInt32ByName("failed_attempt_count"),
            reader.GetDateTimeOffsetFromText("first_failed_at"),
            reader.GetDateTimeOffsetFromText("last_failed_at"),
            reader.GetNullableDateTimeOffsetFromText("locked_until"),
            reader.GetString(reader.GetOrdinal("version")));
    }

    private static AccountLockoutRecordUpdate ReadUpdate(SqliteDataReader reader)
    {
        return new AccountLockoutRecordUpdate(
            ReadRecord(reader),
            Convert.ToBoolean(reader.GetInt32ByName("lockout_activated"), System.Globalization.CultureInfo.InvariantCulture));
    }

    private static void ValidateUserId(Guid userId)
    {
        if (userId == Guid.Empty)
        {
            throw new ArgumentException("User ID cannot be empty.", nameof(userId));
        }
    }
}
