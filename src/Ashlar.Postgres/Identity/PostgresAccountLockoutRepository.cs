using Dapper;

namespace Ashlar.Postgres.Identity;

internal sealed class PostgresAccountLockoutRepository(IPostgresConnectionProvider connectionProvider) : IAccountLockoutRepository
{
    private const string TenantIdName = "TenantId";

    private readonly IPostgresConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));

    public async Task<IReadOnlyList<AccountLockoutRecord>> SearchAsync(SearchAccountLockoutsRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        SearchAccountLockoutsRequest.ThrowIfInvalid(request);

        var conditions = new List<string>();
        var parameters = new DynamicParameters();
        parameters.Add("Limit", request.Limit);
        parameters.Add("Offset", request.Offset);
        if (request.Tenant is { } tenant)
        {
            conditions.Add(tenant.TenantId.HasValue ? "tenant_id = @TenantId" : "tenant_id IS NULL");
            parameters.Add(TenantIdName, tenant.TenantId);
        }

        if (request.UserId.HasValue)
        {
            conditions.Add("user_id = @UserId");
            parameters.Add("UserId", request.UserId);
        }

        if (request.Provider is { } provider)
        {
            conditions.Add("provider_type = @ProviderType");
            conditions.Add("provider_name = @ProviderName");
            parameters.Add("ProviderType", provider.StorageTypeValue);
            parameters.Add("ProviderName", provider.Name);
        }

        if (request.LockedOut is { } lockedOut)
        {
            conditions.Add(lockedOut ? "locked_until > @Now" : "(locked_until IS NULL OR locked_until <= @Now)");
            parameters.Add("Now", now);
        }

        var sql = SelectSql;
        if (conditions.Count > 0)
        {
            sql += $"{Environment.NewLine}WHERE {string.Join($"{Environment.NewLine}  AND ", conditions)}";
        }

        sql += """

            ORDER BY last_failed_at DESC, user_id, provider_type, provider_name
            LIMIT @Limit OFFSET @Offset
            """;

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, parameters, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var rows = await connectionHandle.Connection.QueryAsync(command);
            return rows.Select(ToRecord).ToList().AsReadOnly();
        }
    }

    public async Task<AccountLockoutRecord?> GetAsync(Guid userId, Guid? tenantId, AuthenticationProviderKey provider, CancellationToken cancellationToken = default)
    {
        ValidateUserId(userId);
        AuthenticationProviderKey.ThrowIfNotConfigured(provider, nameof(provider));

        const string sql = SelectSql + """

            WHERE user_id = @UserId
              AND tenant_id IS NOT DISTINCT FROM @TenantId
              AND provider_type = @ProviderType
              AND provider_name = @ProviderName
            """;

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, ToKeyParameters(userId, tenantId, provider), transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var row = await connectionHandle.Connection.QueryFirstOrDefaultAsync(command);
            return row == null ? null : ToRecord(row);
        }
    }

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
        AuthenticationProviderKey.ThrowIfNotConfigured(provider, nameof(provider));
        AccountLockoutOptions.ThrowIfInvalidPolicy(failureThreshold, lockoutDuration);

        const string sql = """
            INSERT INTO ashlar_account_lockouts (
                user_id, tenant_id, provider_type, provider_name, failed_attempt_count, first_failed_at, last_failed_at, locked_until, version)
            VALUES (
                @UserId, @TenantId, @ProviderType, @ProviderName, 1, @FailedAt, @FailedAt,
                CASE WHEN @FailureThreshold <= 1 THEN @LockedUntil ELSE NULL END,
                CASE WHEN @FailureThreshold <= 1 THEN @ActivationVersion ELSE @Version END)
            ON CONFLICT (user_id, tenant_id, provider_type, provider_name)
            DO UPDATE SET
                failed_attempt_count = CASE
                    WHEN ashlar_account_lockouts.locked_until IS NOT NULL AND ashlar_account_lockouts.locked_until <= @FailedAt THEN 1
                    ELSE ashlar_account_lockouts.failed_attempt_count + 1
                END,
                first_failed_at = CASE
                    WHEN ashlar_account_lockouts.locked_until IS NOT NULL AND ashlar_account_lockouts.locked_until <= @FailedAt THEN @FailedAt
                    ELSE ashlar_account_lockouts.first_failed_at
                END,
                last_failed_at = @FailedAt,
                locked_until = CASE
                    WHEN ashlar_account_lockouts.locked_until IS NOT NULL AND ashlar_account_lockouts.locked_until > @FailedAt THEN ashlar_account_lockouts.locked_until
                    WHEN (
                        CASE
                            WHEN ashlar_account_lockouts.locked_until IS NOT NULL AND ashlar_account_lockouts.locked_until <= @FailedAt THEN 1
                            ELSE ashlar_account_lockouts.failed_attempt_count + 1
                        END
                    ) >= @FailureThreshold THEN @LockedUntil
                    ELSE NULL
                END,
                version = CASE
                    WHEN ashlar_account_lockouts.locked_until IS NOT NULL AND ashlar_account_lockouts.locked_until > @FailedAt THEN @Version
                    WHEN (
                        CASE
                            WHEN ashlar_account_lockouts.locked_until IS NOT NULL AND ashlar_account_lockouts.locked_until <= @FailedAt THEN 1
                            ELSE ashlar_account_lockouts.failed_attempt_count + 1
                        END
                    ) >= @FailureThreshold THEN @ActivationVersion
                    ELSE @Version
                END
            RETURNING user_id AS UserId, tenant_id AS TenantId, provider_type AS ProviderType, provider_name AS ProviderName,
                      failed_attempt_count AS FailedAttemptCount, first_failed_at AS FirstFailedAt, last_failed_at AS LastFailedAt,
                      locked_until AS LockedUntil, version AS Version,
                      version = @ActivationVersion AS LockoutActivated
            """;

        var parameters = ToKeyParameters(userId, tenantId, provider);
        parameters.Add("FailedAt", failedAt);
        parameters.Add("FailureThreshold", failureThreshold);
        parameters.Add("LockedUntil", failedAt.Add(lockoutDuration));
        parameters.Add("Version", Guid.NewGuid().ToString("N"));
        parameters.Add("ActivationVersion", Guid.NewGuid().ToString("N"));

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, parameters, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var row = await connectionHandle.Connection.QuerySingleAsync(command);
            return ToUpdate(row);
        }
    }

    public async Task<bool> ResetAsync(Guid userId, Guid? tenantId, AuthenticationProviderKey provider, CancellationToken cancellationToken = default)
    {
        ValidateUserId(userId);
        AuthenticationProviderKey.ThrowIfNotConfigured(provider, nameof(provider));

        const string sql = """
            DELETE FROM ashlar_account_lockouts
            WHERE user_id = @UserId
              AND tenant_id IS NOT DISTINCT FROM @TenantId
              AND provider_type = @ProviderType
              AND provider_name = @ProviderName
            """;

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, ToKeyParameters(userId, tenantId, provider), transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            return await connectionHandle.Connection.ExecuteAsync(command) > 0;
        }
    }

    private const string SelectSql = """
        SELECT user_id AS UserId, tenant_id AS TenantId, provider_type AS ProviderType, provider_name AS ProviderName,
               failed_attempt_count AS FailedAttemptCount, first_failed_at AS FirstFailedAt, last_failed_at AS LastFailedAt,
               locked_until AS LockedUntil, version AS Version
        FROM ashlar_account_lockouts
        """;

    private static DynamicParameters ToKeyParameters(Guid userId, Guid? tenantId, AuthenticationProviderKey provider)
    {
        var parameters = new DynamicParameters();
        parameters.Add("UserId", userId);
        parameters.Add(TenantIdName, tenantId);
        parameters.Add("ProviderType", provider.StorageTypeValue);
        parameters.Add("ProviderName", provider.Name);
        return parameters;
    }

    private static AccountLockoutRecord ToRecord(dynamic row)
    {
        var values = new Dictionary<string, object?>((IDictionary<string, object?>)row, StringComparer.OrdinalIgnoreCase);
        return ToRecord(values);
    }

    private static AccountLockoutRecord ToRecord(Dictionary<string, object?> values)
    {
        ProviderType providerType = (string)values["ProviderType"]!;
        return new AccountLockoutRecord(
            (Guid)values["UserId"]!,
            values[TenantIdName] == null ? null : (Guid?)values[TenantIdName],
            new AuthenticationProviderKey(providerType, (string)values["ProviderName"]!),
            (int)values["FailedAttemptCount"]!,
            ToDateTimeOffset(values["FirstFailedAt"]!),
            ToDateTimeOffset(values["LastFailedAt"]!),
            values["LockedUntil"] == null ? null : ToDateTimeOffset(values["LockedUntil"]!),
            (string)values["Version"]!);
    }

    private static AccountLockoutRecordUpdate ToUpdate(dynamic row)
    {
        var values = new Dictionary<string, object?>((IDictionary<string, object?>)row, StringComparer.OrdinalIgnoreCase);
        return new AccountLockoutRecordUpdate(ToRecord(values), (bool)values["LockoutActivated"]!);
    }

    private static DateTimeOffset ToDateTimeOffset(object value)
    {
        return new DateTimeOffset((DateTime)value);
    }

    private static void ValidateUserId(Guid userId)
    {
        if (userId == Guid.Empty)
        {
            throw new ArgumentException("User ID cannot be empty.", nameof(userId));
        }
    }
}
