using Ashlar.Operational.Diagnostics;

namespace Ashlar.AspNetCore.Diagnostics;

internal static class AshlarHealthCheckData
{
    public static Dictionary<string, object> ForSchema(AshlarSchemaDiagnosticResult result)
    {
        var data = Common(result.Status, result.ProviderName, result.Reason, result.CheckedAt);
        Add(data, "schema_status", result.SchemaStatus.ToString());
        Add(data, "applied_migration_count", result.AppliedMigrationCount);
        Add(data, "expected_migration_count", result.ExpectedMigrationCount);
        Add(data, "missing_migration_count", result.MissingMigrationCount);
        Add(data, "latest_applied_migration_name", result.LatestAppliedMigrationName);
        Add(data, "latest_expected_migration_name", result.LatestExpectedMigrationName);
        Add(data, "minimum_provider_version", result.MinimumProviderVersion);
        Add(data, "provider_version", result.ProviderVersion);
        return data;
    }

    public static Dictionary<string, object> ForEmailOutbox(EmailOutboxDiagnosticResult result)
    {
        return ForOutbox(
            result.Status,
            result.ProviderName,
            result.Reason,
            result.CheckedAt,
            result.PendingCount,
            result.ScheduledCount,
            result.LockedCount,
            result.ExpiredLockCount,
            result.FailedCount,
            result.OldestPendingAt,
            result.OldestFailedAt,
            result.MaxAttempts,
            result.PollingInterval,
            result.BatchSize);
    }

    public static Dictionary<string, object> ForSecurityEventWebhookOutbox(SecurityEventWebhookOutboxDiagnosticResult result)
    {
        return ForOutbox(
            result.Status,
            result.ProviderName,
            result.Reason,
            result.CheckedAt,
            result.PendingCount,
            result.ScheduledCount,
            result.LockedCount,
            result.ExpiredLockCount,
            result.FailedCount,
            result.OldestPendingAt,
            result.OldestFailedAt,
            result.MaxAttempts,
            result.PollingInterval,
            result.BatchSize);
    }

    private static Dictionary<string, object> ForOutbox(
        AshlarDiagnosticStatus status,
        string providerName,
        string? reason,
        DateTimeOffset checkedAt,
        long? pendingCount,
        long? scheduledCount,
        long? lockedCount,
        long? expiredLockCount,
        long? failedCount,
        DateTimeOffset? oldestPendingAt,
        DateTimeOffset? oldestFailedAt,
        int? maxAttempts,
        TimeSpan? pollingInterval,
        int? batchSize)
    {
        var data = Common(status, providerName, reason, checkedAt);
        Add(data, "pending_count", pendingCount);
        Add(data, "scheduled_count", scheduledCount);
        Add(data, "locked_count", lockedCount);
        Add(data, "expired_lock_count", expiredLockCount);
        Add(data, "failed_count", failedCount);
        Add(data, "oldest_pending_at", oldestPendingAt);
        Add(data, "oldest_failed_at", oldestFailedAt);
        Add(data, "oldest_pending_age_seconds", oldestPendingAt.HasValue ? Math.Max(0, (checkedAt - oldestPendingAt.Value).TotalSeconds) : null);
        Add(data, "max_attempts", maxAttempts);
        Add(data, "polling_interval_seconds", pollingInterval?.TotalSeconds);
        Add(data, "batch_size", batchSize);
        return data;
    }

    public static Dictionary<string, object> ForCleanup(AshlarCleanupDiagnosticResult result)
    {
        var data = Common(result.Status, result.ProviderName, result.Reason, result.CheckedAt);
        Add(data, "configured", result.Configured);
        Add(data, "options_valid", result.OptionsValid);
        Add(data, "cleanup_interval_seconds", result.CleanupInterval?.TotalSeconds);
        Add(data, "batch_size", result.BatchSize);
        Add(data, "max_batches_per_run", result.MaxBatchesPerRun);
        Add(data, "disabled_category_count", result.DisabledCategoryCount);
        Add(data, "enabled_category_count", result.EnabledCategoryCount);
        return data;
    }

    public static Dictionary<string, object> ForRateLimiter(AuthenticationRateLimiterDiagnosticResult result)
    {
        var data = Common(result.Status, result.ProviderName, result.Reason, result.CheckedAt);
        Add(data, "configured", result.Configured);
        Add(data, "distributed", result.Distributed);
        Add(data, "persistent", result.Persistent);
        Add(data, "expired_row_count", result.ExpiredRowCount);
        Add(data, "active_key_count", result.ActiveKeyCount);
        Add(data, "blocked_key_count", result.BlockedKeyCount);
        Add(data, "cleanup_configured", result.CleanupConfigured);
        Add(data, "cleanup_interval_seconds", result.CleanupInterval?.TotalSeconds);
        Add(data, "max_cleanup_rows", result.MaxCleanupRows);
        return data;
    }

    private static Dictionary<string, object> Common(
        AshlarDiagnosticStatus status,
        string providerName,
        string? reason,
        DateTimeOffset checkedAt)
    {
        var data = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["diagnostic_status"] = status.ToString(),
            ["provider_name"] = providerName,
            ["checked_at"] = checkedAt
        };
        Add(data, "reason", reason);
        return data;
    }

    private static void Add(Dictionary<string, object> data, string key, object? value)
    {
        if (value is not null)
        {
            data[key] = value;
        }
    }
}
