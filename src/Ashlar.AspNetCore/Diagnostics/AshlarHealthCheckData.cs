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
        return data;
    }

    public static Dictionary<string, object> ForEmailOutbox(EmailOutboxDiagnosticResult result)
    {
        return ForOutbox(ToOutboxMetrics(result));
    }

    public static Dictionary<string, object> ForSecurityEventWebhookOutbox(SecurityEventWebhookOutboxDiagnosticResult result)
    {
        return ForOutbox(ToOutboxMetrics(result));
    }

    public static AshlarOutboxHealthCheckMetrics ToOutboxMetrics(EmailOutboxDiagnosticResult result)
    {
        return new AshlarOutboxHealthCheckMetrics
        {
            Status = result.Status,
            ProviderName = result.ProviderName,
            Reason = result.Reason,
            CheckedAt = result.CheckedAt,
            PendingCount = result.PendingCount,
            ScheduledCount = result.ScheduledCount,
            LockedCount = result.LockedCount,
            ExpiredLockCount = result.ExpiredLockCount,
            FailedCount = result.FailedCount,
            OldestPendingAt = result.OldestPendingAt,
            OldestFailedAt = result.OldestFailedAt,
            MaxAttempts = result.MaxAttempts,
            PollingInterval = result.PollingInterval,
            BatchSize = result.BatchSize
        };
    }

    public static AshlarOutboxHealthCheckMetrics ToOutboxMetrics(SecurityEventWebhookOutboxDiagnosticResult result)
    {
        return new AshlarOutboxHealthCheckMetrics
        {
            Status = result.Status,
            ProviderName = result.ProviderName,
            Reason = result.Reason,
            CheckedAt = result.CheckedAt,
            PendingCount = result.PendingCount,
            ScheduledCount = result.ScheduledCount,
            LockedCount = result.LockedCount,
            ExpiredLockCount = result.ExpiredLockCount,
            FailedCount = result.FailedCount,
            OldestPendingAt = result.OldestPendingAt,
            OldestFailedAt = result.OldestFailedAt,
            MaxAttempts = result.MaxAttempts,
            PollingInterval = result.PollingInterval,
            BatchSize = result.BatchSize
        };
    }

    private static Dictionary<string, object> ForOutbox(AshlarOutboxHealthCheckMetrics metrics)
    {
        var data = Common(metrics.Status, metrics.ProviderName, metrics.Reason, metrics.CheckedAt);
        Add(data, "pending_count", metrics.PendingCount);
        Add(data, "scheduled_count", metrics.ScheduledCount);
        Add(data, "locked_count", metrics.LockedCount);
        Add(data, "expired_lock_count", metrics.ExpiredLockCount);
        Add(data, "failed_count", metrics.FailedCount);
        Add(data, "oldest_pending_at", metrics.OldestPendingAt);
        Add(data, "oldest_failed_at", metrics.OldestFailedAt);
        Add(data, "oldest_pending_age_seconds", metrics.OldestPendingAt.HasValue ? Math.Max(0, (metrics.CheckedAt - metrics.OldestPendingAt.Value).TotalSeconds) : null);
        Add(data, "max_attempts", metrics.MaxAttempts);
        Add(data, "polling_interval_seconds", metrics.PollingInterval?.TotalSeconds);
        Add(data, "batch_size", metrics.BatchSize);
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
