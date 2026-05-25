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
        var data = Common(result.Status, result.ProviderName, result.Reason, result.CheckedAt);
        Add(data, "pending_count", result.PendingCount);
        Add(data, "scheduled_count", result.ScheduledCount);
        Add(data, "locked_count", result.LockedCount);
        Add(data, "expired_lock_count", result.ExpiredLockCount);
        Add(data, "failed_count", result.FailedCount);
        Add(data, "oldest_pending_at", result.OldestPendingAt);
        Add(data, "oldest_failed_at", result.OldestFailedAt);
        Add(data, "oldest_pending_age_seconds", result.OldestPendingAt.HasValue ? Math.Max(0, (result.CheckedAt - result.OldestPendingAt.Value).TotalSeconds) : null);
        Add(data, "max_attempts", result.MaxAttempts);
        Add(data, "polling_interval_seconds", result.PollingInterval?.TotalSeconds);
        Add(data, "batch_size", result.BatchSize);
        return data;
    }

    public static Dictionary<string, object> ForSecurityEventWebhookOutbox(SecurityEventWebhookOutboxDiagnosticResult result)
    {
        var data = Common(result.Status, result.ProviderName, result.Reason, result.CheckedAt);
        Add(data, "pending_count", result.PendingCount);
        Add(data, "scheduled_count", result.ScheduledCount);
        Add(data, "locked_count", result.LockedCount);
        Add(data, "expired_lock_count", result.ExpiredLockCount);
        Add(data, "failed_count", result.FailedCount);
        Add(data, "oldest_pending_at", result.OldestPendingAt);
        Add(data, "oldest_failed_at", result.OldestFailedAt);
        Add(data, "oldest_pending_age_seconds", result.OldestPendingAt.HasValue ? Math.Max(0, (result.CheckedAt - result.OldestPendingAt.Value).TotalSeconds) : null);
        Add(data, "max_attempts", result.MaxAttempts);
        Add(data, "polling_interval_seconds", result.PollingInterval?.TotalSeconds);
        Add(data, "batch_size", result.BatchSize);
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
