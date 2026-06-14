namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Represents a provider-neutral operational summary for Ashlar diagnostics.
/// </summary>
/// <param name="Status">Conservative overall status derived from child diagnostic statuses.</param>
/// <param name="CheckedAt">UTC time when the summary was assembled.</param>
/// <param name="Schema">Storage schema diagnostic summary.</param>
/// <param name="Cleanup">Cleanup configuration diagnostic summary.</param>
/// <param name="AuthenticationRateLimiter">Authentication rate limiter diagnostic summary.</param>
/// <param name="EmailOutbox">Email outbox diagnostic summary.</param>
/// <param name="SecurityEventWebhookOutbox">Security-event webhook outbox diagnostic summary.</param>
/// <param name="Issues">Safe component issue summaries for diagnostics needing attention.</param>
public sealed record AshlarOperationsSummary(
    AshlarDiagnosticStatus Status,
    DateTimeOffset CheckedAt,
    AshlarSchemaOperationsSummary Schema,
    AshlarCleanupOperationsSummary Cleanup,
    AshlarAuthenticationRateLimiterOperationsSummary AuthenticationRateLimiter,
    AshlarOutboxOperationsSummary EmailOutbox,
    AshlarOutboxOperationsSummary SecurityEventWebhookOutbox,
    IReadOnlyList<AshlarOperationsIssue> Issues);

/// <summary>
/// Describes a diagnostic area that needs attention using safe provider-neutral text.
/// </summary>
/// <param name="Component">Stable component name.</param>
/// <param name="Status">Diagnostic status reported for <paramref name="Component" />.</param>
/// <param name="Reason">Optional safe reason reported for <paramref name="Component" />.</param>
public sealed record AshlarOperationsIssue(
    string Component,
    AshlarDiagnosticStatus Status,
    string? Reason);

/// <summary>
/// Represents common safe fields included for every Ashlar operations summary section.
/// </summary>
/// <param name="Status">Diagnostic status for the component.</param>
/// <param name="ProviderName">Provider that produced the diagnostic result, when available.</param>
/// <param name="CheckedAt">UTC time when the component diagnostic was evaluated.</param>
/// <param name="Reason">Optional safe reason reported by the component.</param>
public abstract record AshlarOperationsComponentSummary(
    AshlarDiagnosticStatus Status,
    string? ProviderName,
    DateTimeOffset CheckedAt,
    string? Reason);

/// <summary>
/// Summarizes safe storage schema diagnostics for Ashlar operations views.
/// </summary>
/// <param name="Status">Diagnostic status for the schema component.</param>
/// <param name="ProviderName">Persistence provider that produced the diagnostic result, when available.</param>
/// <param name="CheckedAt">UTC time when the schema diagnostic was evaluated.</param>
/// <param name="Reason">Optional safe reason reported by the schema diagnostic.</param>
/// <param name="SchemaStatus">Provider-neutral schema state.</param>
/// <param name="AppliedMigrationCount">Number of migrations already applied by the provider.</param>
/// <param name="ExpectedMigrationCount">Number of migrations expected by the current Ashlar package.</param>
/// <param name="MissingMigrationCount">Number of expected migrations not yet applied.</param>
public sealed record AshlarSchemaOperationsSummary(
    AshlarDiagnosticStatus Status,
    string? ProviderName,
    DateTimeOffset CheckedAt,
    string? Reason,
    AshlarSchemaStatus SchemaStatus,
    int? AppliedMigrationCount,
    int? ExpectedMigrationCount,
    int? MissingMigrationCount) : AshlarOperationsComponentSummary(Status, ProviderName, CheckedAt, Reason);

/// <summary>
/// Summarizes safe cleanup diagnostics for Ashlar operations views.
/// </summary>
/// <param name="Status">Diagnostic status for the cleanup component.</param>
/// <param name="ProviderName">Provider that produced the diagnostic result, when available.</param>
/// <param name="CheckedAt">UTC time when the cleanup diagnostic was evaluated.</param>
/// <param name="Reason">Optional safe reason reported by the cleanup diagnostic.</param>
/// <param name="Configured">Whether cleanup services are registered.</param>
/// <param name="OptionsValid">Whether cleanup options passed validation.</param>
/// <param name="CleanupInterval">Registered interval between cleanup runs.</param>
/// <param name="BatchSize">Maximum items cleaned per batch.</param>
/// <param name="MaxBatchesPerRun">Maximum batches processed during one cleanup run.</param>
/// <param name="EnabledCategoryCount">Number of cleanup categories enabled.</param>
/// <param name="DisabledCategoryCount">Number of cleanup categories explicitly disabled.</param>
public sealed record AshlarCleanupOperationsSummary(
    AshlarDiagnosticStatus Status,
    string? ProviderName,
    DateTimeOffset CheckedAt,
    string? Reason,
    bool Configured,
    bool OptionsValid,
    TimeSpan? CleanupInterval,
    int? BatchSize,
    int? MaxBatchesPerRun,
    int? EnabledCategoryCount,
    int? DisabledCategoryCount) : AshlarOperationsComponentSummary(Status, ProviderName, CheckedAt, Reason);

/// <summary>
/// Summarizes safe authentication rate limiter diagnostics for Ashlar operations views.
/// </summary>
/// <param name="Status">Diagnostic status for the rate limiter component.</param>
/// <param name="ProviderName">Provider that produced the diagnostic result, when available.</param>
/// <param name="CheckedAt">UTC time when the rate limiter diagnostic was evaluated.</param>
/// <param name="Reason">Optional safe reason reported by the rate limiter diagnostic.</param>
/// <param name="Configured">Whether rate limiter services are registered.</param>
/// <param name="Distributed">Whether the limiter coordinates attempts across app instances.</param>
/// <param name="Persistent">Whether limiter state survives process restarts.</param>
/// <param name="ExpiredRowCount">Expired limiter rows observed by providers that can report them.</param>
/// <param name="ActiveKeyCount">Active limiter keys observed by providers that can report them.</param>
/// <param name="BlockedKeyCount">Blocked limiter keys observed by providers that can report them.</param>
/// <param name="CleanupConfigured">Whether rate limiter cleanup scheduling is enabled.</param>
/// <param name="CleanupInterval">Registered cleanup interval, when cleanup is enabled.</param>
/// <param name="MaxCleanupRows">Maximum rows cleaned per cleanup pass, when applicable.</param>
public sealed record AshlarAuthenticationRateLimiterOperationsSummary(
    AshlarDiagnosticStatus Status,
    string? ProviderName,
    DateTimeOffset CheckedAt,
    string? Reason,
    bool Configured,
    bool Distributed,
    bool Persistent,
    long? ExpiredRowCount,
    long? ActiveKeyCount,
    long? BlockedKeyCount,
    bool? CleanupConfigured,
    TimeSpan? CleanupInterval,
    int? MaxCleanupRows) : AshlarOperationsComponentSummary(Status, ProviderName, CheckedAt, Reason);

/// <summary>
/// Summarizes safe outbox diagnostics for Ashlar operations views.
/// </summary>
/// <param name="Status">Diagnostic status for the outbox component.</param>
/// <param name="ProviderName">Provider that produced the diagnostic result, when available.</param>
/// <param name="CheckedAt">UTC time when the outbox diagnostic was evaluated.</param>
/// <param name="Reason">Optional safe reason reported by the outbox diagnostic.</param>
/// <param name="PendingCount">Number of items ready for delivery.</param>
/// <param name="ScheduledCount">Number of items scheduled for future delivery.</param>
/// <param name="LockedCount">Number of items currently locked by a dispatcher.</param>
/// <param name="ExpiredLockCount">Number of locked items whose delivery lock has expired.</param>
/// <param name="FailedCount">Number of items that exhausted delivery attempts.</param>
/// <param name="OldestPendingAt">Oldest pending item timestamp, when available.</param>
/// <param name="OldestFailedAt">Oldest failed item timestamp, when available.</param>
/// <param name="MaxAttempts">Configured maximum delivery attempts.</param>
/// <param name="PollingInterval">Configured dispatcher polling interval.</param>
/// <param name="BatchSize">Configured dispatcher batch size.</param>
public sealed record AshlarOutboxOperationsSummary(
    AshlarDiagnosticStatus Status,
    string? ProviderName,
    DateTimeOffset CheckedAt,
    string? Reason,
    long? PendingCount,
    long? ScheduledCount,
    long? LockedCount,
    long? ExpiredLockCount,
    long? FailedCount,
    DateTimeOffset? OldestPendingAt,
    DateTimeOffset? OldestFailedAt,
    int? MaxAttempts,
    TimeSpan? PollingInterval,
    int? BatchSize) : AshlarOperationsComponentSummary(Status, ProviderName, CheckedAt, Reason);
