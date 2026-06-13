namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Represents a provider-neutral diagnostic result for Ashlar cleanup configuration.
/// </summary>
/// <param name="Status">Overall diagnostic <paramref name="Status" /> for cleanup configuration.</param>
/// <param name="ProviderName">Provider that produced the diagnostic result.</param>
/// <param name="Reason">Optional provider-safe reason when the check is unavailable, degraded, or failed.</param>
/// <param name="CheckedAt">UTC time the diagnostic was evaluated.</param>
/// <param name="Configured">Whether cleanup services are registered.</param>
/// <param name="OptionsValid">Whether cleanup options passed validation.</param>
/// <param name="CleanupInterval">Registered interval between cleanup runs.</param>
/// <param name="BatchSize">Maximum items cleaned per batch.</param>
/// <param name="MaxBatchesPerRun">Maximum batches processed during one cleanup run.</param>
/// <param name="DisabledCategoryCount">Number of cleanup categories explicitly disabled.</param>
/// <param name="EnabledCategoryCount">Number of cleanup categories enabled.</param>
public sealed record AshlarCleanupDiagnosticResult(
    AshlarDiagnosticStatus Status,
    string ProviderName,
    string? Reason,
    DateTimeOffset CheckedAt,
    bool Configured,
    bool OptionsValid,
    TimeSpan? CleanupInterval,
    int? BatchSize,
    int? MaxBatchesPerRun,
    int? DisabledCategoryCount,
    int? EnabledCategoryCount);
