namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Represents a provider-neutral diagnostic result for Ashlar cleanup configuration.
/// </summary>
/// <param name="Status">The diagnostic status value.</param>
/// <param name="ProviderName">The provider name value.</param>
/// <param name="Reason">The reason value.</param>
/// <param name="CheckedAt">The checked at value.</param>
/// <param name="Configured">The configured value.</param>
/// <param name="OptionsValid">The options valid value.</param>
/// <param name="CleanupInterval">The cleanup interval value.</param>
/// <param name="BatchSize">The batch size value.</param>
/// <param name="MaxBatchesPerRun">The max batches per run value.</param>
/// <param name="DisabledCategoryCount">The disabled category count value.</param>
/// <param name="EnabledCategoryCount">The enabled category count value.</param>
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
