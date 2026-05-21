namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Provides shared cleanup diagnostics result mapping for Ashlar persistence providers.
/// </summary>
/// <param name="providerName">The provider name value.</param>
public sealed class AshlarCleanupDiagnosticsRunner(string providerName)
{
    private const string NotConfiguredReason = "Ashlar cleanup services are not configured.";
    private const string InvalidOptionsReason = "Ashlar cleanup options are invalid.";

    /// <summary>
    /// Checks cleanup configuration and returns a sanitized diagnostics result.
    /// </summary>
    /// <param name="timeProvider">The time provider value.</param>
    /// <param name="options">The cleanup options, or <see langword="null" /> when cleanup is not configured.</param>
    /// <param name="configured">Whether cleanup services are configured.</param>
    /// <returns>The diagnostic result.</returns>
    public AshlarCleanupDiagnosticResult Check(
        TimeProvider timeProvider,
        AshlarCleanupOptions? options,
        bool configured)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);

        var checkedAt = timeProvider.GetUtcNow();
        if (!configured || options == null)
        {
            return new AshlarCleanupDiagnosticResult(
                AshlarDiagnosticStatus.NotSupported,
                providerName,
                NotConfiguredReason,
                checkedAt,
                false,
                false,
                null,
                null,
                null,
                null,
                null);
        }

        var optionsValid = AshlarCleanupOptions.Validate(options);
        var (enabledCategoryCount, disabledCategoryCount) = AshlarCleanupPlan.CountCategories(options);

        return new AshlarCleanupDiagnosticResult(
            optionsValid ? AshlarDiagnosticStatus.Healthy : AshlarDiagnosticStatus.Unhealthy,
            providerName,
            optionsValid ? null : InvalidOptionsReason,
            checkedAt,
            true,
            optionsValid,
            options.CleanupInterval,
            options.BatchSize,
            options.MaxBatchesPerRun,
            disabledCategoryCount,
            enabledCategoryCount);
    }
}
