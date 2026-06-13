namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Provides shared cleanup diagnostics result mapping for Ashlar persistence providers.
/// </summary>
/// <param name="providerName">Persistence provider name reported in diagnostic results.</param>
public sealed class AshlarCleanupDiagnosticsRunner(string providerName)
{
    private const string NotConfiguredReason = "Ashlar cleanup services are not configured.";
    private const string InvalidOptionsReason = "Ashlar cleanup options are invalid.";

    /// <summary>
    /// Checks cleanup configuration and returns a sanitized diagnostics result.
    /// </summary>
    /// <param name="timeProvider">Clock used to stamp the diagnostic result.</param>
    /// <param name="options">Cleanup configuration to validate, or <see langword="null" /> when cleanup is not configured.</param>
    /// <param name="configured">Whether cleanup services are configured.</param>
    /// <returns>Provider-neutral cleanup diagnostic result.</returns>
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
