namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Composes Ashlar operational diagnostics into one provider-neutral read-only summary.
/// </summary>
/// <remarks>
/// This public read does not authorize callers because it exposes only low-sensitivity aggregate health and
/// configuration data: statuses, timestamps, counts, booleans, intervals, batch limits, and schema state.
/// It never projects diagnostic provider names or reasons, migration names or provider versions, raw identifiers,
/// tenant or user data, payloads, secrets, endpoint URIs, provider exceptions, lock owners, or row data.
/// </remarks>
public interface IAshlarOperationsSummaryService
{
    /// <summary>
    /// Checks configured Ashlar diagnostic areas and returns a dashboard-friendly operational summary.
    /// </summary>
    /// <param name="cancellationToken">Token for aborting diagnostics work.</param>
    /// <returns>A provider-neutral operational summary built from safe diagnostic results.</returns>
    Task<AshlarOperationsSummary> GetSummaryAsync(CancellationToken cancellationToken = default);
}
