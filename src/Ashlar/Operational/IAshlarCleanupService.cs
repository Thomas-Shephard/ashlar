namespace Ashlar.Operational;

/// <summary>
/// Removes expired or retained Ashlar operational data from the configured storage provider.
/// </summary>
public interface IAshlarCleanupService
{
    /// <summary>
    /// Removes expired or retained operational records according to provider cleanup policy.
    /// </summary>
    /// <param name="cancellationToken">A token that can cancel cleanup execution.</param>
    /// <returns>Counts for records removed or discarded by cleanup.</returns>
    /// <remarks>
    /// Providers with Ashlar transaction support join the active scoped transaction when one exists; otherwise
    /// cleanup runs on a fresh provider connection.
    /// </remarks>
    Task<AshlarCleanupResult> CleanupAsync(CancellationToken cancellationToken = default);
}
