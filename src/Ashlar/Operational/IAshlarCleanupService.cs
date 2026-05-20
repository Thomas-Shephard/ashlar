namespace Ashlar.Operational;

/// <summary>
/// Removes expired or retained Ashlar operational data from the configured storage provider.
/// </summary>
public interface IAshlarCleanupService
{
    /// <summary>
    /// Performs the cleanup <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<AshlarCleanupResult> CleanupAsync(CancellationToken cancellationToken = default);
}
