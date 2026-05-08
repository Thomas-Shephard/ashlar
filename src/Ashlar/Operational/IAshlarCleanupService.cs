namespace Ashlar.Operational;

/// <summary>
/// Removes expired or retained Ashlar operational data from the configured storage provider.
/// </summary>
public interface IAshlarCleanupService
{
    Task<AshlarCleanupResult> CleanupAsync(CancellationToken cancellationToken = default);
}
