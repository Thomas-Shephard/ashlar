namespace Ashlar.Identity.Abstractions.Repositories;

/// <summary>
/// Stores whether initial Ashlar bootstrap has completed.
/// </summary>
public interface IBootstrapStateRepository
{
    /// <summary>
    /// Reads whether first-admin bootstrap has already initialized the installation.
    /// </summary>
    /// <param name="cancellationToken">A token that can cancel status lookup.</param>
    /// <returns>Current bootstrap initialization state.</returns>
    Task<BootstrapStatus> GetBootstrapStatusAsync(CancellationToken cancellationToken = default);
    /// <summary>
    /// Marks bootstrap as initialized by the supplied user.
    /// </summary>
    /// <param name="userId">User that completed bootstrap.</param>
    /// <param name="initializedAt">UTC time when bootstrap completed.</param>
    /// <param name="cancellationToken">A token that can cancel the update.</param>
    /// <returns><see langword="true" /> when bootstrap state changed to initialized.</returns>
    Task<bool> MarkAsInitializedAsync(Guid userId, DateTimeOffset initializedAt, CancellationToken cancellationToken = default);
}
