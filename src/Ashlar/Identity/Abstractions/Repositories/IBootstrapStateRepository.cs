
namespace Ashlar.Identity.Abstractions.Repositories;

/// <summary>
/// Defines the contract for ibootstrap state repository operations.
/// </summary>
public interface IBootstrapStateRepository
{
    /// <summary>
    /// Performs the get bootstrap status <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<BootstrapStatus> GetBootstrapStatusAsync(CancellationToken cancellationToken = default);
    /// <summary>
    /// Performs the mark as initialized <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="initializedAt">The initialized at value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<bool> MarkAsInitializedAsync(Guid userId, DateTimeOffset initializedAt, CancellationToken cancellationToken = default);
}





