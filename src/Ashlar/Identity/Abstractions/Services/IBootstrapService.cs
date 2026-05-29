namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Manages the first-user bootstrap flow for a new Ashlar installation.
/// </summary>
public interface IBootstrapService
{
    /// <summary>
    /// Gets whether the installation has already been initialized.
    /// </summary>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The current bootstrap status.</returns>
    Task<BootstrapStatus> GetStatusAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Bootstraps the first administrator and marks the installation initialized.
    /// </summary>
    /// <param name="request">The first-admin bootstrap details.</param>
    /// <param name="context">Optional request context for auditing and notifications.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The created user ID when bootstrap succeeds.</returns>
    Task<Result<Guid>> BootstrapFirstAdminAsync(BootstrapFirstAdminRequest request, AuthenticationContext? context = null, CancellationToken cancellationToken = default);
}
