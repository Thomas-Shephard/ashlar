namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Manages the first-user bootstrap flow for a new Ashlar installation.
/// </summary>
public interface IBootstrapService
{
    /// <summary>
    /// Checks whether first-admin bootstrap has already initialized the installation.
    /// </summary>
    /// <param name="cancellationToken">A token that can cancel bootstrap status lookup.</param>
    /// <returns>Current bootstrap initialization state.</returns>
    Task<BootstrapStatus> GetStatusAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Bootstraps the first administrator and marks the installation initialized.
    /// </summary>
    /// <param name="request">The first-admin bootstrap details.</param>
    /// <param name="context">Optional request context for auditing and notifications.</param>
    /// <param name="cancellationToken">A token that can cancel first-admin bootstrap.</param>
    /// <returns>The created user and Ashlar-verified session issuance capability when bootstrap succeeds.</returns>
    Task<Result<BootstrapFirstAdminResult>> BootstrapFirstAdminAsync(BootstrapFirstAdminRequest request, AuthenticationContext? context = null, CancellationToken cancellationToken = default);
}
