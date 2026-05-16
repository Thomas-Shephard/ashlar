using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

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
    /// Creates the one-time bootstrap invitation token.
    /// </summary>
    /// <param name="request">The bootstrap invitation details.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The raw bootstrap invitation token when creation succeeds.</returns>
    Task<Result<string>> CreateBootstrapInvitationAsync(CreateBootstrapInvitationRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Accepts the bootstrap invitation and marks the installation initialized.
    /// </summary>
    /// <param name="request">The invitation acceptance details.</param>
    /// <param name="context">Optional request context for auditing and notifications.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The created user ID when bootstrap succeeds.</returns>
    Task<Result<Guid>> AcceptBootstrapInvitationAsync(AcceptInvitationRequest request, AuthenticationContext? context = null, CancellationToken cancellationToken = default);
}
