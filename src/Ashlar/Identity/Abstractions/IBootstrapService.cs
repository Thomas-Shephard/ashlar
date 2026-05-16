using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

/// <summary>
/// Defines the contract for ibootstrap service operations.
/// </summary>
public interface IBootstrapService
{
    /// <summary>
    /// Performs the get status <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<BootstrapStatus> GetStatusAsync(CancellationToken cancellationToken = default);
    /// <summary>
    /// Performs the create bootstrap invitation <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="request">The request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result<string>> CreateBootstrapInvitationAsync(CreateBootstrapInvitationRequest request, CancellationToken cancellationToken = default);
    /// <summary>
    /// Performs the accept bootstrap invitation <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="request">The request value.</param>
    /// <param name="context">The context value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result<Guid>> AcceptBootstrapInvitationAsync(AcceptInvitationRequest request, AuthenticationContext? context = null, CancellationToken cancellationToken = default);
}
