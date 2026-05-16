using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

/// <summary>
/// Defines the contract for iinvitation service operations.
/// </summary>
public interface IInvitationService
{
    /// <summary>
    /// Performs the create invitation <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="request">The request value.</param>
    /// <param name="callbackBaseUri">The callback base uri value.</param>
    /// <param name="context">The context value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result> CreateInvitationAsync(CreateInvitationRequest request, Uri callbackBaseUri, AuthenticationContext? context = null, CancellationToken cancellationToken = default);
    /// <summary>
    /// Performs the accept invitation <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="request">The request value.</param>
    /// <param name="context">The context value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result<Guid>> AcceptInvitationAsync(AcceptInvitationRequest request, AuthenticationContext? context = null, CancellationToken cancellationToken = default);
    /// <summary>
    /// Performs the revoke invitations <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="email">The email value.</param>
    /// <param name="tenantId">The tenant id value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result> RevokeInvitationsAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default);
}
