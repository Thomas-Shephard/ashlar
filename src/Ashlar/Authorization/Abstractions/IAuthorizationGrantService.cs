using Ashlar.Authorization.Models;

namespace Ashlar.Authorization.Abstractions;

/// <summary>
/// Defines the contract for iauthorization grant service operations.
/// </summary>
public interface IAuthorizationGrantService
{
    /// <summary>
    /// Performs the create grant <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="request">The request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result<AuthorizationGrant>> CreateGrantAsync(CreateAuthorizationGrantRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Performs the revoke grant <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="request">The request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<bool> RevokeGrantAsync(RevokeAuthorizationGrantRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Performs the list grants <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="request">The request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<IReadOnlyList<AuthorizationGrant>> ListGrantsAsync(ListAuthorizationGrantsRequest request, CancellationToken cancellationToken = default);
}
