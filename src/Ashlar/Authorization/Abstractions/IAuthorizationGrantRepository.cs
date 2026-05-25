using Ashlar.Authorization.Models;

namespace Ashlar.Authorization.Abstractions;

/// <summary>
/// Defines the contract for iauthorization grant repository operations.
/// </summary>
public interface IAuthorizationGrantRepository
{
    /// <summary>
    /// Performs the create grant <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="grant">The grant value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task CreateGrantAsync(AuthorizationGrant grant, CancellationToken cancellationToken = default);

    /// <summary>
    /// Performs the list grants <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="request">The request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<IReadOnlyList<AuthorizationGrant>> ListGrantsAsync(ListAuthorizationGrantsRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Performs the get grant <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="grantId">The grant id value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<AuthorizationGrant?> GetGrantAsync(Guid grantId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Performs the revoke grant <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="grantId">The grant id value.</param>
    /// <param name="tenantId">The tenant id value. A <see langword="null" /> value matches only global grants.</param>
    /// <param name="revokedAt">The revoked at value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<bool> RevokeGrantAsync(Guid grantId, Guid? tenantId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default);
}
