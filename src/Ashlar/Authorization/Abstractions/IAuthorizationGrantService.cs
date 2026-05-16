using Ashlar.Authorization.Models;

namespace Ashlar.Authorization.Abstractions;

/// <summary>
/// Creates, revokes, and lists authorization grants.
/// </summary>
public interface IAuthorizationGrantService
{
    /// <summary>
    /// Creates a role or permission grant for a user.
    /// </summary>
    /// <param name="request">The grant to create.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The created grant when validation succeeds.</returns>
    Task<Result<AuthorizationGrant>> CreateGrantAsync(CreateAuthorizationGrantRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a grant and returns whether a matching active grant was found.
    /// </summary>
    /// <param name="request">The grant revocation criteria.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns><see langword="true" /> when an active grant was revoked; otherwise, <see langword="false" />.</returns>
    Task<bool> RevokeGrantAsync(RevokeAuthorizationGrantRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists grants matching the supplied filter.
    /// </summary>
    /// <param name="request">The grant list filter.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The matching grants.</returns>
    Task<IReadOnlyList<AuthorizationGrant>> ListGrantsAsync(ListAuthorizationGrantsRequest request, CancellationToken cancellationToken = default);
}
