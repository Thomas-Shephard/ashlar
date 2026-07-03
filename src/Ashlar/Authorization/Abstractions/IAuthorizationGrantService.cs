using Ashlar.Authorization.Models;

namespace Ashlar.Authorization.Abstractions;

/// <summary>
/// Creates, revokes, and lists authorization grants.
/// </summary>
/// <remarks>
/// These operations do not authorize callers. Host applications must protect usage with appropriate admin
/// authorization, audit policy, and fresh MFA or equivalent step-up policy before creating or revoking grants.
/// Creating and revoking grants are privilege changes and require audit context on the mutation request.
/// </remarks>
public interface IAuthorizationGrantService
{
    /// <summary>
    /// Creates a role or permission grant for a user. Grant creation is a privilege change and requires audit context.
    /// </summary>
    /// <param name="request">Grant details supplied by an already-authorized caller.</param>
    /// <param name="cancellationToken">A token that can cancel grant creation.</param>
    /// <returns>Created grant when validation and tenant checks succeed.</returns>
    Task<Result<AuthorizationGrant>> CreateGrantAsync(CreateAuthorizationGrantRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a grant and returns a stable outcome for the requested grant and tenant boundary. Grant revocation is a privilege change and requires audit context.
    /// </summary>
    /// <param name="request">Grant identifier, tenant scope, and audit context for revocation.</param>
    /// <param name="cancellationToken">A token that can cancel grant revocation.</param>
    /// <returns>Revocation result with the grant id, requested tenant boundary, and outcome.</returns>
    Task<RevokeAuthorizationGrantResult> RevokeGrantAsync(RevokeAuthorizationGrantRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists grants matching the supplied filter.
    /// </summary>
    /// <param name="request">User, tenant, and optional scope filters for listing grants.</param>
    /// <param name="cancellationToken">A token that can cancel grant listing.</param>
    /// <returns>Matching grants visible for the supplied filters.</returns>
    Task<IReadOnlyList<AuthorizationGrant>> ListGrantsAsync(ListAuthorizationGrantsRequest request, CancellationToken cancellationToken = default);
}
