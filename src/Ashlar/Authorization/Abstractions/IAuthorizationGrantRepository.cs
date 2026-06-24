using Ashlar.Authorization.Models;

namespace Ashlar.Authorization.Abstractions;

/// <summary>
/// Persists and queries provider-neutral authorization grants.
/// </summary>
public interface IAuthorizationGrantRepository
{
    /// <summary>
    /// Persists a new authorization grant.
    /// </summary>
    /// <param name="grant">Validated grant to store.</param>
    /// <param name="cancellationToken">A token that can cancel persistence.</param>
    /// <returns>A task that completes after the grant has been persisted.</returns>
    Task CreateGrantAsync(AuthorizationGrant grant, CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists grants matching a user, tenant, and optional resource scope.
    /// </summary>
    /// <param name="request">Provider-neutral user, tenant, and optional scope criteria.</param>
    /// <param name="cancellationToken">A token that can cancel the query.</param>
    /// <returns>Matching grants. Repository implementations must not return secrets in metadata.</returns>
    Task<IReadOnlyList<AuthorizationGrant>> ListGrantsAsync(ListAuthorizationGrantsRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets one grant by identifier within the requested tenant boundary.
    /// </summary>
    /// <param name="grantId">Identifier of the grant to retrieve.</param>
    /// <param name="tenantId">Tenant boundary that must match the grant. A <see langword="null" /> value matches only global grants.</param>
    /// <param name="cancellationToken">A token that can cancel the lookup.</param>
    /// <returns>Matching grant, or <see langword="null" /> when no grant exists in the requested tenant boundary.</returns>
    Task<AuthorizationGrant?> GetGrantAsync(Guid grantId, Guid? tenantId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Marks an active grant as revoked.
    /// </summary>
    /// <param name="grantId">Identifier of the grant to revoke.</param>
    /// <param name="tenantId">Tenant boundary that must match the grant. A <see langword="null" /> value matches only global grants.</param>
    /// <param name="revokedAt">UTC time to record as the revocation timestamp.</param>
    /// <param name="cancellationToken">A token that can cancel revocation.</param>
    /// <returns><see langword="true" /> when an active matching grant was revoked.</returns>
    Task<bool> RevokeGrantAsync(Guid grantId, Guid? tenantId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default);
}
