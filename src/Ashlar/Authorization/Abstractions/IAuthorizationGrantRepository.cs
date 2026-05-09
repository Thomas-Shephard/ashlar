using Ashlar.Authorization.Models;

namespace Ashlar.Authorization.Abstractions;

public interface IAuthorizationGrantRepository
{
    Task CreateGrantAsync(AuthorizationGrant grant, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<AuthorizationGrant>> ListGrantsAsync(ListAuthorizationGrantsRequest request, CancellationToken cancellationToken = default);

    Task<AuthorizationGrant?> GetGrantAsync(Guid grantId, CancellationToken cancellationToken = default);

    Task<bool> RevokeGrantAsync(Guid grantId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default);
}
