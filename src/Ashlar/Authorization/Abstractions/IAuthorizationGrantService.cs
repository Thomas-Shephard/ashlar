using Ashlar.Authorization.Models;

namespace Ashlar.Authorization.Abstractions;

public interface IAuthorizationGrantService
{
    Task<AuthorizationGrant> CreateGrantAsync(CreateAuthorizationGrantRequest request, CancellationToken cancellationToken = default);

    Task<bool> RevokeGrantAsync(RevokeAuthorizationGrantRequest request, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<AuthorizationGrant>> ListGrantsAsync(ListAuthorizationGrantsRequest request, CancellationToken cancellationToken = default);
}
