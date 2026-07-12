namespace Ashlar.Identity.Features.Sessions;

internal interface IAuthenticationSessionMutationExecutor
{
    Task<int> RevokeSessionsForUserAsync(Guid userId, RevokeAuthenticationSessionsForUserRequest request, CancellationToken cancellationToken = default);
    Task<bool> RevokeSessionForUserAsync(Guid userId, RevokeAuthenticationSessionRequest request, CancellationToken cancellationToken = default);
    Task<int> RevokeOtherSessionsAsync(Guid userId, RevokeOtherAuthenticationSessionsRequest request, CancellationToken cancellationToken = default);
}
