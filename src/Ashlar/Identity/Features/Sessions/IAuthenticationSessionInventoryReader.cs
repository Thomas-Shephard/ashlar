namespace Ashlar.Identity.Features.Sessions;

internal interface IAuthenticationSessionInventoryReader : IAuthenticationSessionReader
{
    Task<Result<IReadOnlyList<AuthenticationSessionSummary>>> ListSessionsForUserAsync(
        Guid userId, Guid? tenantId, ListAuthenticationSessionsRequest request,
        CancellationToken cancellationToken = default);
}
