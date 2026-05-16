using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

public interface IInvitationService
{
    Task<Result> CreateInvitationAsync(CreateInvitationRequest request, Uri callbackBaseUri, AuthenticationContext? context = null, CancellationToken cancellationToken = default);
    Task<Result<Guid>> AcceptInvitationAsync(AcceptInvitationRequest request, AuthenticationContext? context = null, CancellationToken cancellationToken = default);
    Task<Result> RevokeInvitationsAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default);
}
