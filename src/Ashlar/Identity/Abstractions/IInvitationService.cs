using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

public interface IInvitationService
{
    Task CreateInvitationAsync(CreateInvitationRequest request, Uri callbackBaseUri, AuthenticationContext? context = null, CancellationToken cancellationToken = default);
    Task<InvitationAcceptanceResult> AcceptInvitationAsync(AcceptInvitationRequest request, AuthenticationContext? context = null, CancellationToken cancellationToken = default);
    Task RevokeInvitationsAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default);
}
