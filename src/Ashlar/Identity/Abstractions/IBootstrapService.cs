using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

public interface IBootstrapService
{
    Task<BootstrapStatus> GetStatusAsync(CancellationToken cancellationToken = default);
    Task<BootstrapInvitationResult> CreateBootstrapInvitationAsync(CreateBootstrapInvitationRequest request, CancellationToken cancellationToken = default);
    Task<InvitationAcceptanceResult> AcceptBootstrapInvitationAsync(AcceptInvitationRequest request, AuthenticationContext? context = null, CancellationToken cancellationToken = default);
}
