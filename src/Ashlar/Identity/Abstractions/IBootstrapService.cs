using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

public interface IBootstrapService
{
    Task<BootstrapStatus> GetStatusAsync(CancellationToken cancellationToken = default);
    Task<Result<string>> CreateBootstrapInvitationAsync(CreateBootstrapInvitationRequest request, CancellationToken cancellationToken = default);
    Task<Result<Guid>> AcceptBootstrapInvitationAsync(AcceptInvitationRequest request, AuthenticationContext? context = null, CancellationToken cancellationToken = default);
}
