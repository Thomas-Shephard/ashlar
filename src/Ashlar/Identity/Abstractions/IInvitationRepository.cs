using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

public interface IInvitationRepository
{
    Task CreateInvitationAsync(UserInvitation invitation, CancellationToken cancellationToken = default);
    Task<UserInvitation?> GetInvitationByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default);
    Task<bool> UpdateInvitationAsync(UserInvitation invitation, string expectedVersion, CancellationToken cancellationToken = default);
    Task<int> RevokeInvitationsByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default);
}
