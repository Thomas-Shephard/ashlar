using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

public interface IAuthenticationHandshakeRepository
{
    Task CreateAsync(AuthenticationHandshake handshake, CancellationToken cancellationToken = default);
    Task<AuthenticationHandshake?> FindByTokenHashAsync(string tokenHash, bool forUpdate = false, CancellationToken cancellationToken = default);
    Task UpdateAsync(AuthenticationHandshake handshake, CancellationToken cancellationToken = default);
}
