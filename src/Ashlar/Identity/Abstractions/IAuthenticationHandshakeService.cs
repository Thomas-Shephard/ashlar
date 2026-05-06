using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

public interface IAuthenticationHandshakeService
{
    Task<(AuthenticationHandshake Handshake, string Token)> CreateHandshakeAsync(CreateAuthenticationHandshakeRequest request, CancellationToken cancellationToken = default);
    
    Task<AuthenticationHandshakeResult> VerifyFactorAsync(VerifyAuthenticationHandshakeRequest request, CancellationToken cancellationToken = default);
    
    Task<AuthenticationHandshake?> GetHandshakeAsync(string handshakeToken, CancellationToken cancellationToken = default);
    
    Task RevokeHandshakeAsync(string handshakeToken, CancellationToken cancellationToken = default);
}
