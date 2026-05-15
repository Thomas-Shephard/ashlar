using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

public interface IAuthenticationHandshakeService
{
    Task<Result<AuthenticationHandshakeCreated>> CreateHandshakeAsync(CreateAuthenticationHandshakeRequest request, CancellationToken cancellationToken = default);
    
    Task<Result<AuthenticationHandshake>> VerifyFactorAsync(VerifyAuthenticationHandshakeRequest request, CancellationToken cancellationToken = default);
    
    Task<AuthenticationHandshake?> GetHandshakeAsync(string handshakeToken, CancellationToken cancellationToken = default);
    
    Task<Result> RevokeHandshakeAsync(string handshakeToken, CancellationToken cancellationToken = default);
}
