using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

public interface ICredentialService
{
    Task<(IUser? User, UserCredential? Credential, bool UnprotectFailed)> ResolveAsync(string? email, IAuthenticationAssertion assertion, Guid? tenantId = null, CancellationToken cancellationToken = default);
    Task<(IUser? User, UserCredential? Credential, bool UnprotectFailed)> ResolveAsync(Guid userId, IAuthenticationAssertion assertion, CancellationToken cancellationToken = default);
    
    Task LinkCredentialAsync(Guid userId, IAuthenticationAssertion assertion, string? credentialValue = null, CancellationToken cancellationToken = default);
    Task UpdateCredentialUsageAsync(UserCredential? credential, AuthenticationResult result, IAuthenticationProvider provider, CancellationToken cancellationToken = default);
}