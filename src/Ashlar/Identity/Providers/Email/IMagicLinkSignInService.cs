using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;

namespace Ashlar.Identity.Providers.Email;

public interface IMagicLinkSignInService
{
    Task RequestLinkAsync(string email, Uri callbackBaseUri, AuthenticationContext? context = null, CancellationToken cancellationToken = default);
    Task<AuthenticationResponse> VerifyLinkAsync(string token, AuthenticationContext? context = null, CancellationToken cancellationToken = default);
}
