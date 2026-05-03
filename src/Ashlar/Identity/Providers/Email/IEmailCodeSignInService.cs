using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;

namespace Ashlar.Identity.Providers.Email;

public interface IEmailCodeSignInService
{
    Task RequestCodeAsync(string email, AuthenticationContext? context = null, CancellationToken cancellationToken = default);
    Task<AuthenticationResponse> VerifyCodeAsync(string email, string code, AuthenticationContext? context = null, CancellationToken cancellationToken = default);
}
