using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

public interface IAuthenticationPipeline
{
    Task<AuthenticationResponse> LoginAsync(AuthenticationContext context, IAuthenticationAssertion assertion, CancellationToken cancellationToken = default);
}
