using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;

namespace Ashlar.Identity.Providers.Email;

/// <summary>
/// Sends and verifies passwordless sign-in links.
/// </summary>
public interface IMagicLinkSignInService
{
    /// <summary>
    /// Sends a magic link when the address is eligible for sign-in.
    /// </summary>
    /// <param name="email">The email address requesting sign-in.</param>
    /// <param name="callbackBaseUri">The callback URI that receives the generated token as a query parameter.</param>
    /// <param name="context">Optional request context for auditing and rate limiting.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    Task RequestLinkAsync(string email, Uri callbackBaseUri, AuthenticationContext? context = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies a raw magic-link token and returns the authentication result.
    /// </summary>
    /// <param name="token">The raw token from the callback URL.</param>
    /// <param name="context">Optional request context for auditing and rate limiting.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The authentication response.</returns>
    Task<AuthenticationResponse> VerifyLinkAsync(string token, AuthenticationContext? context = null, CancellationToken cancellationToken = default);
}
