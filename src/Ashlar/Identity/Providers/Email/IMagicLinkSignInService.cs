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
    /// <param name="cancellationToken">A token that can cancel repository, messaging, or audit work.</param>
    Task RequestLinkAsync(string email, Uri callbackBaseUri, AuthenticationContext? context = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies a raw magic-link token and returns the MFA-aware authentication result.
    /// </summary>
    /// <param name="token">The raw token from the callback URL. Do not log or persist this value.</param>
    /// <param name="context">Optional request context for auditing and rate limiting.</param>
    /// <param name="cancellationToken">A token that can cancel verification before authentication completes.</param>
    /// <returns>The MFA-aware authentication result. Issue an application session only when the status is <see cref="MfaAuthenticationStatus.Succeeded" />.</returns>
    Task<MfaAuthenticationResult> VerifyLinkAsync(string? token, AuthenticationContext? context = null, CancellationToken cancellationToken = default);
}
