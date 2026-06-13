namespace Ashlar.Identity.Providers.Email;

/// <summary>
/// Sends and verifies one-time email codes for passwordless sign-in.
/// </summary>
public interface IEmailCodeSignInService
{
    /// <summary>
    /// Sends a one-time code when the address is eligible for sign-in.
    /// </summary>
    /// <param name="email">The email address requesting sign-in.</param>
    /// <param name="context">Optional request context for auditing and rate limiting.</param>
    /// <param name="cancellationToken">A token that can cancel repository, messaging, or audit work.</param>
    Task RequestCodeAsync(string email, AuthenticationContext? context = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies a submitted code and returns the MFA-aware authentication result.
    /// </summary>
    /// <param name="email">Email address associated with the submitted sign-in code.</param>
    /// <param name="code">The one-time code supplied by the user. Do not log this value.</param>
    /// <param name="context">Optional request context for auditing and rate limiting.</param>
    /// <param name="cancellationToken">A token that can cancel verification before authentication completes.</param>
    /// <returns>The MFA-aware authentication result. Issue an application session only when the status is <see cref="MfaAuthenticationStatus.Succeeded" />.</returns>
    Task<MfaAuthenticationResult> VerifyCodeAsync(string email, string code, AuthenticationContext? context = null, CancellationToken cancellationToken = default);
}
