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
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    Task RequestCodeAsync(string email, AuthenticationContext? context = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies a submitted code and returns the authentication result.
    /// </summary>
    /// <param name="email">The email address associated with the code.</param>
    /// <param name="code">The one-time code supplied by the user.</param>
    /// <param name="context">Optional request context for auditing and rate limiting.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The authentication response.</returns>
    Task<AuthenticationResponse> VerifyCodeAsync(string email, string code, AuthenticationContext? context = null, CancellationToken cancellationToken = default);
}
