namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Coordinates password reset requests for local password credentials.
/// </summary>
public interface IPasswordResetService
{
    /// <summary>
    /// Requests a password reset email for a local password credential.
    /// </summary>
    /// <param name="email">The account email address.</param>
    /// <param name="callbackBaseUri">Trusted callback base URI that receives the raw reset token.</param>
    /// <param name="context">Optional authentication context for tenant and audit metadata.</param>
    /// <param name="cancellationToken">A token that can cancel password reset message delivery or audit work.</param>
    /// <returns>A deliberately generic success result for accepted requests, including requests where account existence is suppressed.</returns>
    Task<Result> RequestPasswordResetAsync(
        string email,
        Uri callbackBaseUri,
        AuthenticationContext? context = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Completes a password reset with a one-time token and replacement password.
    /// </summary>
    /// <param name="request">One-time reset token and replacement password. Do not log either value.</param>
    /// <param name="context">Optional authentication context for tenant and audit metadata.</param>
    /// <param name="cancellationToken">A token that can cancel token verification or password update work.</param>
    /// <returns>The reset outcome, including the affected user when the token is accepted.</returns>
    Task<Result<PasswordResetResult>> ResetPasswordAsync(
        PasswordResetRequest request,
        AuthenticationContext? context = null,
        CancellationToken cancellationToken = default);
}
