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
    /// <param name="callbackBaseUri">The trusted callback base URI that receives the reset token.</param>
    /// <param name="context">Optional authentication context for tenant and audit metadata.</param>
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
    /// <returns>A generic result for the externally visible request flow.</returns>
    Task<Result> RequestPasswordResetAsync(
        string email,
        Uri callbackBaseUri,
        AuthenticationContext? context = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Completes a password reset with a one-time token and replacement password.
    /// </summary>
    /// <param name="request">The reset request.</param>
    /// <param name="context">Optional authentication context for tenant and audit metadata.</param>
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
    /// <returns>The reset result.</returns>
    Task<Result<PasswordResetResult>> ResetPasswordAsync(
        PasswordResetRequest request,
        AuthenticationContext? context = null,
        CancellationToken cancellationToken = default);
}
