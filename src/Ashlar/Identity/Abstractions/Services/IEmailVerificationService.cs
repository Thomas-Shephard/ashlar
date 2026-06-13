namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Sends verification messages and confirms raw email verification tokens.
/// </summary>
public interface IEmailVerificationService
{
    /// <summary>
    /// Enqueues or sends a verification message for the requested user.
    /// </summary>
    /// <param name="request">User, callback base URI, and audit context for issuing the verification message.</param>
    /// <param name="cancellationToken">A token that can cancel the request.</param>
    /// <returns>A success result when the verification message is queued or sent; otherwise, a failure describing why the request was rejected.</returns>
    Task<Result> RequestVerificationAsync(EmailVerificationRequest request, CancellationToken cancellationToken = default);
    /// <summary>
    /// Confirms a raw verification token and marks the user's email as verified.
    /// </summary>
    /// <param name="request">The user, raw token, and audit context for the confirmation attempt. Do not log or persist the token.</param>
    /// <param name="cancellationToken">A token that can cancel confirmation.</param>
    /// <returns>A success result when the token is consumed and the email is marked verified; otherwise, a failure describing why confirmation was rejected.</returns>
    Task<Result> ConfirmVerificationAsync(ConfirmEmailVerificationRequest request, CancellationToken cancellationToken = default);
}
