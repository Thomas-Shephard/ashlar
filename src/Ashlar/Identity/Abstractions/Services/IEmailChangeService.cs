namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Sends email change confirmation messages and confirms raw email change tokens.
/// </summary>
public interface IEmailChangeService
{
    /// <summary>
    /// Enqueues or sends a confirmation message for a pending email change.
    /// </summary>
    /// <param name="request">The validated session, new email address, callback base URI, and audit context.</param>
    /// <param name="cancellationToken">A token that can cancel the request.</param>
    /// <returns>A success result when the email-change confirmation message is queued or sent; otherwise, a failure describing why the request was rejected.</returns>
    Task<Result> RequestChangeAsync(RequestEmailChangeRequest request, CancellationToken cancellationToken = default);
    /// <summary>
    /// Confirms a raw email change token and updates the user's email address.
    /// </summary>
    /// <param name="request">The user, raw token, and audit context for the confirmation attempt. Do not log or persist the token.</param>
    /// <param name="cancellationToken">A token that can cancel confirmation.</param>
    /// <returns>A success result when the token is consumed and the email address is updated; otherwise, a failure describing why confirmation was rejected.</returns>
    Task<Result> ConfirmChangeAsync(ConfirmEmailChangeRequest request, CancellationToken cancellationToken = default);
}
