namespace Ashlar.Messaging;

/// <summary>
/// Provides the low-level delivery mechanism for email messages.
/// This is used by the outbox dispatcher to physically send emails through an SMTP client, API, or other transport.
/// </summary>
public interface IEmailTransport
{
    /// <summary>
    /// Delivers the specified email message.
    /// </summary>
    /// <param name="message">The email message to deliver.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task representing the asynchronous delivery operation.</returns>
    Task DeliverAsync(EmailMessage message, CancellationToken cancellationToken = default);
}
