namespace Ashlar.Messaging;

/// <summary>
/// Provides documented behavior for this API surface.
/// This is used by the outbox dispatcher to physically send emails through an SMTP client, API, or other transport.
/// </summary>
public interface IEmailTransport
{
    /// <summary>
    /// Delivers the specified email message.
    /// </summary>
    /// <param name="message">The message value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task DeliverAsync(EmailMessage message, CancellationToken cancellationToken = default);
}
