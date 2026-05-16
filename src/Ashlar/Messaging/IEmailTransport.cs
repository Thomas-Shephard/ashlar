namespace Ashlar.Messaging;

/// <summary>
/// Physically delivers email messages through SMTP, an API, or another transport.
/// </summary>
public interface IEmailTransport
{
    /// <summary>
    /// Delivers the specified email message.
    /// </summary>
    /// <param name="message">The message to deliver.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    Task DeliverAsync(EmailMessage message, CancellationToken cancellationToken = default);
}
