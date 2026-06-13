namespace Ashlar.Messaging;

/// <summary>
/// Sends email messages for Ashlar security and identity flows.
/// </summary>
public interface IEmailSender
{
    /// <summary>
    /// Sends or queues an email message.
    /// </summary>
    /// <param name="message">The message to send or queue.</param>
    /// <param name="cancellationToken">A token that can cancel sending or queueing before the message is accepted.</param>
    Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default);
}
