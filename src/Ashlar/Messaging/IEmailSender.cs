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
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default);
}


