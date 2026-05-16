using Ashlar.Messaging;

namespace Ashlar.Email.Smtp;

/// <summary>
/// SMTP implementation of <see cref="IEmailSender"/> that delivers emails immediately.
/// </summary>
/// <param name="transport">The transport value.</param>
public sealed class SmtpEmailSender(IEmailTransport transport) : IEmailSender
{
    /// <summary>
    /// Sends an email message through the configured SMTP transport.
    /// </summary>
    /// <param name="message">The email message.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task that represents the asynchronous send operation.</returns>
    public Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
    {
        return transport.DeliverAsync(message, cancellationToken);
    }
}
