using Ashlar.Messaging;

namespace Ashlar.Email.Smtp;

/// <summary>
/// SMTP implementation of <see cref="IEmailSender"/> that delivers emails immediately.
/// </summary>
public sealed class SmtpEmailSender(IEmailTransport transport) : IEmailSender
{
    /// <inheritdoc />
    public Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
    {
        return transport.DeliverAsync(message, cancellationToken);
    }
}
