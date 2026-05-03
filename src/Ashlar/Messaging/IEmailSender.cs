namespace Ashlar.Messaging;

/// <summary>
/// Sends email messages for Ashlar security and identity flows.
/// </summary>
public interface IEmailSender
{
    Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default);
}
