namespace Ashlar.Messaging;

/// <summary>
/// Email sender that accepts messages and intentionally delivers nothing.
/// </summary>
public sealed class NullEmailSender : IEmailSender
{
    public Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);

        return Task.CompletedTask;
    }
}
