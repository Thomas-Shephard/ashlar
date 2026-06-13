namespace Ashlar.Messaging;

/// <summary>
/// Email sender that accepts messages and intentionally delivers nothing.
/// </summary>
public sealed class NullEmailSender : IEmailSender
{
    /// <summary>
    /// Validates the message and completes without delivering it.
    /// </summary>
    /// <param name="message">The message to validate.</param>
    /// <param name="cancellationToken">A token that can cancel validation before completion.</param>
    public Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);

        return Task.CompletedTask;
    }
}
