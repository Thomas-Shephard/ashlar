namespace Ashlar.Messaging;

/// <summary>
/// Email sender that accepts messages and intentionally delivers nothing.
/// </summary>
public sealed class NullEmailSender : IEmailSender
{
    /// <summary>
    /// Performs the send <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="message">The message value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);

        return Task.CompletedTask;
    }
}
