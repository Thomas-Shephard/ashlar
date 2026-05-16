namespace Ashlar.Messaging;

/// <summary>
/// Sends email messages for Ashlar security and identity flows.
/// </summary>
public interface IEmailSender
{
    /// <summary>
    /// Performs the send <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="message">The message value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default);
}
