namespace Ashlar.Messaging;

/// <summary>
/// Defines a service for dispatching pending email messages from an email outbox.
/// </summary>
public interface IEmailOutboxDispatcher
{
    /// <summary>
    /// Processes a single batch of pending email messages.
    /// </summary>
    /// <param name="cancellationToken">A token that can cancel dispatch before a message is sent.</param>
    /// <returns>The number of outbox messages processed.</returns>
    Task<int> ProcessBatchAsync(CancellationToken cancellationToken = default);
}
