namespace Ashlar.Messaging;

/// <summary>
/// Defines a service for dispatching pending email messages from an email outbox.
/// </summary>
public interface IEmailOutboxDispatcher
{
    /// <summary>
    /// Processes a single batch of pending email messages.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<int> ProcessBatchAsync(CancellationToken cancellationToken = default);
}
