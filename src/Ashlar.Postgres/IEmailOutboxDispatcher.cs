namespace Ashlar.Postgres;

/// <summary>
/// Defines a service for dispatching pending email messages from the PostgreSQL outbox.
/// </summary>
public interface IEmailOutboxDispatcher
{
    /// <summary>
    /// Processes a single batch of pending email messages.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The number of messages processed in this batch.</returns>
    Task<int> ProcessBatchAsync(CancellationToken cancellationToken = default);
}
