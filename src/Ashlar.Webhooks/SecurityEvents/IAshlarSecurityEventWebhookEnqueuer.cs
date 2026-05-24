namespace Ashlar.Webhooks.SecurityEvents;

/// <summary>
/// Defines durable enqueue behavior for prepared Ashlar security event webhook deliveries.
/// </summary>
public interface IAshlarSecurityEventWebhookEnqueuer
{
    /// <summary>
    /// Enqueues a prepared webhook delivery for later dispatch.
    /// </summary>
    /// <param name="delivery">The prepared delivery.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>A task representing the enqueue operation.</returns>
    Task EnqueueAsync(AshlarSecurityEventWebhookDelivery delivery, CancellationToken cancellationToken = default);
}
