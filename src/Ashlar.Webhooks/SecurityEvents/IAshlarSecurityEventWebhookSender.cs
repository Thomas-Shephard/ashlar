namespace Ashlar.Webhooks.SecurityEvents;

/// <summary>
/// Defines a sender for prepared Ashlar security event webhook deliveries.
/// </summary>
public interface IAshlarSecurityEventWebhookSender
{
    /// <summary>
    /// Sends one prepared webhook delivery to its endpoint.
    /// </summary>
    /// <param name="delivery">The prepared delivery.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>A task representing the send operation.</returns>
    Task SendAsync(AshlarSecurityEventWebhookDelivery delivery, CancellationToken cancellationToken = default);
}
