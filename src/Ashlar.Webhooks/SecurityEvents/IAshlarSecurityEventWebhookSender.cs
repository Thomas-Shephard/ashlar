namespace Ashlar.Webhooks.SecurityEvents;

/// <summary>
/// Defines prepared webhook delivery outcomes.
/// </summary>
public enum AshlarSecurityEventWebhookSendResult
{
    /// <summary>
    /// The webhook endpoint returned a success response.
    /// </summary>
    Sent = 0,

    /// <summary>
    /// The webhook destination was rejected by destination validation.
    /// </summary>
    DestinationRejected = 1,

    /// <summary>
    /// The webhook endpoint returned a non-success response.
    /// </summary>
    DeliveryFailed = 2
}

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
    /// <returns>The explicit delivery outcome.</returns>
    Task<AshlarSecurityEventWebhookSendResult> SendAsync(
        AshlarSecurityEventWebhookDelivery delivery,
        CancellationToken cancellationToken = default);
}
