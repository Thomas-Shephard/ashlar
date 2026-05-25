using Ashlar.Auditing;

namespace Ashlar.Webhooks.SecurityEvents;

/// <summary>
/// Enqueues prepared Ashlar security event webhook deliveries for durable dispatch.
/// </summary>
public sealed class AshlarSecurityEventWebhookOutboxHandler : ISecurityEventHandler
{
    private readonly AshlarSecurityEventWebhookDeliveryFactory _deliveryFactory;
    private readonly IAshlarSecurityEventWebhookEnqueuer _enqueuer;

    /// <summary>
    /// Initializes a new instance of the durable webhook handler class.
    /// </summary>
    /// <param name="deliveryFactory">The delivery factory.</param>
    /// <param name="enqueuer">The durable enqueuer.</param>
    public AshlarSecurityEventWebhookOutboxHandler(
        AshlarSecurityEventWebhookDeliveryFactory deliveryFactory,
        IAshlarSecurityEventWebhookEnqueuer enqueuer)
    {
        ArgumentNullException.ThrowIfNull(deliveryFactory);
        ArgumentNullException.ThrowIfNull(enqueuer);

        _deliveryFactory = deliveryFactory;
        _enqueuer = enqueuer;
    }

    /// <summary>
    /// Enqueues security event webhook deliveries for configured endpoints.
    /// </summary>
    /// <param name="securityEvent">The security event value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>A task representing durable enqueue.</returns>
    public async Task HandleAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        cancellationToken.ThrowIfCancellationRequested();

        foreach (var delivery in _deliveryFactory.CreateDeliveries(securityEvent))
        {
            await _enqueuer.EnqueueAsync(delivery, cancellationToken).ConfigureAwait(false);
        }
    }
}
