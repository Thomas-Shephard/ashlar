namespace Ashlar.Webhooks.SecurityEvents;

internal sealed class AshlarSecurityEventWebhookDeliveryObserverContribution<TObserver>(TObserver observer)
    : IAshlarSecurityEventWebhookDeliveryObserverContribution
    where TObserver : IAshlarSecurityEventWebhookDeliveryObserver
{
    public IAshlarSecurityEventWebhookDeliveryObserver Observer { get; } = observer ?? throw new ArgumentNullException(nameof(observer));
}
