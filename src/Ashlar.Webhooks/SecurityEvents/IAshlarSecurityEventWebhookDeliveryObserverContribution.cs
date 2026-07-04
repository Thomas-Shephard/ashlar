namespace Ashlar.Webhooks.SecurityEvents;

internal interface IAshlarSecurityEventWebhookDeliveryObserverContribution
{
    IAshlarSecurityEventWebhookDeliveryObserver Observer { get; }
}
