namespace Ashlar.Webhooks.SecurityEvents;

internal sealed class CompositeAshlarSecurityEventWebhookDeliveryObserver(
    IEnumerable<IAshlarSecurityEventWebhookDeliveryObserverContribution> contributions)
    : IAshlarSecurityEventWebhookDeliveryObserver
{
    private readonly IAshlarSecurityEventWebhookDeliveryObserver[] _observers =
        contributions.Select(contribution => contribution.Observer).ToArray();

    public void RecordDeliveryAttempt(AshlarSecurityEventWebhookDeliveryTelemetry telemetry)
    {
        ArgumentNullException.ThrowIfNull(telemetry);

        foreach (var observer in _observers)
        {
            try
            {
                observer.RecordDeliveryAttempt(telemetry);
            }
            catch
            {
                // Delivery observers are best-effort and must not block later observers.
            }
        }
    }
}
