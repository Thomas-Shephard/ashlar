namespace Ashlar.Webhooks.SecurityEvents;

/// <summary>
/// Default no-op security event webhook delivery observer.
/// </summary>
public sealed class NoOpAshlarSecurityEventWebhookDeliveryObserver : IAshlarSecurityEventWebhookDeliveryObserver
{
    /// <summary>
    /// Gets the shared no-op observer instance.
    /// </summary>
    public static NoOpAshlarSecurityEventWebhookDeliveryObserver Instance { get; } = new();

    private NoOpAshlarSecurityEventWebhookDeliveryObserver()
    {
    }

    /// <inheritdoc />
    public void RecordDeliveryAttempt(AshlarSecurityEventWebhookDeliveryTelemetry telemetry)
    {
        ArgumentNullException.ThrowIfNull(telemetry);
    }
}
