namespace Ashlar.Webhooks.SecurityEvents;

/// <summary>
/// Observes completed Ashlar security event webhook delivery attempts.
/// </summary>
public interface IAshlarSecurityEventWebhookDeliveryObserver
{
    /// <summary>
    /// Records a completed delivery attempt.
    /// </summary>
    /// <param name="telemetry">The safe delivery telemetry.</param>
    void RecordDeliveryAttempt(AshlarSecurityEventWebhookDeliveryTelemetry telemetry);
}
