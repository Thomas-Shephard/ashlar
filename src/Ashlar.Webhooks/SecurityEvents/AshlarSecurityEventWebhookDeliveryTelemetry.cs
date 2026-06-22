namespace Ashlar.Webhooks.SecurityEvents;

/// <summary>
/// Contains safe, provider-neutral telemetry for a completed security event webhook delivery attempt.
/// </summary>
/// <param name="DeliveryMode">Stable delivery mode tag value.</param>
/// <param name="EventType">The security event type.</param>
/// <param name="EndpointName">The configured endpoint name, if available.</param>
/// <param name="Outcome">The delivery outcome.</param>
/// <param name="FailureKind">The coarse failure kind, if the attempt failed.</param>
/// <param name="Duration">The delivery attempt duration.</param>
public sealed record AshlarSecurityEventWebhookDeliveryTelemetry(
    string DeliveryMode,
    string? EventType,
    string? EndpointName,
    string Outcome,
    string? FailureKind,
    TimeSpan Duration)
{
    /// <summary>
    /// Defines the best-effort delivery mode tag value.
    /// </summary>
    public const string BestEffortDeliveryMode = "best_effort";

    /// <summary>
    /// Defines the durable outbox delivery mode tag value.
    /// </summary>
    public const string DurableOutboxDeliveryMode = "durable_outbox";

    /// <summary>
    /// Defines the successful outcome tag value.
    /// </summary>
    public const string SuccessOutcome = "success";

    /// <summary>
    /// Defines the failed outcome tag value.
    /// </summary>
    public const string FailureOutcome = "failure";

    /// <summary>
    /// Defines the HTTP status failure kind tag value.
    /// </summary>
    public const string HttpStatusFailureKind = "http_status";

    /// <summary>
    /// Defines the timeout failure kind tag value.
    /// </summary>
    public const string TimeoutFailureKind = "timeout";

    /// <summary>
    /// Defines the canceled failure kind tag value.
    /// </summary>
    public const string CanceledFailureKind = "canceled";

    /// <summary>
    /// Defines the exception failure kind tag value.
    /// </summary>
    public const string ExceptionFailureKind = "exception";
}
