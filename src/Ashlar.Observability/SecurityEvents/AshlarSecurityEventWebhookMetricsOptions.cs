namespace Ashlar.Observability.SecurityEvents;

/// <summary>
/// Configures metrics emitted for Ashlar security event webhook delivery.
/// </summary>
public sealed class AshlarSecurityEventWebhookMetricsOptions
{
    /// <summary>
    /// Defines the default meter name for Ashlar security event webhook metrics.
    /// </summary>
    public const string DefaultMeterName = "Ashlar.Webhooks";

    /// <summary>
    /// Gets or sets the meter name for Ashlar security event webhook metrics.
    /// </summary>
    public string MeterName { get; set; } = DefaultMeterName;

    /// <summary>
    /// Gets or sets a value indicating whether endpoint names are emitted as metric tags.
    /// </summary>
    /// <remarks>
    /// Endpoint names are application-defined, so this is disabled by default to keep metric cardinality bounded.
    /// </remarks>
    public bool IncludeEndpointName { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether delivery duration histogram measurements are emitted.
    /// </summary>
    public bool EmitDurationHistogram { get; set; } = true;
}
