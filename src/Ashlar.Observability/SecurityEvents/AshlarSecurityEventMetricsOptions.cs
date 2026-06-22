namespace Ashlar.Observability.SecurityEvents;

/// <summary>
/// Configures metrics emitted for Ashlar security events.
/// </summary>
public sealed class AshlarSecurityEventMetricsOptions
{
    /// <summary>
    /// Defines the default meter name for Ashlar security event metrics.
    /// </summary>
    public const string DefaultMeterName = "Ashlar.SecurityEvents";

    /// <summary>
    /// Gets or sets the meter name for Ashlar security event metrics.
    /// </summary>
    public string MeterName { get; set; } = DefaultMeterName;

    /// <summary>
    /// Gets or sets a value indicating whether the provider name is emitted as a metric tag.
    /// </summary>
    /// <remarks>
    /// Provider names can be application-defined, so this is disabled by default to keep metric cardinality bounded.
    /// </remarks>
    public bool IncludeProviderName { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether separate success and failure counters are emitted.
    /// </summary>
    public bool EmitOutcomeCounters { get; set; }
}
