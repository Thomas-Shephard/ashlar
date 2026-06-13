using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Globalization;
using Ashlar.Webhooks.SecurityEvents;
using Microsoft.Extensions.Options;

namespace Ashlar.Observability.SecurityEvents;

/// <summary>
/// Emits OpenTelemetry-compatible metrics for Ashlar security event webhook delivery attempts.
/// </summary>
public sealed class AshlarSecurityEventWebhookMetricsObserver : IAshlarSecurityEventWebhookDeliveryObserver, IDisposable
{
    /// <summary>
    /// Defines the delivery attempts counter name.
    /// </summary>
    public const string DeliveryAttemptsCounterName = "ashlar.security_event_webhooks.delivery_attempts";

    /// <summary>
    /// Defines the delivery successes counter name.
    /// </summary>
    public const string DeliverySuccessesCounterName = "ashlar.security_event_webhooks.delivery_successes";

    /// <summary>
    /// Defines the delivery failures counter name.
    /// </summary>
    public const string DeliveryFailuresCounterName = "ashlar.security_event_webhooks.delivery_failures";

    /// <summary>
    /// Defines the delivery duration histogram name.
    /// </summary>
    public const string DeliveryDurationHistogramName = "ashlar.security_event_webhooks.delivery_duration";

    private const string UnknownTagValue = "unknown";

    private readonly AshlarSecurityEventWebhookMetricsOptions _options;
    private readonly Meter _meter;
    private readonly Counter<long> _deliveryAttempts;
    private readonly Counter<long> _deliverySuccesses;
    private readonly Counter<long> _deliveryFailures;
    private readonly Histogram<double> _deliveryDuration;

    /// <summary>
    /// Initializes a new instance of the security event webhook metrics observer class.
    /// </summary>
    /// <param name="options">The metrics options.</param>
    public AshlarSecurityEventWebhookMetricsObserver(IOptions<AshlarSecurityEventWebhookMetricsOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);

        _options = options.Value;
        _meter = new Meter(GetMeterName(_options), GetMeterVersion());
        _deliveryAttempts = _meter.CreateCounter<long>(DeliveryAttemptsCounterName, unit: "{attempt}", description: "Total Ashlar security event webhook delivery attempts.");
        _deliverySuccesses = _meter.CreateCounter<long>(DeliverySuccessesCounterName, unit: "{attempt}", description: "Successful Ashlar security event webhook delivery attempts.");
        _deliveryFailures = _meter.CreateCounter<long>(DeliveryFailuresCounterName, unit: "{attempt}", description: "Failed Ashlar security event webhook delivery attempts.");
        _deliveryDuration = _meter.CreateHistogram<double>(DeliveryDurationHistogramName, unit: "ms", description: "Ashlar security event webhook delivery attempt duration.");
    }

    /// <summary>
    /// Records metrics for a completed delivery attempt.
    /// </summary>
    /// <param name="telemetry">The safe delivery telemetry.</param>
    public void RecordDeliveryAttempt(AshlarSecurityEventWebhookDeliveryTelemetry telemetry)
    {
        ArgumentNullException.ThrowIfNull(telemetry);

        var tags = CreateTags(telemetry);
        _deliveryAttempts.Add(1, tags);

        if (string.Equals(telemetry.Outcome, AshlarSecurityEventWebhookDeliveryTelemetry.SuccessOutcome, StringComparison.Ordinal))
        {
            _deliverySuccesses.Add(1, tags);
        }
        else if (string.Equals(telemetry.Outcome, AshlarSecurityEventWebhookDeliveryTelemetry.FailureOutcome, StringComparison.Ordinal))
        {
            _deliveryFailures.Add(1, tags);
        }

        if (_options.EmitDurationHistogram)
        {
            _deliveryDuration.Record(telemetry.Duration.TotalMilliseconds, tags);
        }
    }

    /// <summary>
    /// Disposes the owned meter.
    /// </summary>
    public void Dispose()
    {
        _meter.Dispose();
    }

    private static string GetMeterName(AshlarSecurityEventWebhookMetricsOptions options)
    {
        return string.IsNullOrWhiteSpace(options.MeterName)
            ? AshlarSecurityEventWebhookMetricsOptions.DefaultMeterName
            : options.MeterName;
    }

    private static string? GetMeterVersion()
    {
        return Convert.ToString(typeof(AshlarSecurityEventWebhookMetricsObserver).Assembly.GetName().Version, CultureInfo.InvariantCulture);
    }

    private TagList CreateTags(AshlarSecurityEventWebhookDeliveryTelemetry telemetry)
    {
        var tags = new TagList
        {
            { "ashlar.delivery_mode", GetTagValue(telemetry.DeliveryMode) },
            { "ashlar.event_type", GetTagValue(telemetry.EventType) },
            { "ashlar.outcome", GetTagValue(telemetry.Outcome) }
        };

        if (string.Equals(telemetry.Outcome, AshlarSecurityEventWebhookDeliveryTelemetry.FailureOutcome, StringComparison.Ordinal))
        {
            tags.Add("ashlar.failure_kind", GetTagValue(telemetry.FailureKind));
        }

        if (_options.IncludeEndpointName)
        {
            tags.Add("ashlar.endpoint_name", GetTagValue(telemetry.EndpointName));
        }

        return tags;
    }

    private static string GetTagValue(string? value)
    {
        return AshlarSecurityEventWebhookOutboxBrowser.SanitizeSafeText(value) ?? UnknownTagValue;
    }
}
