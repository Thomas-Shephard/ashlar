using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Globalization;
using Ashlar.Auditing;
using Ashlar.Identity.Models.Authentication;
using Microsoft.Extensions.Options;

namespace Ashlar.Observability.SecurityEvents;

/// <summary>
/// Emits OpenTelemetry-compatible metrics for Ashlar security events.
/// </summary>
public sealed class AshlarSecurityEventMetricsHandler : ISecurityEventHandler, IDisposable
{
    /// <summary>
    /// Defines the total security events counter name.
    /// </summary>
    public const string TotalEventsCounterName = "ashlar.security.events";

    /// <summary>
    /// Defines the successful security events counter name.
    /// </summary>
    public const string SuccessEventsCounterName = "ashlar.security.events.successes";

    /// <summary>
    /// Defines the failed security events counter name.
    /// </summary>
    public const string FailureEventsCounterName = "ashlar.security.events.failures";

    private const string UnknownTagValue = "unknown";

    private readonly AshlarSecurityEventMetricsOptions _options;
    private readonly Meter _meter;
    private readonly Counter<long> _totalEvents;
    private readonly Counter<long> _successEvents;
    private readonly Counter<long> _failureEvents;

    /// <summary>
    /// Initializes a new instance of the security event metrics handler class.
    /// </summary>
    /// <param name="options">The metrics options.</param>
    public AshlarSecurityEventMetricsHandler(IOptions<AshlarSecurityEventMetricsOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);

        _options = options.Value;
        _meter = new Meter(GetMeterName(_options), GetMeterVersion());
        _totalEvents = _meter.CreateCounter<long>(TotalEventsCounterName, unit: "{event}", description: "Total Ashlar security events.");
        _successEvents = _meter.CreateCounter<long>(SuccessEventsCounterName, unit: "{event}", description: "Successful Ashlar security events.");
        _failureEvents = _meter.CreateCounter<long>(FailureEventsCounterName, unit: "{event}", description: "Failed Ashlar security events.");
    }

    /// <summary>
    /// Emits metrics for a security event.
    /// </summary>
    /// <param name="securityEvent">The security event value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>A completed task after metrics are emitted.</returns>
    public Task HandleAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        cancellationToken.ThrowIfCancellationRequested();

        var tags = CreateTags(securityEvent);
        _totalEvents.Add(1, tags);

        if (_options.EmitOutcomeCounters)
        {
            if (IsOutcome(securityEvent, SecurityEventOutcomes.Success))
            {
                _successEvents.Add(1, tags);
            }
            else if (IsOutcome(securityEvent, SecurityEventOutcomes.Failure))
            {
                _failureEvents.Add(1, tags);
            }
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Disposes the owned meter.
    /// </summary>
    public void Dispose()
    {
        _meter.Dispose();
    }

    private static string GetMeterName(AshlarSecurityEventMetricsOptions options)
    {
        return string.IsNullOrWhiteSpace(options.MeterName)
            ? AshlarSecurityEventMetricsOptions.DefaultMeterName
            : options.MeterName;
    }

    private static string? GetMeterVersion()
    {
        return Convert.ToString(typeof(AshlarSecurityEventMetricsHandler).Assembly.GetName().Version, CultureInfo.InvariantCulture);
    }

    private static bool IsOutcome(AshlarSecurityEvent securityEvent, string outcome)
    {
        return string.Equals(securityEvent.Outcome, outcome, StringComparison.Ordinal);
    }

    private TagList CreateTags(AshlarSecurityEvent securityEvent)
    {
        var tags = new TagList
        {
            { "ashlar.event_type", GetTagValue(securityEvent.EventType) },
            { "ashlar.outcome", GetTagValue(securityEvent.Outcome) },
            { "ashlar.provider_type", GetTagValue(AuthenticationProviderKey.GetStorageTypeValue(securityEvent.Provider)) }
        };

        if (_options.IncludeProviderName)
        {
            tags.Add("ashlar.provider_name", GetTagValue(securityEvent.Provider?.Name));
        }

        return tags;
    }

    private static string GetTagValue(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? UnknownTagValue : value;
    }
}
