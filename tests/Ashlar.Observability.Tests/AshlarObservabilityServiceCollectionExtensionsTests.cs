using System.Diagnostics.Metrics;
using Ashlar.Auditing;
using Ashlar.Observability.SecurityEvents;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Ashlar.Observability.Tests;

internal sealed class AshlarObservabilityServiceCollectionExtensionsTests
{
    [Test]
    public void AddAshlarSecurityEventMetricsRegistersHandlerAndOptions()
    {
        var services = new ServiceCollection();

        services.AddAshlarSecurityEventMetrics(options =>
        {
            options.MeterName = "Custom.Meter";
            options.IncludeProviderName = true;
            options.EmitOutcomeCounters = false;
        });

        using var provider = services.BuildServiceProvider();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.GetRequiredService<ISecurityEventSink>(), Is.TypeOf<SecurityEventFanOutSink>());
            Assert.That(provider.GetServices<ISecurityEventHandler>().Single(), Is.TypeOf<AshlarSecurityEventMetricsHandler>());
            Assert.That(provider.GetRequiredService<IOptions<AshlarSecurityEventMetricsOptions>>().Value.MeterName, Is.EqualTo("Custom.Meter"));
            Assert.That(provider.GetRequiredService<IOptions<AshlarSecurityEventMetricsOptions>>().Value.IncludeProviderName, Is.True);
            Assert.That(provider.GetRequiredService<IOptions<AshlarSecurityEventMetricsOptions>>().Value.EmitOutcomeCounters, Is.False);
        }
    }

    [Test]
    public void AddAshlarSecurityEventMetricsIsIdempotent()
    {
        var services = new ServiceCollection();

        services
            .AddAshlarSecurityEventMetrics()
            .AddAshlarSecurityEventMetrics();

        using var provider = services.BuildServiceProvider();

        Assert.That(provider.GetServices<ISecurityEventHandler>().OfType<AshlarSecurityEventMetricsHandler>(), Has.Exactly(1).Items);
    }

    [Test]
    public async Task AddAshlarSecurityEventMetricsWorksThroughFanOutSink()
    {
        using var listener = new RecordingMeterListener();
        var services = new ServiceCollection();
        services.AddAshlarSecurityEventMetrics(options => options.MeterName = listener.MeterName);
        using var provider = services.BuildServiceProvider();

        await provider.GetRequiredService<ISecurityEventSink>().RecordAsync(new AshlarSecurityEvent
        {
            Id = Guid.NewGuid(),
            EventType = "identity.sign_in",
            OccurredAt = DateTimeOffset.UtcNow,
            Outcome = SecurityEventOutcomes.Success
        });

        Assert.That(listener.Measurements.Select(measurement => measurement.InstrumentName), Does.Contain(AshlarSecurityEventMetricsHandler.TotalEventsCounterName));
    }

    [Test]
    public void AddAshlarSecurityEventMetricsRejectsNullServices()
    {
        var exception = Assert.Throws<ArgumentNullException>(() => AshlarObservabilityServiceCollectionExtensions.AddAshlarSecurityEventMetrics(null!));

        Assert.That(exception?.ParamName, Is.EqualTo("services"));
    }

    private sealed class RecordingMeterListener : IDisposable
    {
        private readonly MeterListener _listener = new();

        public RecordingMeterListener()
        {
            MeterName = $"Ashlar.SecurityEvents.Tests.{Guid.NewGuid():N}";
            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == MeterName)
                {
                    listener.EnableMeasurementEvents(instrument);
                }
            };
            _listener.SetMeasurementEventCallback<long>((instrument, _, _, _) =>
            {
                Measurements.Add(new RecordedMeasurement(instrument.Name));
            });
            _listener.Start();
        }

        public string MeterName { get; }

        public List<RecordedMeasurement> Measurements { get; } = [];

        public void Dispose()
        {
            _listener.Dispose();
        }
    }

    private sealed record RecordedMeasurement(string InstrumentName);
}
