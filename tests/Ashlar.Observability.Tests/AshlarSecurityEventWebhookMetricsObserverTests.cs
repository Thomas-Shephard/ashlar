using System.Diagnostics.Metrics;
using Ashlar.Observability.SecurityEvents;
using Ashlar.Webhooks.SecurityEvents;
using Microsoft.Extensions.Options;

namespace Ashlar.Observability.Tests;

internal sealed class AshlarSecurityEventWebhookMetricsObserverTests
{
    [Test]
    public void RecordDeliveryAttemptRecordsSuccessCountersAndHistogram()
    {
        using var listener = new RecordingMeterListener();
        using var observer = CreateObserver(new AshlarSecurityEventWebhookMetricsOptions { MeterName = listener.MeterName });

        observer.RecordDeliveryAttempt(CreateTelemetry(AshlarSecurityEventWebhookDeliveryTelemetry.SuccessOutcome));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(listener.LongMeasurements.Select(measurement => measurement.InstrumentName), Does.Contain(AshlarSecurityEventWebhookMetricsObserver.DeliveryAttemptsCounterName));
            Assert.That(listener.LongMeasurements.Select(measurement => measurement.InstrumentName), Does.Contain(AshlarSecurityEventWebhookMetricsObserver.DeliverySuccessesCounterName));
            Assert.That(listener.LongMeasurements.Select(measurement => measurement.InstrumentName), Does.Not.Contain(AshlarSecurityEventWebhookMetricsObserver.DeliveryFailuresCounterName));
            Assert.That(listener.DoubleMeasurements.Single().InstrumentName, Is.EqualTo(AshlarSecurityEventWebhookMetricsObserver.DeliveryDurationHistogramName));
            Assert.That(listener.DoubleMeasurements.Single().Value, Is.EqualTo(12.5d));
        }
    }

    [Test]
    public void RecordDeliveryAttemptRecordsFailureKindAndOptionalEndpointName()
    {
        using var listener = new RecordingMeterListener();
        using var observer = CreateObserver(new AshlarSecurityEventWebhookMetricsOptions
        {
            MeterName = listener.MeterName,
            IncludeEndpointName = true
        });

        observer.RecordDeliveryAttempt(CreateTelemetry(
            AshlarSecurityEventWebhookDeliveryTelemetry.FailureOutcome,
            AshlarSecurityEventWebhookDeliveryTelemetry.TimeoutFailureKind));

        var tags = listener.LongMeasurements.First(measurement => measurement.InstrumentName == AshlarSecurityEventWebhookMetricsObserver.DeliveryFailuresCounterName).Tags;
        using (Assert.EnterMultipleScope())
        {
            Assert.That(tags["ashlar.delivery_mode"], Is.EqualTo(AshlarSecurityEventWebhookDeliveryTelemetry.BestEffortDeliveryMode));
            Assert.That(tags["ashlar.event_type"], Is.EqualTo("ashlar.sign_in.failed"));
            Assert.That(tags["ashlar.outcome"], Is.EqualTo(AshlarSecurityEventWebhookDeliveryTelemetry.FailureOutcome));
            Assert.That(tags["ashlar.failure_kind"], Is.EqualTo(AshlarSecurityEventWebhookDeliveryTelemetry.TimeoutFailureKind));
            Assert.That(tags["ashlar.endpoint_name"], Is.EqualTo("audit"));
        }
    }

    [Test]
    public void RecordDeliveryAttemptDoesNotEmitUnsafeDefaultTags()
    {
        using var listener = new RecordingMeterListener();
        using var observer = CreateObserver(new AshlarSecurityEventWebhookMetricsOptions { MeterName = listener.MeterName });
        var unsafeValues = new[]
        {
            "body-secret",
            "shared-secret",
            "raw exception text",
            "22222222-2222-2222-2222-222222222222",
            "55555555-5555-5555-5555-555555555555",
            "203.0.113.10",
            "Sensitive Browser",
            "correlation-1",
            "lock-owner"
        };

        observer.RecordDeliveryAttempt(CreateTelemetry(
            AshlarSecurityEventWebhookDeliveryTelemetry.FailureOutcome,
            AshlarSecurityEventWebhookDeliveryTelemetry.ExceptionFailureKind,
            endpointName: "22222222-2222-2222-2222-222222222222"));

        var tagValues = listener.LongMeasurements.First().Tags.Values.Select(value => value?.ToString()).ToArray();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(listener.LongMeasurements.First().Tags.ContainsKey("ashlar.endpoint_name"), Is.False);
            foreach (var unsafeValue in unsafeValues)
            {
                Assert.That(tagValues, Does.Not.Contain(unsafeValue));
            }
        }
    }

    [Test]
    public void RecordDeliveryAttemptCanDisableDurationHistogramAndIgnoresUnknownOutcomeCounters()
    {
        using var listener = new RecordingMeterListener();
        using var observer = CreateObserver(new AshlarSecurityEventWebhookMetricsOptions
        {
            MeterName = listener.MeterName,
            EmitDurationHistogram = false
        });

        observer.RecordDeliveryAttempt(CreateTelemetry("deferred"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(listener.LongMeasurements.Single().InstrumentName, Is.EqualTo(AshlarSecurityEventWebhookMetricsObserver.DeliveryAttemptsCounterName));
            Assert.That(listener.DoubleMeasurements, Is.Empty);
        }
    }

    [Test]
    public void RecordDeliveryAttemptSanitizesUnsafeOutcomeTagAndIgnoresOutcomeCounters()
    {
        using var listener = new RecordingMeterListener();
        using var observer = CreateObserver(new AshlarSecurityEventWebhookMetricsOptions
        {
            MeterName = listener.MeterName,
            EmitDurationHistogram = false
        });

        observer.RecordDeliveryAttempt(CreateTelemetry("failure\r\nraw exception text"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(listener.LongMeasurements.Single().InstrumentName, Is.EqualTo(AshlarSecurityEventWebhookMetricsObserver.DeliveryAttemptsCounterName));
            Assert.That(listener.LongMeasurements.Single().Tags["ashlar.outcome"], Is.EqualTo("unknown"));
            Assert.That(listener.DoubleMeasurements, Is.Empty);
        }
    }

    [Test]
    public void RecordDeliveryAttemptUsesUnknownTagsAndDefaultMeterName()
    {
        using var listener = new RecordingMeterListener(AshlarSecurityEventWebhookMetricsOptions.DefaultMeterName);
        using var observer = CreateObserver(new AshlarSecurityEventWebhookMetricsOptions
        {
            MeterName = " ",
            IncludeEndpointName = true
        });

        observer.RecordDeliveryAttempt(new AshlarSecurityEventWebhookDeliveryTelemetry(
            " ",
            null,
            " ",
            AshlarSecurityEventWebhookDeliveryTelemetry.FailureOutcome,
            null,
            TimeSpan.Zero));

        var tags = listener.LongMeasurements.First().Tags;
        using (Assert.EnterMultipleScope())
        {
            Assert.That(tags["ashlar.delivery_mode"], Is.EqualTo("unknown"));
            Assert.That(tags["ashlar.event_type"], Is.EqualTo("unknown"));
            Assert.That(tags["ashlar.failure_kind"], Is.EqualTo("unknown"));
            Assert.That(tags["ashlar.endpoint_name"], Is.EqualTo("unknown"));
        }
    }

    [Test]
    public void RecordDeliveryAttemptSanitizesUnsafeTelemetryTagValues()
    {
        using var listener = new RecordingMeterListener();
        using var observer = CreateObserver(new AshlarSecurityEventWebhookMetricsOptions
        {
            MeterName = listener.MeterName,
            IncludeEndpointName = true
        });

        observer.RecordDeliveryAttempt(new AshlarSecurityEventWebhookDeliveryTelemetry(
            "durable\r\noutbox",
            "security.test\r\nbody-secret",
            "audit\r\nshared-secret",
            AshlarSecurityEventWebhookDeliveryTelemetry.FailureOutcome,
            "timeout\r\nraw exception text",
            TimeSpan.FromMilliseconds(12.5)));

        var tags = listener.LongMeasurements.First(measurement => measurement.InstrumentName == AshlarSecurityEventWebhookMetricsObserver.DeliveryFailuresCounterName).Tags;
        using (Assert.EnterMultipleScope())
        {
            Assert.That(tags["ashlar.delivery_mode"], Is.EqualTo("unknown"));
            Assert.That(tags["ashlar.event_type"], Is.EqualTo("unknown"));
            Assert.That(tags["ashlar.outcome"], Is.EqualTo(AshlarSecurityEventWebhookDeliveryTelemetry.FailureOutcome));
            Assert.That(tags["ashlar.failure_kind"], Is.EqualTo("unknown"));
            Assert.That(tags["ashlar.endpoint_name"], Is.EqualTo("unknown"));
        }
    }

    [Test]
    public void RecordDeliveryAttemptRejectsNullArguments()
    {
        using var observer = CreateObserver();

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => new AshlarSecurityEventWebhookMetricsObserver(null!));
            Assert.Throws<ArgumentNullException>(() => observer.RecordDeliveryAttempt(null!));
        }
    }

    private static AshlarSecurityEventWebhookMetricsObserver CreateObserver(AshlarSecurityEventWebhookMetricsOptions? options = null)
    {
        return new AshlarSecurityEventWebhookMetricsObserver(Options.Create(options ?? new AshlarSecurityEventWebhookMetricsOptions()));
    }

    private static AshlarSecurityEventWebhookDeliveryTelemetry CreateTelemetry(
        string outcome,
        string? failureKind = null,
        string? endpointName = "audit")
    {
        return new AshlarSecurityEventWebhookDeliveryTelemetry(
            AshlarSecurityEventWebhookDeliveryTelemetry.BestEffortDeliveryMode,
            "ashlar.sign_in.failed",
            endpointName,
            outcome,
            failureKind,
            TimeSpan.FromMilliseconds(12.5));
    }

    private sealed class RecordingMeterListener : IDisposable
    {
        private readonly MeterListener _listener = new();

        public RecordingMeterListener(string? meterName = null)
        {
            MeterName = meterName ?? $"Ashlar.Webhooks.Tests.{Guid.NewGuid():N}";
            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == MeterName)
                {
                    listener.EnableMeasurementEvents(instrument);
                }
            };
            _listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) =>
            {
                LongMeasurements.Add(new RecordedMeasurement<long>(instrument.Name, value, ToDictionary(tags)));
            });
            _listener.SetMeasurementEventCallback<double>((instrument, value, tags, _) =>
            {
                DoubleMeasurements.Add(new RecordedMeasurement<double>(instrument.Name, value, ToDictionary(tags)));
            });
            _listener.Start();
        }

        public string MeterName { get; }

        public List<RecordedMeasurement<long>> LongMeasurements { get; } = [];

        public List<RecordedMeasurement<double>> DoubleMeasurements { get; } = [];

        public void Dispose()
        {
            _listener.Dispose();
        }

        private static Dictionary<string, object?> ToDictionary(ReadOnlySpan<KeyValuePair<string, object?>> tags)
        {
            var dictionary = new Dictionary<string, object?>(StringComparer.Ordinal);
            foreach (var tag in tags)
            {
                dictionary.Add(tag.Key, tag.Value);
            }

            return dictionary;
        }
    }

    private sealed record RecordedMeasurement<T>(string InstrumentName, T Value, IReadOnlyDictionary<string, object?> Tags);
}
