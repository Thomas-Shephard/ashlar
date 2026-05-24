using System.Diagnostics.Metrics;
using Ashlar.Auditing;
using Ashlar.Identity.Models.Authentication;
using Ashlar.Observability.SecurityEvents;
using Microsoft.Extensions.Options;

namespace Ashlar.Observability.Tests;

internal sealed class AshlarSecurityEventMetricsHandlerTests
{
    [Test]
    public async Task HandleAsyncRecordsTotalCounterByDefault()
    {
        using var listener = new RecordingMeterListener();
        using var handler = CreateHandler(new AshlarSecurityEventMetricsOptions { MeterName = listener.MeterName });

        await handler.HandleAsync(CreateEvent(SecurityEventOutcomes.Failure));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(listener.Measurements, Has.Count.EqualTo(1));
            Assert.That(listener.Measurements.Single().InstrumentName, Is.EqualTo(AshlarSecurityEventMetricsHandler.TotalEventsCounterName));
            Assert.That(listener.Measurements.Single().Value, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task HandleAsyncCanRecordSuccessCounter()
    {
        using var listener = new RecordingMeterListener();
        using var handler = CreateHandler(new AshlarSecurityEventMetricsOptions
        {
            MeterName = listener.MeterName,
            EmitOutcomeCounters = true
        });

        await handler.HandleAsync(CreateEvent(SecurityEventOutcomes.Success));

        Assert.That(listener.Measurements.Select(measurement => measurement.InstrumentName), Does.Contain(AshlarSecurityEventMetricsHandler.SuccessEventsCounterName));
    }

    [Test]
    public async Task HandleAsyncCanRecordFailureCounter()
    {
        using var listener = new RecordingMeterListener();
        using var handler = CreateHandler(new AshlarSecurityEventMetricsOptions
        {
            MeterName = listener.MeterName,
            EmitOutcomeCounters = true
        });

        await handler.HandleAsync(CreateEvent(SecurityEventOutcomes.Failure));

        Assert.That(listener.Measurements.Select(measurement => measurement.InstrumentName), Does.Contain(AshlarSecurityEventMetricsHandler.FailureEventsCounterName));
    }

    [Test]
    public async Task HandleAsyncDoesNotRecordOutcomeCounterForUnknownOutcome()
    {
        using var listener = new RecordingMeterListener();
        using var handler = CreateHandler(new AshlarSecurityEventMetricsOptions
        {
            MeterName = listener.MeterName,
            EmitOutcomeCounters = true
        });

        await handler.HandleAsync(CreateEvent("challenge"));

        Assert.That(listener.Measurements.Single().InstrumentName, Is.EqualTo(AshlarSecurityEventMetricsHandler.TotalEventsCounterName));
    }

    [Test]
    public async Task HandleAsyncCanDisableSplitOutcomeCounters()
    {
        using var listener = new RecordingMeterListener();
        using var handler = CreateHandler(new AshlarSecurityEventMetricsOptions
        {
            MeterName = listener.MeterName,
            EmitOutcomeCounters = false
        });

        await handler.HandleAsync(CreateEvent(SecurityEventOutcomes.Failure));

        Assert.That(listener.Measurements.Single().InstrumentName, Is.EqualTo(AshlarSecurityEventMetricsHandler.TotalEventsCounterName));
    }

    [Test]
    public async Task HandleAsyncEmitsSafeDefaultTags()
    {
        using var listener = new RecordingMeterListener();
        using var handler = CreateHandler(new AshlarSecurityEventMetricsOptions { MeterName = listener.MeterName });
        var securityEvent = CreateEvent(SecurityEventOutcomes.Failure);

        await handler.HandleAsync(securityEvent);

        var tags = listener.Measurements.First().Tags;
        using (Assert.EnterMultipleScope())
        {
            Assert.That(tags["ashlar.event_type"], Is.EqualTo(securityEvent.EventType));
            Assert.That(tags["ashlar.outcome"], Is.EqualTo(SecurityEventOutcomes.Failure));
            Assert.That(tags["ashlar.provider_type"], Is.EqualTo(ProviderType.Oidc.Value));
            Assert.That(tags.ContainsKey("ashlar.provider_name"), Is.False);
            Assert.That(tags.Values, Does.Not.Contain(securityEvent.UserId.ToString()));
            Assert.That(tags.Values, Does.Not.Contain(securityEvent.SessionId.ToString()));
            Assert.That(tags.Values, Does.Not.Contain(securityEvent.TenantId.ToString()));
            Assert.That(tags.Values, Does.Not.Contain(securityEvent.IpAddress));
            Assert.That(tags.Values, Does.Not.Contain(securityEvent.UserAgent));
            Assert.That(tags.Values, Does.Not.Contain(securityEvent.CorrelationId));
        }
    }

    [Test]
    public async Task HandleAsyncCanIncludeProviderName()
    {
        using var listener = new RecordingMeterListener();
        using var handler = CreateHandler(new AshlarSecurityEventMetricsOptions
        {
            MeterName = listener.MeterName,
            IncludeProviderName = true
        });

        await handler.HandleAsync(CreateEvent(SecurityEventOutcomes.Success));

        Assert.That(listener.Measurements.First().Tags["ashlar.provider_name"], Is.EqualTo("Contoso"));
    }

    [Test]
    public async Task HandleAsyncUsesUnknownTagValueForPartialEvents()
    {
        using var listener = new RecordingMeterListener();
        using var handler = CreateHandler(new AshlarSecurityEventMetricsOptions
        {
            MeterName = listener.MeterName,
            IncludeProviderName = true
        });
        var securityEvent = new AshlarSecurityEvent
        {
            Id = Guid.NewGuid(),
            EventType = " ",
            OccurredAt = DateTimeOffset.UtcNow
        };

        await handler.HandleAsync(securityEvent);

        var tags = listener.Measurements.Single().Tags;
        using (Assert.EnterMultipleScope())
        {
            Assert.That(tags["ashlar.event_type"], Is.EqualTo("unknown"));
            Assert.That(tags["ashlar.outcome"], Is.EqualTo("unknown"));
            Assert.That(tags["ashlar.provider_type"], Is.EqualTo("unknown"));
            Assert.That(tags["ashlar.provider_name"], Is.EqualTo("unknown"));
        }
    }

    [Test]
    public async Task HandleAsyncFallsBackToDefaultMeterNameWhenConfiguredMeterNameIsBlank()
    {
        using var listener = new RecordingMeterListener(AshlarSecurityEventMetricsOptions.DefaultMeterName);
        using var handler = CreateHandler(new AshlarSecurityEventMetricsOptions { MeterName = " " });

        await handler.HandleAsync(CreateEvent(SecurityEventOutcomes.Success));

        Assert.That(listener.Measurements, Is.Not.Empty);
    }

    [Test]
    public void HandleAsyncThrowsForNullEvent()
    {
        using var handler = CreateHandler();

        var exception = Assert.ThrowsAsync<ArgumentNullException>(async () => await handler.HandleAsync(null!));

        Assert.That(exception?.ParamName, Is.EqualTo("securityEvent"));
    }

    [Test]
    public void HandleAsyncRespectsCallerCancellation()
    {
        using var handler = CreateHandler();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        Assert.ThrowsAsync<OperationCanceledException>(async () => await handler.HandleAsync(CreateEvent(SecurityEventOutcomes.Success), cancellation.Token));
    }

    [Test]
    public void ConstructorThrowsForNullOptions()
    {
        var exception = Assert.Throws<ArgumentNullException>(() => new AshlarSecurityEventMetricsHandler(null!));

        Assert.That(exception?.ParamName, Is.EqualTo("options"));
    }

    private static AshlarSecurityEventMetricsHandler CreateHandler(AshlarSecurityEventMetricsOptions? options = null)
    {
        return new AshlarSecurityEventMetricsHandler(Options.Create(options ?? new AshlarSecurityEventMetricsOptions()));
    }

    private static AshlarSecurityEvent CreateEvent(string? outcome)
    {
        return new AshlarSecurityEvent
        {
            Id = Guid.NewGuid(),
            EventType = "identity.sign_in",
            OccurredAt = DateTimeOffset.UtcNow,
            UserId = Guid.NewGuid(),
            TenantId = Guid.NewGuid(),
            ActorUserId = Guid.NewGuid(),
            SessionId = Guid.NewGuid(),
            Provider = new AuthenticationProviderKey(ProviderType.Oidc, "Contoso"),
            IpAddress = "203.0.113.10",
            UserAgent = "Browser",
            CorrelationId = "correlation-1",
            Outcome = outcome,
            FailureReason = "invalid_code",
            Properties = new Dictionary<string, string> { ["token_hash"] = "secret" }
        };
    }

    private sealed class RecordingMeterListener : IDisposable
    {
        private readonly MeterListener _listener = new();

        public RecordingMeterListener(string? meterName = null)
        {
            MeterName = meterName ?? $"Ashlar.SecurityEvents.Tests.{Guid.NewGuid():N}";
            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == MeterName)
                {
                    listener.EnableMeasurementEvents(instrument);
                }
            };
            _listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) =>
            {
                Measurements.Add(new RecordedMeasurement(instrument.Name, value, ToDictionary(tags)));
            });
            _listener.Start();
        }

        public string MeterName { get; }

        public List<RecordedMeasurement> Measurements { get; } = [];

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

    private sealed record RecordedMeasurement(string InstrumentName, long Value, IReadOnlyDictionary<string, object?> Tags);
}
