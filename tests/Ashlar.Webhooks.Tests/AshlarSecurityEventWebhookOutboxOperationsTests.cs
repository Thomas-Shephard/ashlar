using Ashlar.Auditing;
using Ashlar.Webhooks.SecurityEvents;

namespace Ashlar.Webhooks.Tests;

internal sealed class AshlarSecurityEventWebhookOutboxOperationsTests
{
    private static readonly DateTimeOffset Now = new(2026, 5, 31, 12, 0, 0, TimeSpan.Zero);
    private static readonly string[] FullAuditPropertyNames = ["delivery_id", "endpoint_name", "event_id", "event_type", "outcome"];
    private static readonly string[] MinimalAuditPropertyNames = ["delivery_id"];

    [Test]
    public void ValidateRequestRejectsInvalidRequests()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => AshlarSecurityEventWebhookOutboxOperations.ValidateRequest(null!));
            Assert.Throws<ArgumentException>(() => AshlarSecurityEventWebhookOutboxOperations.ValidateRequest(new AshlarSecurityEventWebhookOutboxOperationRequest(Guid.Empty, new AuditContext())));
            Assert.Throws<ArgumentNullException>(() => AshlarSecurityEventWebhookOutboxOperations.ValidateRequest(new AshlarSecurityEventWebhookOutboxOperationRequest(Guid.NewGuid(), null!)));
        }
    }

    [Test]
    public void CreateResultSanitizesPublicFields()
    {
        var eventId = Guid.NewGuid();

        var safe = AshlarSecurityEventWebhookOutboxOperations.CreateResult(
            AshlarSecurityEventWebhookOutboxOperationStatus.Retried,
            Guid.NewGuid(),
            "endpoint",
            eventId,
            "event.type",
            "success");
        var unsafeResult = AshlarSecurityEventWebhookOutboxOperations.CreateResult(
            AshlarSecurityEventWebhookOutboxOperationStatus.Discarded,
            Guid.NewGuid(),
            "bad\nendpoint",
            null,
            "bad\revent",
            " ");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(safe.EndpointName, Is.EqualTo("endpoint"));
            Assert.That(safe.EventId, Is.EqualTo(eventId));
            Assert.That(safe.EventType, Is.EqualTo("event.type"));
            Assert.That(safe.Outcome, Is.EqualTo("success"));
            Assert.That(unsafeResult.EndpointName, Is.Null);
            Assert.That(unsafeResult.EventId, Is.Null);
            Assert.That(unsafeResult.EventType, Is.Null);
            Assert.That(unsafeResult.Outcome, Is.Null);
        }
    }

    [Test]
    public async Task RecordSuccessfulOperationAsyncEmitsSafeAuditProperties()
    {
        var sink = new RecordingSecurityEventSink();
        var time = new FixedTimeProvider(Now);
        var actorUserId = Guid.NewGuid();
        var deliveryId = Guid.NewGuid();
        var eventId = Guid.NewGuid();
        var request = new AshlarSecurityEventWebhookOutboxOperationRequest(
            deliveryId,
            new AuditContext(actorUserId, "203.0.113.10", "agent", "corr", new Dictionary<string, string> { ["ignored"] = "ignored" }));
        var result = AshlarSecurityEventWebhookOutboxOperations.CreateResult(
            AshlarSecurityEventWebhookOutboxOperationStatus.Retried,
            deliveryId,
            "endpoint",
            eventId,
            "event.type",
            "success");

        await AshlarSecurityEventWebhookOutboxOperations.RecordSuccessfulOperationAsync(
            sink,
            time,
            AshlarSecurityEventTypes.SecurityEventWebhookOutboxDeliveryRetried,
            request,
            result,
            CancellationToken.None);

        var securityEvent = sink.Events.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(securityEvent.EventType, Is.EqualTo(AshlarSecurityEventTypes.SecurityEventWebhookOutboxDeliveryRetried));
            Assert.That(securityEvent.Outcome, Is.EqualTo(SecurityEventOutcomes.Success));
            Assert.That(securityEvent.OccurredAt, Is.EqualTo(time.GetUtcNow()));
            Assert.That(securityEvent.ActorUserId, Is.EqualTo(actorUserId));
            Assert.That(securityEvent.IpAddress, Is.EqualTo("203.0.113.10"));
            Assert.That(securityEvent.UserAgent, Is.EqualTo("agent"));
            Assert.That(securityEvent.CorrelationId, Is.EqualTo("corr"));
            Assert.That(securityEvent.Properties, Does.ContainKey("delivery_id").WithValue(deliveryId.ToString("D")));
            Assert.That(securityEvent.Properties, Does.ContainKey("endpoint_name").WithValue("endpoint"));
            Assert.That(securityEvent.Properties, Does.ContainKey("event_id").WithValue(eventId.ToString("D")));
            Assert.That(securityEvent.Properties, Does.ContainKey("event_type").WithValue("event.type"));
            Assert.That(securityEvent.Properties, Does.ContainKey("outcome").WithValue("success"));
            Assert.That(securityEvent.Properties!.Keys, Is.EquivalentTo(FullAuditPropertyNames));
        }
    }

    [Test]
    public async Task RecordSuccessfulOperationAsyncOmitsAbsentPropertiesAndFailsOpen()
    {
        var request = new AshlarSecurityEventWebhookOutboxOperationRequest(Guid.NewGuid(), new AuditContext());
        var result = AshlarSecurityEventWebhookOutboxOperations.CreateResult(
            AshlarSecurityEventWebhookOutboxOperationStatus.Discarded,
            request.DeliveryId);

        var sink = new RecordingSecurityEventSink();
        await AshlarSecurityEventWebhookOutboxOperations.RecordSuccessfulOperationAsync(
            sink,
            TimeProvider.System,
            AshlarSecurityEventTypes.SecurityEventWebhookOutboxDeliveryDiscarded,
            request,
            result,
            CancellationToken.None);

        Assert.That(sink.Events.Single().Properties!.Keys, Is.EquivalentTo(MinimalAuditPropertyNames));
        Assert.DoesNotThrowAsync(async () => await AshlarSecurityEventWebhookOutboxOperations.RecordSuccessfulOperationAsync(
            new ThrowingSecurityEventSink(new InvalidOperationException("boom")),
            TimeProvider.System,
            AshlarSecurityEventTypes.SecurityEventWebhookOutboxDeliveryDiscarded,
            request,
            result,
            CancellationToken.None));
        Assert.DoesNotThrowAsync(async () => await AshlarSecurityEventWebhookOutboxOperations.RecordSuccessfulOperationAsync(
            new ThrowingSecurityEventSink(new OperationCanceledException()),
            TimeProvider.System,
            AshlarSecurityEventTypes.SecurityEventWebhookOutboxDeliveryDiscarded,
            request,
            result,
            CancellationToken.None));
    }

    private sealed class RecordingSecurityEventSink : ISecurityEventSink
    {
        public List<AshlarSecurityEvent> Events { get; } = [];

        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            Events.Add(securityEvent);
            return Task.CompletedTask;
        }
    }

    private sealed class ThrowingSecurityEventSink(Exception exception) : ISecurityEventSink
    {
        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            throw exception;
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return now;
        }
    }
}
