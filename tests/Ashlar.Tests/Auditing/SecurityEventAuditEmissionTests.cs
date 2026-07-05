using Ashlar.Auditing;

namespace Ashlar.Tests.Auditing;

internal sealed class SecurityEventAuditEmissionTests
{
    [Test]
    public async Task RecordCompletedOperationAsyncRecordsAuditEvent()
    {
        var sink = new CapturingSecurityEventSink();
        var actorUserId = Guid.NewGuid();
        var properties = new Dictionary<string, string> { ["operation_id"] = Guid.NewGuid().ToString("D") };

        await SecurityEventAuditEmission.RecordCompletedOperationAsync(
            sink,
            TimeProvider.System,
            "operation.completed",
            new AuditContext(actorUserId, "127.0.0.1", "tests", "correlation"),
            properties,
            CancellationToken.None);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(sink.Events, Has.Count.EqualTo(1));
            Assert.That(sink.Events[0].EventType, Is.EqualTo("operation.completed"));
            Assert.That(sink.Events[0].ActorUserId, Is.EqualTo(actorUserId));
            Assert.That(sink.Events[0].Properties, Is.SameAs(properties));
        }
    }

    [Test]
    public void RecordCompletedOperationAsyncValidatesInputs()
    {
        var sink = new CapturingSecurityEventSink();
        var audit = new AuditContext();
        var properties = new Dictionary<string, string>();

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentNullException>(() => SecurityEventAuditEmission.RecordCompletedOperationAsync(null!, TimeProvider.System, "event", audit, properties, CancellationToken.None));
            Assert.ThrowsAsync<ArgumentNullException>(() => SecurityEventAuditEmission.RecordCompletedOperationAsync(sink, null!, "event", audit, properties, CancellationToken.None));
            Assert.ThrowsAsync<ArgumentException>(() => SecurityEventAuditEmission.RecordCompletedOperationAsync(sink, TimeProvider.System, "", audit, properties, CancellationToken.None));
            Assert.ThrowsAsync<ArgumentNullException>(() => SecurityEventAuditEmission.RecordCompletedOperationAsync(sink, TimeProvider.System, "event", null!, properties, CancellationToken.None));
            Assert.ThrowsAsync<ArgumentNullException>(() => SecurityEventAuditEmission.RecordCompletedOperationAsync(sink, TimeProvider.System, "event", audit, null!, CancellationToken.None));
        }
    }

    [Test]
    public void RecordCompletedOperationAsyncPropagatesAuditSinkFailures()
    {
        var cancellationTokenSource = new CancellationTokenSource();
        var canceledBySink = new ThrowingSecurityEventSink(new OperationCanceledException());
        var failedBySink = new ThrowingSecurityEventSink(new InvalidOperationException("audit failed"));
        var externallyCanceled = new ThrowingSecurityEventSink(new OperationCanceledException(cancellationTokenSource.Token));

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<OperationCanceledException>(() => SecurityEventAuditEmission.RecordCompletedOperationAsync(
                canceledBySink,
                TimeProvider.System,
                "event",
                new AuditContext(),
                new Dictionary<string, string>(),
                CancellationToken.None));
            Assert.ThrowsAsync<InvalidOperationException>(() => SecurityEventAuditEmission.RecordCompletedOperationAsync(
                failedBySink,
                TimeProvider.System,
                "event",
                new AuditContext(),
                new Dictionary<string, string>(),
                CancellationToken.None));

            cancellationTokenSource.Cancel();
            Assert.ThrowsAsync<OperationCanceledException>(() => SecurityEventAuditEmission.RecordCompletedOperationAsync(
                externallyCanceled,
                TimeProvider.System,
                "event",
                new AuditContext(),
                new Dictionary<string, string>(),
                cancellationTokenSource.Token));
        }
    }

    private sealed class CapturingSecurityEventSink : ISecurityEventSink
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
}
