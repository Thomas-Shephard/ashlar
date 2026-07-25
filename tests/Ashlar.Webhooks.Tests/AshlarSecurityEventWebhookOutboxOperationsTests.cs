using Ashlar.Auditing;
using Ashlar.Identity.Abstractions.Transactions;
using Ashlar.Identity.Abstractions.Services;
using Ashlar.Identity.Models.AccountSecurity;
using Ashlar.Testing;
using Ashlar.Webhooks.SecurityEvents;

namespace Ashlar.Webhooks.Tests;

internal sealed class AshlarSecurityEventWebhookOutboxOperationsTests
{
    private static readonly DateTimeOffset Now = new(2026, 5, 31, 12, 0, 0, TimeSpan.Zero);
    private static readonly string[] FullAuditPropertyNames = ["delivery_id", "endpoint_name", "event_id", "event_type", "outcome"];
    private static readonly string[] MinimalAuditPropertyNames = ["delivery_id"];
    private static readonly AccountSecurityActorTestContext Security = new(Now, IAccountSecurityAdministrationService.ProofPurpose);

    [Test]
    public void ValidateRequestRejectsInvalidRequests()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => AshlarSecurityEventWebhookOutboxOperations.ValidateRequest(null!));
            Assert.Throws<ArgumentException>(() => AshlarSecurityEventWebhookOutboxOperations.ValidateRequest(new AshlarSecurityEventWebhookOutboxOperationRequest(Guid.Empty, Security.Actor)));
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
        var actorUserId = Security.Actor.ActorUserId;
        var deliveryId = Guid.NewGuid();
        var eventId = Guid.NewGuid();
        var request = new AshlarSecurityEventWebhookOutboxOperationRequest(
            deliveryId,
            new AccountSecurityActorContext(actorUserId, Security.Actor.ActorTenant, Security.Actor.CurrentSessionId,
                Security.Actor.FreshMfaProof, new AuditContext(actorUserId, "203.0.113.10", "agent", "corr", new Dictionary<string, string> { ["ignored"] = "ignored" })));
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
    public async Task RecordSuccessfulOperationAsyncOmitsAbsentPropertiesAndPropagatesAuditFailures()
    {
        var request = new AshlarSecurityEventWebhookOutboxOperationRequest(Guid.NewGuid(), Security.Actor);
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
        Assert.ThrowsAsync<InvalidOperationException>(async () => await AshlarSecurityEventWebhookOutboxOperations.RecordSuccessfulOperationAsync(
            new ThrowingSecurityEventSink(new InvalidOperationException("boom")),
            TimeProvider.System,
            AshlarSecurityEventTypes.SecurityEventWebhookOutboxDeliveryDiscarded,
            request,
            result,
            CancellationToken.None));
        Assert.ThrowsAsync<OperationCanceledException>(async () => await AshlarSecurityEventWebhookOutboxOperations.RecordSuccessfulOperationAsync(
            new ThrowingSecurityEventSink(new OperationCanceledException()),
            TimeProvider.System,
            AshlarSecurityEventTypes.SecurityEventWebhookOutboxDeliveryDiscarded,
            request,
            result,
            CancellationToken.None));
    }

    [Test]
    public void ServiceBaseRequiresAuditAndTransactionDependencies()
    {
        var sink = new RecordingSecurityEventSink();
        Assert.Throws<ArgumentNullException>(() => new TestWebhookOutboxOperations(null!, new RecordingTransactionProvider()));
        Assert.Throws<ArgumentNullException>(() => new TestWebhookOutboxOperations(sink, null!));
    }

    [Test]
    public async Task ServiceBaseCommitsOperationWithTransactionProvider()
    {
        var sink = new RecordingSecurityEventSink();
        var transactionProvider = new RecordingTransactionProvider();
        var operations = new TestWebhookOutboxOperations(sink, transactionProvider);

        var result = await operations.RetryAsync(new AshlarSecurityEventWebhookOutboxOperationRequest(Guid.NewGuid(), Security.Actor));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarSecurityEventWebhookOutboxOperationStatus.Retried));
            Assert.That(transactionProvider.Transaction.CommitCount, Is.EqualTo(1));
            Assert.That(transactionProvider.Transaction.DisposeCount, Is.EqualTo(1));
        }
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

    private sealed class TestWebhookOutboxOperations(
        ISecurityEventSink sink,
        IAshlarTransactionProvider transactionProvider)
        : AshlarSecurityEventWebhookOutboxOperationsBase(new FixedTimeProvider(Now), sink, DurableTransactionComposition.Create(transactionProvider),
            Security.Sessions, Security.Authorizer, Security.AuditSink)
    {
        protected override Task<AshlarSecurityEventWebhookOutboxOperationState?> RetryFailedAsync(Guid deliveryId, CancellationToken cancellationToken)
        {
            return Task.FromResult<AshlarSecurityEventWebhookOutboxOperationState?>(new(deliveryId, "endpoint", Guid.NewGuid(), "event.type", "failed", IsDiscarded: false));
        }

        protected override Task<AshlarSecurityEventWebhookOutboxOperationState?> DiscardFailedAsync(Guid deliveryId, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        protected override Task<AshlarSecurityEventWebhookOutboxOperationState?> LoadAsync(Guid deliveryId, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }
    }

    private sealed class RecordingTransactionProvider : IAshlarTransactionProvider
    {
        public RecordingTransaction Transaction { get; } = new();

        public Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IAshlarTransaction>(Transaction);
        }
    }

    private sealed class RecordingTransaction : IAshlarTransaction
    {
        private readonly List<Func<CancellationToken, Task>> _hooks = [];
        private bool _completed;
        public int CommitCount { get; private set; }
        public int DisposeCount { get; private set; }

        public async Task CommitAsync(CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(_completed, this);
            CommitCount++;
            _completed = true;
            foreach (var hook in _hooks)
            {
                try
                {
                    await hook(CancellationToken.None);
                }
                catch (Exception)
                {
                }
            }
        }

        public Task RollbackAsync(CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(_completed, this);
            _hooks.Clear();
            _completed = true;
            return Task.CompletedTask;
        }

        public void OnCommitted(Func<CancellationToken, Task> action)
        {
            ObjectDisposedException.ThrowIf(_completed, this);
            _hooks.Add(action ?? throw new ArgumentNullException(nameof(action)));
        }

        public ValueTask DisposeAsync()
        {
            DisposeCount++;
            _completed = true;
            return ValueTask.CompletedTask;
        }
    }
}
