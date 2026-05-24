using Ashlar.Auditing;
using Ashlar.Testing;

namespace Ashlar.Tests.Auditing;

internal sealed class SecurityEventFanOutSinkTests
{
    private static readonly string[] PersistentThenHandler = ["persistent", "handler"];

    [Test]
    public async Task RecordAsyncRecordsToPersistentSinkWhenConfigured()
    {
        var persistentSink = new RecordingPersistentSink();
        var securityEvent = CreateEvent();
        var sink = new SecurityEventFanOutSink(persistentSink);

        await sink.RecordAsync(securityEvent);

        Assert.That(persistentSink.Events, Is.EqualTo(new[] { securityEvent }));
    }

    [Test]
    public async Task RecordAsyncInvokesAllHandlers()
    {
        var first = new RecordingHandler();
        var second = new RecordingHandler();
        var securityEvent = CreateEvent();
        var sink = new SecurityEventFanOutSink(handlers: [first, second]);

        await sink.RecordAsync(securityEvent);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(first.Events, Is.EqualTo(new[] { securityEvent }));
            Assert.That(second.Events, Is.EqualTo(new[] { securityEvent }));
        }
    }

    [Test]
    public async Task RecordAsyncRecordsToPersistentSinkBeforeHandlers()
    {
        List<string> calls = [];
        var persistentSink = new RecordingPersistentSink(calls, "persistent");
        var handler = new RecordingHandler(calls, "handler");
        var sink = new SecurityEventFanOutSink(persistentSink, [handler]);

        await sink.RecordAsync(CreateEvent());

        Assert.That(calls, Is.EqualTo(PersistentThenHandler));
    }

    [Test]
    public async Task RecordAsyncLogsHandlerFailureAndContinues()
    {
        var logger = new RecordingLogger<SecurityEventFanOutSink>();
        var first = new ThrowingHandler(new InvalidOperationException("handler failed"));
        var second = new RecordingHandler();
        var securityEvent = CreateEvent();
        var sink = new SecurityEventFanOutSink(handlers: [first, second], logger: logger);

        await sink.RecordAsync(securityEvent);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(second.Events, Is.EqualTo(new[] { securityEvent }));
            Assert.That(logger.Entries, Has.Count.EqualTo(1));
            Assert.That(logger.Entries[0].Message, Does.Contain("Security event handler failed"));
            Assert.That(logger.Entries[0].Message, Does.Contain("EventType=test.event"));
            Assert.That(logger.Entries[0].Exception, Is.TypeOf<InvalidOperationException>());
        }
    }

    [Test]
    public async Task RecordAsyncLogsPersistentSinkFailureAndContinuesToHandlers()
    {
        var logger = new RecordingLogger<SecurityEventFanOutSink>();
        var handler = new RecordingHandler();
        var securityEvent = CreateEvent();
        var sink = new SecurityEventFanOutSink(
            new ThrowingPersistentSink(new InvalidOperationException("persistent failed")),
            [handler],
            logger);

        await sink.RecordAsync(securityEvent);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(handler.Events, Is.EqualTo(new[] { securityEvent }));
            Assert.That(logger.Entries, Has.Count.EqualTo(1));
            Assert.That(logger.Entries[0].Message, Does.Contain("Persistent security event sink failed"));
            Assert.That(logger.Entries[0].Exception, Is.TypeOf<InvalidOperationException>());
        }
    }

    [Test]
    public async Task RecordAsyncLogsPersistentSinkFailureForNullProvider()
    {
        var logger = new RecordingLogger<SecurityEventFanOutSink>();
        var securityEvent = CreateEventWithNullProvider();
        var sink = new SecurityEventFanOutSink(
            new ThrowingPersistentSink(new InvalidOperationException("persistent failed")),
            logger: logger);

        await sink.RecordAsync(securityEvent);

        Assert.That(logger.Entries.Single().Message, Does.Contain("ProviderName=(null)"));
    }

    [Test]
    public void RecordAsyncRethrowsPersistentSinkCallerCancellation()
    {
        using var cancellation = new CancellationTokenSource();
        var sink = new SecurityEventFanOutSink(new CancelingPersistentSink(cancellation));

        Assert.ThrowsAsync<OperationCanceledException>(async () => await sink.RecordAsync(CreateEvent(), cancellation.Token));
    }

    [Test]
    public void RecordAsyncRespectsCallerCancellationBeforePersistentSink()
    {
        var persistentSink = new RecordingPersistentSink();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var sink = new SecurityEventFanOutSink(persistentSink);

        Assert.ThrowsAsync<OperationCanceledException>(async () => await sink.RecordAsync(CreateEvent(), cancellation.Token));
        Assert.That(persistentSink.Events, Is.Empty);
    }

    [Test]
    public void RecordAsyncStopsBeforeLaterHandlersWhenCallerCancellationIsRequested()
    {
        using var cancellation = new CancellationTokenSource();
        var first = new CancelingHandler(cancellation);
        var second = new RecordingHandler();
        var sink = new SecurityEventFanOutSink(handlers: [first, second]);

        Assert.ThrowsAsync<OperationCanceledException>(async () => await sink.RecordAsync(CreateEvent(), cancellation.Token));
        Assert.That(second.Events, Is.Empty);
    }

    [Test]
    public void RecordAsyncThrowsForNullEvent()
    {
        var sink = new SecurityEventFanOutSink();

        var exception = Assert.ThrowsAsync<ArgumentNullException>(async () => await sink.RecordAsync(null!));

        Assert.That(exception?.ParamName, Is.EqualTo("securityEvent"));
    }

    private static AshlarSecurityEvent CreateEvent(AuthenticationProviderKey? provider = null)
    {
        return CreateEventCore(provider ?? new AuthenticationProviderKey(ProviderType.Local, "Password"));
    }

    private static AshlarSecurityEvent CreateEventWithNullProvider()
    {
        return CreateEventCore(null);
    }

    private static AshlarSecurityEvent CreateEventCore(AuthenticationProviderKey? provider)
    {
        return new AshlarSecurityEvent
        {
            Id = Guid.NewGuid(),
            EventType = "test.event",
            OccurredAt = DateTimeOffset.UtcNow,
            UserId = Guid.NewGuid(),
            SessionId = Guid.NewGuid(),
            Provider = provider
        };
    }

    private sealed class RecordingPersistentSink(List<string>? calls = null, string? callName = null) : IPersistentSecurityEventSink
    {
        public List<AshlarSecurityEvent> Events { get; } = [];

        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Events.Add(securityEvent);
            if (callName != null)
            {
                calls?.Add(callName);
            }

            return Task.CompletedTask;
        }
    }

    private sealed class ThrowingPersistentSink(Exception exception) : IPersistentSecurityEventSink
    {
        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            return Task.FromException(exception);
        }
    }

    private sealed class CancelingPersistentSink(CancellationTokenSource cancellation) : IPersistentSecurityEventSink
    {
        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            cancellation.Cancel();
            throw new OperationCanceledException(cancellation.Token);
        }
    }

    private sealed class RecordingHandler(List<string>? calls = null, string? callName = null) : ISecurityEventHandler
    {
        public List<AshlarSecurityEvent> Events { get; } = [];

        public Task HandleAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Events.Add(securityEvent);
            if (callName != null)
            {
                calls?.Add(callName);
            }

            return Task.CompletedTask;
        }
    }

    private sealed class ThrowingHandler(Exception exception) : ISecurityEventHandler
    {
        public Task HandleAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            return Task.FromException(exception);
        }
    }

    private sealed class CancelingHandler(CancellationTokenSource cancellation) : ISecurityEventHandler
    {
        public Task HandleAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            cancellation.Cancel();
            throw new OperationCanceledException(cancellation.Token);
        }
    }
}
