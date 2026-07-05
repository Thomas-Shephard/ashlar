using Ashlar.Auditing;
using Ashlar.Testing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Ashlar.Tests.Auditing;

internal sealed class PersistentSecurityEventSinkTests
{
    [Test]
    public void ConstructorThrowsIfLoggerIsNull()
    {
        Assert.Throws<ArgumentNullException>(() => _ = new TestSink(null!));
    }

    [Test]
    public async Task RecordAsyncPersistsBeforeReturning()
    {
        var sink = new TestSink();
        var securityEvent = new AshlarSecurityEvent
        {
            Id = Guid.NewGuid(),
            EventType = "test",
            OccurredAt = DateTimeOffset.UtcNow
        };

        await sink.RecordAsync(securityEvent);

        Assert.That(sink.Events, Is.EqualTo(new[] { securityEvent }));
    }

    [Test]
    public void RecordAsyncLogsAndRethrowsPersistenceFailure()
    {
        var logger = new RecordingLogger();
        var sink = new TestSink(logger, new InvalidOperationException("write failed"));
        var securityEvent = new AshlarSecurityEvent
        {
            Id = Guid.NewGuid(),
            EventType = "test",
            OccurredAt = DateTimeOffset.UtcNow,
            Provider = new AuthenticationProviderKey(ProviderType.Local, "Password")
        };

        var exception = Assert.ThrowsAsync<InvalidOperationException>(async () => await sink.RecordAsync(securityEvent));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exception?.Message, Is.EqualTo("write failed"));
            Assert.That(logger.Entries, Has.Count.EqualTo(1));
            Assert.That(logger.Entries[0].Message, Does.Contain("Security event persistence failed"));
            Assert.That(logger.Entries[0].Exception, Is.SameAs(exception));
        }
    }

    [Test]
    public void RecordAsyncLogsPersistenceFailureWithoutProvider()
    {
        var logger = new RecordingLogger();
        var sink = new TestSink(logger, new InvalidOperationException("write failed"));
        var securityEvent = new AshlarSecurityEvent
        {
            Id = Guid.NewGuid(),
            EventType = "test",
            OccurredAt = DateTimeOffset.UtcNow
        };

        Assert.ThrowsAsync<InvalidOperationException>(async () => await sink.RecordAsync(securityEvent));

        Assert.That(logger.Entries, Has.Count.EqualTo(1));
    }

    [Test]
    public void RecordAsyncRethrowsCallerCancellationWithoutLogging()
    {
        var logger = new RecordingLogger();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var sink = new TestSink(logger, new OperationCanceledException(cancellation.Token));

        Assert.ThrowsAsync<OperationCanceledException>(async () => await sink.RecordAsync(new AshlarSecurityEvent
        {
            Id = Guid.NewGuid(),
            EventType = "test",
            OccurredAt = DateTimeOffset.UtcNow
        }, cancellation.Token));

        Assert.That(logger.Entries, Is.Empty);
    }

    private sealed class TestSink : PersistentSecurityEventSink
    {
        public TestSink()
            : this(NullLogger.Instance)
        {
        }

        private readonly Exception? _exception;

        public TestSink(ILogger logger, Exception? exception = null)
            : base(logger)
        {
            _exception = exception;
        }

        public List<AshlarSecurityEvent> Events { get; } = [];

        protected override Task PersistAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken)
        {
            if (_exception != null)
            {
                return Task.FromException(_exception);
            }

            Events.Add(securityEvent);
            return Task.CompletedTask;
        }
    }
}
