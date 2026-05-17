using Ashlar.Auditing;
using Ashlar.Identity.Models;
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
    public async Task DisposeAsyncCompletesEmptyChannel()
    {
        await using var sink = new TestSink();

        await sink.DisposeAsync();

        Assert.That(sink.Events, Is.Empty);
    }

    [Test]
    public async Task RecordAsyncPersistsQueuedEvents()
    {
        await using var sink = new TestSink();
        var securityEvent = new AshlarSecurityEvent
        {
            Id = Guid.NewGuid(),
            EventType = "test",
            OccurredAt = DateTimeOffset.UtcNow
        };

        await sink.RecordAsync(securityEvent);
        await sink.DisposeAsync();

        Assert.That(sink.Events, Is.EqualTo(new[] { securityEvent }));
    }

    [Test]
    public void GetProviderNameHandlesNullAndNamedProviders()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(TestSink.ReadProviderName(null), Is.Null);
            Assert.That(TestSink.ReadProviderName(new AuthenticationProviderKey(ProviderType.Local, "Password")), Is.EqualTo("Password"));
        }
    }

    private sealed class TestSink : PersistentSecurityEventSink
    {
        public TestSink()
            : this(NullLogger.Instance)
        {
        }

        public TestSink(NullLogger logger)
            : base(logger)
        {
        }

        public List<AshlarSecurityEvent> Events { get; } = [];

        public static string? ReadProviderName(AuthenticationProviderKey? provider)
        {
            return GetProviderName(provider);
        }

        protected override Task PersistAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken)
        {
            Events.Add(securityEvent);
            return Task.CompletedTask;
        }
    }
}
