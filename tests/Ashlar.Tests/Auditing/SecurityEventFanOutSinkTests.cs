using Ashlar.Auditing;
using Ashlar.Testing;

namespace Ashlar.Tests.Auditing;

internal sealed class SecurityEventFanOutSinkTests
{
    private static readonly string[] PersistentThenDurableThenHandler = ["persistent", "durable", "handler"];
    private static readonly string[] PersistentThenDurable = ["persistent", "durable"];

    private static AshlarDurableTransactionProvider Durable(IAshlarTransactionProvider provider, params object[] participants) =>
        AshlarDurableTransactionProvider.Create(provider, participants);

    [Test]
    public void ConstructorRejectsDurableComponentsWithoutDurableTransactionProvider()
    {
        Assert.Throws<InvalidOperationException>(() => new SecurityEventFanOutSink(new RecordingPersistentSink()));
        Assert.Throws<InvalidOperationException>(() => new SecurityEventFanOutSink(durableHandlers: [new RecordingDurableHandler()]));
        Assert.Throws<InvalidOperationException>(() => new SecurityEventFanOutSink(new RecordingPersistentSink(), transactionProvider: new NonDurableTransactionProvider()));
    }

    [Test]
    public void ConstructorRejectsParticipantFromAnotherDurableComposition()
    {
        var enlisted = new RecordingPersistentSink();
        var other = new RecordingPersistentSink();
        var composition = Durable(new RecordingTransactionProvider(), enlisted);

        Assert.Throws<InvalidOperationException>(() => new SecurityEventFanOutSink(other, transactionProvider: composition));
        Assert.Throws<ArgumentException>(() => Durable(new RecordingTransactionProvider(), new object[] { null! }));
    }

    [Test]
    public void MutationCompositionRejectsMissingDurabilityProviderAndParticipants()
    {
        var persistent = new RecordingPersistentSink();
        var participant = new object();
        var composition = Durable(new RecordingTransactionProvider(), persistent);
        var otherComposition = Durable(new RecordingTransactionProvider(), persistent, participant);
        var fanOut = new SecurityEventFanOutSink(persistent, transactionProvider: composition);

        Assert.Throws<ArgumentException>(() => DurableSecurityMutationComposition.Require(new SecurityEventFanOutSink(), composition, "Test", participant));
        Assert.Throws<ArgumentException>(() => DurableSecurityMutationComposition.Require(fanOut, otherComposition, "Test", participant));
        Assert.Throws<ArgumentException>(() => DurableSecurityMutationComposition.Require(fanOut, composition, "Test", participant));
        Assert.That(DurableSecurityMutationComposition.Require(
            new SecurityEventFanOutSink(persistent, transactionProvider: otherComposition), otherComposition, "Test", participant), Is.Not.Null);
    }

    [Test]
    public async Task RecordAsyncRecordsToPersistentSinkWhenConfigured()
    {
        var persistentSink = new RecordingPersistentSink();
        var securityEvent = CreateEvent();
        var sink = new SecurityEventFanOutSink(persistentSink, transactionProvider: Durable(new RecordingTransactionProvider(), persistentSink));

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
        var durableHandler = new RecordingDurableHandler(calls, "durable");
        var sink = new SecurityEventFanOutSink(persistentSink, [handler], transactionProvider: Durable(new RecordingTransactionProvider(), persistentSink, durableHandler), durableHandlers: [durableHandler]);

        await sink.RecordAsync(CreateEvent());

        Assert.That(calls, Is.EqualTo(PersistentThenDurableThenHandler));
    }

    [Test]
    public void RecordAsyncPropagatesDurableHandlerFailureAndSkipsBestEffortHandlers()
    {
        var handler = new RecordingHandler();
        var expected = new InvalidOperationException("durable failed");
        var persistentSink = new RecordingPersistentSink();
        var durableHandler = new ThrowingDurableHandler(expected);
        var sink = new SecurityEventFanOutSink(
            persistentSink,
            [handler],
            transactionProvider: Durable(new RecordingTransactionProvider(), persistentSink, durableHandler),
            durableHandlers: [durableHandler]);

        var exception = Assert.ThrowsAsync<InvalidOperationException>(async () => await sink.RecordAsync(CreateEvent()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exception, Is.SameAs(expected));
            Assert.That(handler.Events, Is.Empty);
        }
    }

    [Test]
    public async Task RecordAsyncRunsPersistentAndDurableHandlersInOneTransactionBeforeBestEffortHandlers()
    {
        await using var transactionProvider = new RecordingTransactionProvider();
        List<string> calls = [];
        var persistentSink = new RecordingPersistentSink(calls, "persistent");
        var durableHandler = new RecordingDurableHandler(calls, "durable");
        var sink = new SecurityEventFanOutSink(
            persistentSink,
            [new RecordingHandler(calls, "handler")],
            transactionProvider: Durable(transactionProvider, persistentSink, durableHandler),
            durableHandlers: [durableHandler]);

        await sink.RecordAsync(CreateEvent());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(calls, Is.EqualTo(PersistentThenDurableThenHandler));
            Assert.That(transactionProvider.RootTransactions, Is.EqualTo(1));
            Assert.That(transactionProvider.LastRootTransaction.CommitCount, Is.EqualTo(1));
            Assert.That(transactionProvider.LastRootTransaction.RollbackCount, Is.Zero);
        }
    }

    [Test]
    public async Task RecordAsyncCommitsTransactionWhenNoBestEffortHandlersAreConfigured()
    {
        await using var transactionProvider = new RecordingTransactionProvider();
        var persistentSink = new RecordingPersistentSink();
        var durableHandler = new RecordingDurableHandler();
        var securityEvent = CreateEvent();
        var sink = new SecurityEventFanOutSink(
            persistentSink,
            transactionProvider: Durable(transactionProvider, persistentSink, durableHandler),
            durableHandlers: [durableHandler]);

        await sink.RecordAsync(securityEvent);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(persistentSink.Events, Is.EqualTo(new[] { securityEvent }));
            Assert.That(durableHandler.Events, Is.EqualTo(new[] { securityEvent }));
            Assert.That(transactionProvider.LastRootTransaction.CommitCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task RecordAsyncDefersHandlersUntilTransactionCommits()
    {
        await using var transactionProvider = new RecordingTransactionProvider();
        var persistentSink = new RecordingPersistentSink();
        var handler = new RecordingHandler();
        var securityEvent = CreateEvent();
        var sink = new SecurityEventFanOutSink(persistentSink, [handler], transactionProvider: Durable(transactionProvider, persistentSink));

        await sink.RecordAsync(securityEvent);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(persistentSink.Events, Is.EqualTo(new[] { securityEvent }));
            Assert.That(handler.Events, Is.EqualTo(new[] { securityEvent }));
            Assert.That(transactionProvider.LastRootTransaction.CommitCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task RecordAsyncJoinsAmbientTransactionAndDefersHandlersUntilOuterCommit()
    {
        await using var transactionProvider = new RecordingTransactionProvider();
        var persistentSink = new RecordingPersistentSink();
        var handler = new RecordingHandler();
        var securityEvent = CreateEvent();
        var sink = new SecurityEventFanOutSink(persistentSink, [handler], transactionProvider: Durable(transactionProvider, persistentSink));

        await using var transaction = await transactionProvider.BeginTransactionAsync();
        await sink.RecordAsync(securityEvent);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(persistentSink.Events, Is.EqualTo(new[] { securityEvent }));
            Assert.That(handler.Events, Is.Empty);
            Assert.That(transactionProvider.RootTransactions, Is.EqualTo(1));
            Assert.That(transactionProvider.JoinedTransactions, Is.EqualTo(1));
        }

        await transaction.CommitAsync();

        Assert.That(handler.Events, Is.EqualTo(new[] { securityEvent }));
    }

    [Test]
    public async Task RecordAsyncSkipsDeferredHandlersWhenAmbientTransactionRollsBack()
    {
        await using var transactionProvider = new RecordingTransactionProvider();
        var persistentSink = new RecordingPersistentSink();
        var handler = new RecordingHandler();
        var securityEvent = CreateEvent();
        var sink = new SecurityEventFanOutSink(persistentSink, [handler], transactionProvider: Durable(transactionProvider, persistentSink));

        await using var transaction = await transactionProvider.BeginTransactionAsync();
        await sink.RecordAsync(securityEvent);
        await transaction.RollbackAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(persistentSink.Events, Is.EqualTo(new[] { securityEvent }));
            Assert.That(handler.Events, Is.Empty);
        }
    }

    [Test]
    public void RecordAsyncPropagatesTransactionProviderFailureBeforePersistence()
    {
        var expected = new InvalidOperationException("transaction unavailable");
        var persistentSink = new RecordingPersistentSink();
        var handler = new RecordingHandler();
        var sink = new SecurityEventFanOutSink(
            persistentSink,
            [handler],
            transactionProvider: Durable(new ThrowingTransactionProvider(expected), persistentSink));

        var exception = Assert.ThrowsAsync<InvalidOperationException>(async () => await sink.RecordAsync(CreateEventWithNullProvider()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exception, Is.SameAs(expected));
            Assert.That(persistentSink.Events, Is.Empty);
            Assert.That(handler.Events, Is.Empty);
        }
    }

    [Test]
    public void RecordAsyncRethrowsTransactionProviderCallerCancellationBeforePersistence()
    {
        using var cancellation = new CancellationTokenSource();
        var persistentSink = new RecordingPersistentSink();
        var handler = new RecordingHandler();
        var sink = new SecurityEventFanOutSink(
            persistentSink,
            [handler],
            transactionProvider: Durable(new CancelingTransactionProvider(cancellation), persistentSink));

        Assert.ThrowsAsync<OperationCanceledException>(async () => await sink.RecordAsync(CreateEvent(), cancellation.Token));
        using (Assert.EnterMultipleScope())
        {
            Assert.That(persistentSink.Events, Is.Empty);
            Assert.That(handler.Events, Is.Empty);
        }
    }

    [Test]
    public async Task RecordAsyncRollsBackAndSkipsDurableAndBestEffortHandlersWhenPersistentSinkFails()
    {
        await using var transactionProvider = new RecordingTransactionProvider();
        var expected = new InvalidOperationException("persistent failed");
        var durableHandler = new RecordingDurableHandler();
        var handler = new RecordingHandler();
        var persistentSink = new ThrowingPersistentSink(expected);
        var sink = new SecurityEventFanOutSink(
            persistentSink,
            [handler],
            transactionProvider: Durable(transactionProvider, persistentSink, durableHandler),
            durableHandlers: [durableHandler]);

        var exception = Assert.ThrowsAsync<InvalidOperationException>(async () => await sink.RecordAsync(CreateEvent()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exception, Is.SameAs(expected));
            Assert.That(durableHandler.Events, Is.Empty);
            Assert.That(handler.Events, Is.Empty);
            Assert.That(transactionProvider.LastRootTransaction.RollbackCount, Is.EqualTo(1));
            Assert.That(transactionProvider.LastRootTransaction.CommitCount, Is.Zero);
        }
    }

    [Test]
    public async Task RecordAsyncRollsBackPersistentAuditAndSkipsBestEffortHandlersWhenDurableFanOutFails()
    {
        await using var transactionProvider = new RecordingTransactionProvider();
        var expected = new InvalidOperationException("durable failed");
        var persistentSink = new RecordingPersistentSink();
        var handler = new RecordingHandler();
        var durableHandler = new ThrowingDurableHandler(expected);
        var sink = new SecurityEventFanOutSink(
            persistentSink,
            [handler],
            transactionProvider: Durable(transactionProvider, persistentSink, durableHandler),
            durableHandlers: [durableHandler]);

        var exception = Assert.ThrowsAsync<InvalidOperationException>(async () => await sink.RecordAsync(CreateEvent()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exception, Is.SameAs(expected));
            Assert.That(persistentSink.Events, Has.Count.EqualTo(1));
            Assert.That(handler.Events, Is.Empty);
            Assert.That(transactionProvider.LastRootTransaction.RollbackCount, Is.EqualTo(1));
            Assert.That(transactionProvider.LastRootTransaction.CommitCount, Is.Zero);
        }
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
    public void RecordAsyncPropagatesPersistentSinkFailureAndSkipsHandlers()
    {
        var logger = new RecordingLogger<SecurityEventFanOutSink>();
        var handler = new RecordingHandler();
        var securityEvent = CreateEvent();
        var expected = new InvalidOperationException("persistent failed");
        var persistentSink = new ThrowingPersistentSink(expected);
        var sink = new SecurityEventFanOutSink(
            persistentSink,
            [handler],
            logger: logger,
            transactionProvider: Durable(new RecordingTransactionProvider(), persistentSink));

        var exception = Assert.ThrowsAsync<InvalidOperationException>(async () => await sink.RecordAsync(securityEvent));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exception, Is.SameAs(expected));
            Assert.That(handler.Events, Is.Empty);
            Assert.That(logger.Entries, Is.Empty);
        }
    }

    [Test]
    public async Task RecordAsyncLogsHandlerFailureForNullProvider()
    {
        var logger = new RecordingLogger<SecurityEventFanOutSink>();
        var securityEvent = CreateEventWithNullProvider();
        var sink = new SecurityEventFanOutSink(handlers: [new ThrowingHandler(new InvalidOperationException("handler failed"))], logger: logger);

        await sink.RecordAsync(securityEvent);

        Assert.That(logger.Entries.Single().Message, Does.Contain("ProviderName=(null)"));
    }

    [Test]
    public void RecordAsyncPropagatesPersistentSinkFailureForNullProvider()
    {
        var logger = new RecordingLogger<SecurityEventFanOutSink>();
        var securityEvent = CreateEventWithNullProvider();
        var expected = new InvalidOperationException("persistent failed");
        var persistentSink = new ThrowingPersistentSink(expected);
        var sink = new SecurityEventFanOutSink(
            persistentSink,
            logger: logger,
            transactionProvider: Durable(new RecordingTransactionProvider(), persistentSink));

        var exception = Assert.ThrowsAsync<InvalidOperationException>(async () => await sink.RecordAsync(securityEvent));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exception, Is.SameAs(expected));
            Assert.That(logger.Entries, Is.Empty);
        }
    }

    [Test]
    public void RecordAsyncRethrowsPersistentSinkCallerCancellation()
    {
        using var cancellation = new CancellationTokenSource();
        var persistentSink = new CancelingPersistentSink(cancellation);
        var sink = new SecurityEventFanOutSink(persistentSink, transactionProvider: Durable(new RecordingTransactionProvider(), persistentSink));

        Assert.ThrowsAsync<OperationCanceledException>(async () => await sink.RecordAsync(CreateEvent(), cancellation.Token));
    }

    [Test]
    public void RecordAsyncRespectsCallerCancellationBeforePersistentSink()
    {
        var persistentSink = new RecordingPersistentSink();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var sink = new SecurityEventFanOutSink(persistentSink, transactionProvider: Durable(new RecordingTransactionProvider(), persistentSink));

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

    private sealed class RecordingDurableHandler(List<string>? calls = null, string? callName = null) : IDurableSecurityEventFanOutHandler
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

    private sealed class ThrowingDurableHandler(Exception exception) : IDurableSecurityEventFanOutHandler
    {
        public Task HandleAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            return Task.FromException(exception);
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

    private sealed class RecordingTransactionProvider : IAshlarTransactionProvider, IAsyncDisposable
    {
        private RecordingTransaction? _activeTransaction;

        public RecordingTransaction LastRootTransaction { get; private set; } = null!;

        public int RootTransactions { get; private set; }

        public int JoinedTransactions { get; private set; }

        public Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_activeTransaction is null)
            {
                _activeTransaction = new RecordingTransaction(this, ownsProviderSlot: true);
                LastRootTransaction = _activeTransaction;
                RootTransactions++;
                return Task.FromResult<IAshlarTransaction>(_activeTransaction);
            }

            JoinedTransactions++;
            return Task.FromResult<IAshlarTransaction>(new RecordingTransaction(this, ownsProviderSlot: false, _activeTransaction));
        }

        public void Clear(RecordingTransaction transaction)
        {
            if (ReferenceEquals(_activeTransaction, transaction))
            {
                _activeTransaction = null;
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (_activeTransaction is not null)
            {
                await _activeTransaction.DisposeAsync();
            }
        }
    }

    private sealed class RecordingTransaction(
        RecordingTransactionProvider provider,
        bool ownsProviderSlot,
        RecordingTransaction? parent = null) : IAshlarTransaction
    {
        private readonly List<Func<CancellationToken, Task>> _committedActions = parent?._committedActions ?? [];
        private bool _completed;

        public int CommitCount { get; private set; }

        public int RollbackCount { get; private set; }

        public async Task CommitAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CommitCount++;
            if (!ownsProviderSlot)
            {
                _completed = true;
                return;
            }

            foreach (var action in _committedActions)
            {
                await action(CancellationToken.None);
            }

            _completed = true;
            provider.Clear(this);
        }

        public Task RollbackAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RollbackCount++;
            _committedActions.Clear();
            _completed = true;
            if (ownsProviderSlot)
            {
                provider.Clear(this);
            }

            return Task.CompletedTask;
        }

        public void OnCommitted(Func<CancellationToken, Task> action)
        {
            ArgumentNullException.ThrowIfNull(action);
            ObjectDisposedException.ThrowIf(_completed, this);
            _committedActions.Add(action);
        }

        public ValueTask DisposeAsync()
        {
            if (!_completed && ownsProviderSlot)
            {
                _committedActions.Clear();
                provider.Clear(this);
            }

            _completed = true;
            return ValueTask.CompletedTask;
        }
    }

    private sealed class ThrowingTransactionProvider(Exception exception) : IAshlarTransactionProvider
    {
        public Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromException<IAshlarTransaction>(exception);
        }
    }

    private sealed class NonDurableTransactionProvider : IAshlarTransactionProvider
    {
        public Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }

    private sealed class CancelingTransactionProvider(CancellationTokenSource cancellation) : IAshlarTransactionProvider
    {
        public Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default)
        {
            cancellation.Cancel();
            throw new OperationCanceledException(cancellation.Token);
        }
    }
}
