using Ashlar.ProviderContractTests.Testing;
using Ashlar.Identity.Abstractions.Services;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Ashlar.ProviderContracts.DependencyInjection;

namespace Ashlar.ProviderContractTests.Webhooks;

/// <summary>Verifies safe browsing, state transitions, diagnostics, and atomic security-event fan-out.</summary>
public abstract class SecurityEventWebhookOutboxContractTests : ProviderContractFixture
{
    private const string ValidSecret = "0123456789abcdef0123456789abcdef";

    /// <summary>Fixed timestamp used to create deterministic provider rows.</summary>
    protected static readonly DateTimeOffset Now = new(2026, 5, 24, 12, 0, 0, TimeSpan.Zero);
    private static readonly AccountSecurityActorTestContext Security = new(Now, IAccountSecurityAdministrationService.ProofPurpose);
    private static readonly AccountSecurityActorTestContext ReadSecurity = new(Now, AccountSecurityActorContext.AdministrationReadProofPurpose);
    private static readonly AshlarSecurityEventWebhookOutboxStatus[] ExpectedPagedStatuses =
    [
        AshlarSecurityEventWebhookOutboxStatus.Scheduled,
        AshlarSecurityEventWebhookOutboxStatus.Locked
    ];
    private static readonly string[] FailedEndpointNames = ["failed"];
    private static readonly JsonSerializerOptions WebJsonOptions = new(JsonSerializerDefaults.Web);

    static SecurityEventWebhookOutboxContractTests()
    {
        Security.Sessions.AdditionalSessions.Add(ReadSecurity.Sessions.Session
            ?? throw new InvalidOperationException("The read security context must have a session."));
    }

    /// <summary>Persists the supplied provider-neutral webhook delivery and returns its identifier.</summary>
    /// <param name="row">Provider-neutral state to persist before the assertion.</param>
    /// <returns>The identifier assigned to the seeded row.</returns>
    protected abstract Task<Guid> SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow row);

    /// <summary>Reads scheduling, terminal, lock, and failure state for the requested webhook delivery.</summary>
    /// <param name="id">Identifier of the seeded row.</param>
    /// <returns>The persisted state of the requested row.</returns>
    protected abstract Task<WebhookOutboxRowState> ReadWebhookOutboxRowStateAsync(Guid id);

    /// <summary>Counts every webhook delivery currently stored by the provider.</summary>
    /// <returns>The number of webhook outbox rows.</returns>
    protected abstract Task<int> CountWebhookOutboxRowsAsync();

    /// <summary>Counts every persisted security event, including events awaiting durable fan-out.</summary>
    /// <returns>The number of persisted security events.</returns>
    protected abstract Task<int> CountSecurityEventRowsAsync();

    /// <summary>Makes webhook enqueue fail inside the active transaction by removing its storage table.</summary>
    /// <param name="serviceProvider">Scoped services participating in the contract operation.</param>
    protected abstract Task DropWebhookOutboxTableInCurrentTransactionAsync(IServiceProvider serviceProvider);

    /// <summary>Provider assertion that storage rejects mutually exclusive sent and discarded states.</summary>
    protected abstract Task AssertSentAndDiscardedTerminalStateIsRejectedAsync();

    /// <summary>Paginates stable public statuses and exposes only sanitized delivery failure details.</summary>
    [Test]
    public async Task BrowserListsProviderNeutralStatusesWithPaging()
    {
        await SeedWebhookOutboxRowsAsync();
        await using var scope = CreateAsyncScope();
        var browser = GetSecurityEventWebhookOutboxBrowser(scope.ServiceProvider);

        var page = await browser.ListAsync(ReadSecurity.Actor, OperationalAdministrationScope.Global, new AshlarSecurityEventWebhookOutboxBrowseRequest { Limit = 2, Offset = 1 });
        var failed = await browser.ListAsync(ReadSecurity.Actor, OperationalAdministrationScope.Global, new AshlarSecurityEventWebhookOutboxBrowseRequest
        {
            Statuses = new HashSet<AshlarSecurityEventWebhookOutboxStatus> { AshlarSecurityEventWebhookOutboxStatus.Failed },
            Limit = 10
        });
        var failedDelivery = failed.Deliveries.Single();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(page.Deliveries, Has.Count.EqualTo(2));
            Assert.That(page.HasMore, Is.True);
            Assert.That(page.Deliveries.Select(delivery => delivery.Status), Is.EqualTo(ExpectedPagedStatuses));
            Assert.That(failed.Deliveries.Select(delivery => delivery.EndpointName), Is.EqualTo(FailedEndpointNames));
            Assert.That(failedDelivery.EventType, Is.EqualTo("security.test"));
            Assert.That(failedDelivery.Outcome, Is.EqualTo("success"));
            Assert.That(failedDelivery.LastErrorSummary, Is.EqualTo("kind=transport_error;reason=transport_error"));
        }
    }

    /// <summary>Transitions only terminal failures and clears obsolete locks and error state without corrupting other statuses.</summary>
    [Test]
    public async Task RetryAndDiscardOperateOnlyOnTerminalFailedRows()
    {
        var failed = await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Failed("failed", lastError: "secret https://example.test"));
        var pending = await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Pending("pending"));
        var sent = await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Sent("sent"));
        var retryable = await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Retryable("retryable"));
        var discarded = await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Discarded("discarded"));
        await using var scope = CreateAsyncScope();
        var operations = GetSecurityEventWebhookOutboxOperations(scope.ServiceProvider);

        var missingRetry = await operations.RetryAsync(Security.Actor, OperationalAdministrationScope.Global, CreateOperationRequest(Guid.NewGuid()));
        var missingDiscard = await operations.DiscardAsync(Security.Actor, OperationalAdministrationScope.Global, CreateOperationRequest(Guid.NewGuid()));
        var retry = await operations.RetryAsync(Security.Actor, OperationalAdministrationScope.Global, CreateOperationRequest(failed));
        var retriedState = await ReadWebhookOutboxRowStateAsync(failed);
        var retriedRetry = await operations.RetryAsync(Security.Actor, OperationalAdministrationScope.Global, CreateOperationRequest(failed));
        var retriedDiscard = await operations.DiscardAsync(Security.Actor, OperationalAdministrationScope.Global, CreateOperationRequest(failed));
        var pendingRetry = await operations.RetryAsync(Security.Actor, OperationalAdministrationScope.Global, CreateOperationRequest(pending));
        var pendingDiscard = await operations.DiscardAsync(Security.Actor, OperationalAdministrationScope.Global, CreateOperationRequest(pending));
        var sentRetry = await operations.RetryAsync(Security.Actor, OperationalAdministrationScope.Global, CreateOperationRequest(sent));
        var sentDiscard = await operations.DiscardAsync(Security.Actor, OperationalAdministrationScope.Global, CreateOperationRequest(sent));
        var sentState = await ReadWebhookOutboxRowStateAsync(sent);
        var retryableRetry = await operations.RetryAsync(Security.Actor, OperationalAdministrationScope.Global, CreateOperationRequest(retryable));
        var retryableDiscard = await operations.DiscardAsync(Security.Actor, OperationalAdministrationScope.Global, CreateOperationRequest(retryable));
        var retryableState = await ReadWebhookOutboxRowStateAsync(retryable);
        var discardedRetry = await operations.RetryAsync(Security.Actor, OperationalAdministrationScope.Global, CreateOperationRequest(discarded));
        var discardedDiscard = await operations.DiscardAsync(Security.Actor, OperationalAdministrationScope.Global, CreateOperationRequest(discarded));
        var failedAgain = await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Failed("failed-discard"));
        var discard = await operations.DiscardAsync(Security.Actor, OperationalAdministrationScope.Global, CreateOperationRequest(failedAgain));
        var discardedState = await ReadWebhookOutboxRowStateAsync(failedAgain);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missingRetry.Status, Is.EqualTo(AshlarSecurityEventWebhookOutboxOperationStatus.NotFound));
            Assert.That(missingDiscard.Status, Is.EqualTo(AshlarSecurityEventWebhookOutboxOperationStatus.NotFound));
            Assert.That(retry.Status, Is.EqualTo(AshlarSecurityEventWebhookOutboxOperationStatus.Retried));
            Assert.That(retry.EndpointName, Is.EqualTo("failed"));
            Assert.That(retry.EventType, Is.EqualTo("security.test"));
            Assert.That(retry.Outcome, Is.EqualTo("success"));
            Assert.That(retriedState.FailedAt, Is.Null);
            Assert.That(retriedState.LastError, Is.Null);
            Assert.That(retriedState.LockedBy, Is.Null);
            Assert.That(retriedState.LockedUntil, Is.Null);
            Assert.That(retriedState.AvailableAt, Is.EqualTo(Now));
            Assert.That(retriedRetry.Status, Is.EqualTo(AshlarSecurityEventWebhookOutboxOperationStatus.NotFailed));
            Assert.That(retriedDiscard.Status, Is.EqualTo(AshlarSecurityEventWebhookOutboxOperationStatus.NotFailed));
            Assert.That(pendingRetry.Status, Is.EqualTo(AshlarSecurityEventWebhookOutboxOperationStatus.NotFailed));
            Assert.That(pendingDiscard.Status, Is.EqualTo(AshlarSecurityEventWebhookOutboxOperationStatus.NotFailed));
            Assert.That(sentRetry.Status, Is.EqualTo(AshlarSecurityEventWebhookOutboxOperationStatus.NotFailed));
            Assert.That(sentDiscard.Status, Is.EqualTo(AshlarSecurityEventWebhookOutboxOperationStatus.NotFailed));
            Assert.That(sentState.SentAt, Is.EqualTo(Now));
            Assert.That(sentState.DiscardedAt, Is.Null);
            Assert.That(retryableRetry.Status, Is.EqualTo(AshlarSecurityEventWebhookOutboxOperationStatus.NotFailed));
            Assert.That(retryableDiscard.Status, Is.EqualTo(AshlarSecurityEventWebhookOutboxOperationStatus.NotFailed));
            Assert.That(retryableState.FailedAt, Is.Null);
            Assert.That(retryableState.LastError, Is.Null);
            Assert.That(retryableState.LockedBy, Is.Null);
            Assert.That(retryableState.LockedUntil, Is.Null);
            Assert.That(retryableState.AvailableAt, Is.EqualTo(Now));
            Assert.That(discardedRetry.Status, Is.EqualTo(AshlarSecurityEventWebhookOutboxOperationStatus.AlreadyDiscarded));
            Assert.That(discardedDiscard.Status, Is.EqualTo(AshlarSecurityEventWebhookOutboxOperationStatus.AlreadyDiscarded));
            Assert.That(discard.Status, Is.EqualTo(AshlarSecurityEventWebhookOutboxOperationStatus.Discarded));
            Assert.That(discardedState.DiscardedAt, Is.EqualTo(Now));
            Assert.That(discardedState.LockedBy, Is.Null);
            Assert.That(discardedState.LockedUntil, Is.Null);
        }
    }

    /// <summary>Prevents a delivery from being stored as both sent and discarded.</summary>
    [Test]
    public async Task SchemaRejectsSentAndDiscardedTerminalState()
    {
        await AssertSentAndDiscardedTerminalStateIsRejectedAsync();
    }

    /// <summary>Classifies every delivery state and reports the actual oldest pending and failed timestamps.</summary>
    [Test]
    public async Task DiagnosticsAggregateProviderNeutralBucketsAndOldestTimestamps()
    {
        var oldPending = Now.AddMinutes(-20);
        var oldestFailed = Now.AddDays(-2);
        await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Pending("old-pending", createdAt: oldPending, availableAt: oldPending));
        await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Pending("new-pending", createdAt: Now.AddMinutes(-5), availableAt: Now.AddMinutes(-5)));
        await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Pending("scheduled", createdAt: Now.AddMinutes(-4), availableAt: Now.AddMinutes(5)));
        await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Locked("locked", Now.AddMinutes(5)));
        await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Locked("expired", Now.AddMinutes(-1)));
        await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Failed("failed-old", failedAt: oldestFailed));
        await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Failed("failed-new", failedAt: Now.AddDays(-1)));
        await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Sent("sent"));
        await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Discarded("discarded"));
        await using var scope = CreateAsyncScope();

        var result = await GetSecurityEventWebhookOutboxDiagnostics(scope.ServiceProvider).CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Healthy));
            Assert.That(result.PendingCount, Is.EqualTo(3));
            Assert.That(result.ScheduledCount, Is.EqualTo(1));
            Assert.That(result.LockedCount, Is.EqualTo(1));
            Assert.That(result.ExpiredLockCount, Is.EqualTo(1));
            Assert.That(result.FailedCount, Is.EqualTo(2));
            Assert.That(result.OldestPendingAt, Is.EqualTo(oldPending));
            Assert.That(result.OldestFailedAt, Is.EqualTo(oldestFailed));
        }
    }

    /// <summary>Commits or discards an enqueued delivery with its surrounding Ashlar transaction.</summary>
    /// <exception cref="System.InvalidOperationException">The fixture did not register a transaction provider.</exception>
    [Test]
    public async Task EnqueueParticipatesInAshlarTransactions()
    {
        await using var scope = CreateAsyncScope();
        var transactionProvider = GetTransactionProvider(scope.ServiceProvider)
            ?? throw new InvalidOperationException("Transaction provider is not registered.");
        var enqueuer = GetSecurityEventWebhookEnqueuer(scope.ServiceProvider);

        await using (var transaction = await transactionProvider.BeginTransactionAsync())
        {
            await enqueuer.EnqueueAsync(CreateDelivery("rolled-back"));
            await transaction.RollbackAsync();
        }

        Assert.That(await CountWebhookOutboxRowsAsync(), Is.Zero);

        await using (var transaction = await transactionProvider.BeginTransactionAsync())
        {
            await enqueuer.EnqueueAsync(CreateDelivery("committed"));
            await transaction.CommitAsync();
        }

        Assert.That(await CountWebhookOutboxRowsAsync(), Is.EqualTo(1));
    }

    /// <summary>Commits the protected mutation, audit event, and webhook delivery as one transaction.</summary>
    /// <exception cref="System.InvalidOperationException">The fixture did not register a transaction provider.</exception>
    [Test]
    public async Task SecurityEventFanOutCommitsProtectedMutationAuditAndWebhookOutboxAtomically()
    {
        await using var scope = CreateAsyncScope();
        var transactionProvider = GetTransactionProvider(scope.ServiceProvider)
            ?? throw new InvalidOperationException("Transaction provider is not registered.");
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var sink = GetSecurityEventSink(scope.ServiceProvider);
        var user = CreateTransactionalUser();
        var securityEvent = CreateTransactionalSecurityEvent(user.Id);

        await using (var transaction = await transactionProvider.BeginTransactionAsync())
        {
            await userRepository.CreateUserAsync(user);
            await sink.RecordAsync(securityEvent);
            await transaction.CommitAsync();
        }

        using (Assert.EnterMultipleScope())
        {
            Assert.That(await userRepository.GetUserByIdAsync(user.Id), Is.Not.Null);
            Assert.That(await CountSecurityEventRowsAsync(), Is.EqualTo(1));
            Assert.That(await CountWebhookOutboxRowsAsync(), Is.EqualTo(1));
        }
    }

    /// <summary>Persists both the audit event and webhook delivery when fan-out owns the transaction.</summary>
    [Test]
    public async Task SecurityEventFanOutCommitsAuditAndWebhookOutboxAtomicallyWithoutAmbientTransaction()
    {
        await using var scope = CreateAsyncScope();
        var user = await CreateUserAsync(GetUserRepository(scope.ServiceProvider));
        var sink = GetSecurityEventSink(scope.ServiceProvider);

        await sink.RecordAsync(CreateTransactionalSecurityEvent(user.Id));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(await CountSecurityEventRowsAsync(), Is.EqualTo(1));
            Assert.That(await CountWebhookOutboxRowsAsync(), Is.EqualTo(1));
        }
    }

    /// <summary>Leaves no mutation, audit event, or delivery behind when webhook enqueue fails inside a transaction.</summary>
    /// <exception cref="System.InvalidOperationException">The fixture did not register a transaction provider.</exception>
    [Test]
    public async Task SecurityEventFanOutRollsBackProtectedMutationAndAuditWhenWebhookOutboxEnqueueFails()
    {
        await using var scope = CreateAsyncScope();
        var transactionProvider = GetTransactionProvider(scope.ServiceProvider)
            ?? throw new InvalidOperationException("Transaction provider is not registered.");
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var sink = GetSecurityEventSink(scope.ServiceProvider);
        var user = CreateTransactionalUser();

        await using (var transaction = await transactionProvider.BeginTransactionAsync())
        {
            await DropWebhookOutboxTableInCurrentTransactionAsync(scope.ServiceProvider);
            await userRepository.CreateUserAsync(user);

            Assert.That(async () => await sink.RecordAsync(CreateTransactionalSecurityEvent(user.Id)), Throws.Exception);
            await transaction.RollbackAsync();
        }

        using (Assert.EnterMultipleScope())
        {
            Assert.That(await userRepository.GetUserByIdAsync(user.Id), Is.Null);
            Assert.That(await CountSecurityEventRowsAsync(), Is.Zero);
            Assert.That(await CountWebhookOutboxRowsAsync(), Is.Zero);
        }
    }

    /// <summary>Leaves neither audit nor delivery rows when a durable fan-out participant fails.</summary>
    /// <exception cref="System.InvalidOperationException">The fixture did not register a transaction provider.</exception>
    [Test]
    public async Task SecurityEventFanOutRollsBackAuditAndWebhookOutboxWhenDurableFanOutFailsWithoutAmbientTransaction()
    {
        await using var scope = CreateAsyncScope();
        var rawTransactionProvider = GetTransactionProvider(scope.ServiceProvider)
            ?? throw new InvalidOperationException("Transaction provider is not registered.");
        var user = await CreateUserAsync(GetUserRepository(scope.ServiceProvider));
        var persistentSink = new DelegatingPersistentSecurityEventSink(GetPersistentSecurityEventSink(scope.ServiceProvider));
        var durableHandler = new CompositeDurableSecurityEventFanOutHandler(
            [.. scope.ServiceProvider.GetServices<IDurableSecurityEventFanOutHandler>(), new ThrowingDurableSecurityEventFanOutHandler()]);
        var services = new ServiceCollection();
        services.AddAshlarDurableTransactionProvider<IAshlarTransactionProvider>("Contract rollback", _ => rawTransactionProvider);
        services.AddAshlarProviderScoped<IAshlarTransactionProvider, IPersistentSecurityEventSink>("Contract rollback", _ => persistentSink);
        services.AddAshlarProviderScoped<IAshlarTransactionProvider, IDurableSecurityEventFanOutHandler>("Contract rollback", _ => durableHandler);
        services.AddAshlarDurableTransactionParticipant<IPersistentSecurityEventSink>();
        services.AddAshlarDurableTransactionParticipant<IDurableSecurityEventFanOutHandler>();
        using var composition = services.BuildServiceProvider();
        var transactionProvider = composition.GetRequiredService<AshlarDurableTransactionProvider>();
        var sink = new SecurityEventFanOutSink(
            persistentSink,
            transactionProvider: transactionProvider,
            durableHandlers: [durableHandler]);

        Assert.That(
            async () => await sink.RecordAsync(CreateTransactionalSecurityEvent(user.Id)),
            Throws.TypeOf<InvalidOperationException>().With.Message.EqualTo("durable fan-out failed"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(await CountSecurityEventRowsAsync(), Is.Zero);
            Assert.That(await CountWebhookOutboxRowsAsync(), Is.Zero);
        }
    }

    /// <summary>Rolls back the mutation, audit event, and deferred webhook delivery before commit.</summary>
    /// <exception cref="System.InvalidOperationException">The fixture did not register a transaction provider.</exception>
    [Test]
    public async Task SecurityEventFanOutRollbackBeforeCommitDoesNotEnqueueWebhookOutboxRows()
    {
        await using var scope = CreateAsyncScope();
        var transactionProvider = GetTransactionProvider(scope.ServiceProvider)
            ?? throw new InvalidOperationException("Transaction provider is not registered.");
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var sink = GetSecurityEventSink(scope.ServiceProvider);
        var user = CreateTransactionalUser();

        await using (var transaction = await transactionProvider.BeginTransactionAsync())
        {
            await userRepository.CreateUserAsync(user);
            await sink.RecordAsync(CreateTransactionalSecurityEvent(user.Id));
            await transaction.RollbackAsync();
        }

        using (Assert.EnterMultipleScope())
        {
            Assert.That(await userRepository.GetUserByIdAsync(user.Id), Is.Null);
            Assert.That(await CountSecurityEventRowsAsync(), Is.Zero);
            Assert.That(await CountWebhookOutboxRowsAsync(), Is.Zero);
        }
    }

    private async Task SeedWebhookOutboxRowsAsync()
    {
        await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Pending("pending", createdAt: Now.AddMinutes(-5), availableAt: Now.AddMinutes(-5)));
        await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Pending("scheduled", createdAt: Now.AddMinutes(-4), availableAt: Now.AddMinutes(30)));
        await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Locked("locked", Now.AddMinutes(5), createdAt: Now.AddMinutes(-3)));
        await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Locked("expired", Now.AddMinutes(-1), createdAt: Now.AddMinutes(-2)));
        await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Failed("failed", failedAt: Now.AddSeconds(-30), createdAt: Now.AddMinutes(-1), lastError: "kind=transport_error;reason=transport_error"));
        await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Sent("sent"));
        await SeedWebhookOutboxRowAsync(SeedWebhookOutboxRow.Discarded("discarded"));
    }

    private static AshlarSecurityEventWebhookOutboxOperationRequest CreateOperationRequest(Guid id)
    {
        return new AshlarSecurityEventWebhookOutboxOperationRequest(id);
    }

    private static AshlarSecurityEventWebhookDelivery CreateDelivery(string endpointName)
    {
        var securityEvent = new AshlarSecurityEvent
        {
            Id = Guid.NewGuid(),
            EventType = "ashlar.sign_in.failed",
            OccurredAt = Now.AddHours(-1),
            Outcome = SecurityEventOutcomes.Failure,
            IpAddress = "203.0.113.10"
        };
        var payload = AshlarSecurityEventWebhookDeliveryFactory.CreatePayload(securityEvent);
        var body = JsonSerializer.SerializeToUtf8Bytes(payload, WebJsonOptions);
        var endpoint = new AshlarSecurityEventWebhookEndpointOptions
        {
            Name = endpointName,
            Uri = new Uri($"https://example.test/{endpointName}"),
            SharedSecret = ValidSecret
        };
        var headers = AshlarSecurityEventWebhookDeliveryFactory.CreateHeaders(
            endpoint,
            payload,
            body,
            DateTimeOffset.FromUnixTimeSeconds(1_800_000_000));

        return new AshlarSecurityEventWebhookDelivery(
            endpointName,
            endpoint.Uri,
            TimeSpan.FromSeconds(10),
            headers,
            payload);
    }

    private static AshlarUser CreateTransactionalUser()
    {
        return new AshlarUser
        {
            Id = Guid.NewGuid(),
            DisplayEmail = $"{Guid.NewGuid():N}@example.test",
            Name = "Transactional User",
            AccountState = UserAccountState.Active
        };
    }

    private static AshlarSecurityEvent CreateTransactionalSecurityEvent(Guid userId)
    {
        return new AshlarSecurityEvent
        {
            Id = Guid.NewGuid(),
            EventType = "ashlar.transactional.test",
            OccurredAt = Now,
            UserId = userId,
            Outcome = SecurityEventOutcomes.Success
        };
    }

    private sealed class ThrowingDurableSecurityEventFanOutHandler : IDurableSecurityEventFanOutHandler
    {
        public Task HandleAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            throw new InvalidOperationException("durable fan-out failed");
        }
    }

    /// <summary>In-memory sessions used to authorize protected webhook operations.</summary>
    protected static IAuthenticationSessionRepository SecuritySessions => Security.Sessions;

    /// <summary>Controllable authorizer used by protected webhook operation tests.</summary>
    protected static IAccountSecurityOperationAuthorizer SecurityAuthorizer => Security.Authorizer;

    private sealed class DelegatingPersistentSecurityEventSink(IPersistentSecurityEventSink inner) : IPersistentSecurityEventSink
    {
        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default) =>
            inner.RecordAsync(securityEvent, cancellationToken);
    }

    private sealed class CompositeDurableSecurityEventFanOutHandler(IReadOnlyList<IDurableSecurityEventFanOutHandler> handlers)
        : IDurableSecurityEventFanOutHandler
    {
        public async Task HandleAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            foreach (var handler in handlers) await handler.HandleAsync(securityEvent, cancellationToken);
        }
    }

    /// <summary>Provider-neutral state used to seed a webhook outbox row.</summary>
    /// <param name="EndpointName">Webhook endpoint that owns the delivery.</param>
    /// <param name="CreatedAt">Time the delivery was created.</param>
    /// <param name="AvailableAt">Time the delivery becomes eligible for dispatch.</param>
    /// <param name="SentAt">Successful-delivery time, if sent.</param>
    /// <param name="FailedAt">Terminal failure time, if failed.</param>
    /// <param name="DiscardedAt">Time further delivery was abandoned, if discarded.</param>
    /// <param name="LockedBy">Worker holding the dispatch lock, if locked.</param>
    /// <param name="LockedUntil">Time the dispatch lock expires, if locked.</param>
    /// <param name="AttemptCount">Number of delivery attempts.</param>
    /// <param name="LastError">Safe delivery failure detail, if present.</param>
    protected sealed record SeedWebhookOutboxRow(
        string EndpointName,
        DateTimeOffset CreatedAt,
        DateTimeOffset AvailableAt,
        DateTimeOffset? SentAt,
        DateTimeOffset? FailedAt,
        DateTimeOffset? DiscardedAt,
        string? LockedBy,
        DateTimeOffset? LockedUntil,
        int AttemptCount,
        string? LastError)
    {
        /// <summary>Unique event identifier persisted with this seeded row.</summary>
        public Guid EventId { get; } = Guid.NewGuid();

        /// <summary>Serialized event body persisted with this seeded row.</summary>
        public byte[] Body { get; } = Encoding.UTF8.GetBytes("{}");

        /// <summary>Creates a pending row for provider-state assertions.</summary>
        /// <param name="endpointName">Webhook endpoint that owns the seeded delivery.</param>
        /// <param name="createdAt">Creation time to persist.</param>
        /// <param name="availableAt">Time from which the row is eligible for dispatch.</param>
        /// <returns>A pending row descriptor.</returns>
        public static SeedWebhookOutboxRow Pending(string endpointName, DateTimeOffset? createdAt = null, DateTimeOffset? availableAt = null)
        {
            return new SeedWebhookOutboxRow(endpointName, createdAt ?? Now, availableAt ?? Now, null, null, null, null, null, 0, null);
        }

        /// <summary>Creates a locked row for provider-state assertions.</summary>
        /// <param name="endpointName">Webhook endpoint that owns the seeded delivery.</param>
        /// <param name="lockedUntil">Time until which a worker owns the row.</param>
        /// <param name="createdAt">Creation time to persist.</param>
        /// <returns>A locked row descriptor.</returns>
        public static SeedWebhookOutboxRow Locked(string endpointName, DateTimeOffset lockedUntil, DateTimeOffset? createdAt = null)
        {
            return new SeedWebhookOutboxRow(endpointName, createdAt ?? Now, Now, null, null, null, "worker", lockedUntil, 0, null);
        }

        /// <summary>Creates a failed row for provider-state assertions.</summary>
        /// <param name="endpointName">Webhook endpoint that owns the seeded delivery.</param>
        /// <param name="failedAt">Terminal failure time.</param>
        /// <param name="createdAt">Creation time to persist.</param>
        /// <param name="lastError">Safe persisted delivery failure detail.</param>
        /// <returns>A terminally failed row descriptor.</returns>
        public static SeedWebhookOutboxRow Failed(string endpointName, DateTimeOffset? failedAt = null, DateTimeOffset? createdAt = null, string? lastError = "failure")
        {
            var failureTime = failedAt ?? Now.AddMinutes(-1);
            return new SeedWebhookOutboxRow(endpointName, createdAt ?? Now, Now, null, failureTime, null, null, null, 3, lastError);
        }

        /// <summary>Creates a sent row for provider-state assertions.</summary>
        /// <param name="endpointName">Webhook endpoint that owns the seeded delivery.</param>
        /// <returns>A sent row descriptor.</returns>
        public static SeedWebhookOutboxRow Sent(string endpointName)
        {
            return new SeedWebhookOutboxRow(endpointName, Now, Now, Now, null, null, null, null, 1, null);
        }

        /// <summary>Creates a retryable row for provider-state assertions.</summary>
        /// <param name="endpointName">Webhook endpoint that owns the seeded delivery.</param>
        /// <returns>A retryable row descriptor.</returns>
        public static SeedWebhookOutboxRow Retryable(string endpointName)
        {
            return new SeedWebhookOutboxRow(endpointName, Now, Now, null, null, null, null, null, 1, null);
        }

        /// <summary>Creates a discarded row for provider-state assertions.</summary>
        /// <param name="endpointName">Webhook endpoint that owns the seeded delivery.</param>
        /// <returns>A discarded row descriptor.</returns>
        public static SeedWebhookOutboxRow Discarded(string endpointName)
        {
            return new SeedWebhookOutboxRow(endpointName, Now, Now, null, Now.AddMinutes(-1), Now, null, null, 3, "discarded");
        }
    }

    /// <summary>Provider state read back for webhook outbox row state assertions.</summary>
    /// <param name="AvailableAt">Time the delivery becomes eligible for dispatch.</param>
    /// <param name="SentAt">Successful-delivery time, if sent.</param>
    /// <param name="FailedAt">Terminal failure time, if failed.</param>
    /// <param name="DiscardedAt">Time further delivery was abandoned, if discarded.</param>
    /// <param name="LockedBy">Worker holding the dispatch lock, if locked.</param>
    /// <param name="LockedUntil">Time the dispatch lock expires, if locked.</param>
    /// <param name="LastError">Safe delivery failure detail, if present.</param>
    protected sealed record WebhookOutboxRowState(
        DateTimeOffset AvailableAt,
        DateTimeOffset? SentAt,
        DateTimeOffset? FailedAt,
        DateTimeOffset? DiscardedAt,
        string? LockedBy,
        DateTimeOffset? LockedUntil,
        string? LastError);
}
