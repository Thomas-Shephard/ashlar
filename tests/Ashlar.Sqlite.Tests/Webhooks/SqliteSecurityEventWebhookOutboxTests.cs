using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Ashlar.Webhooks.SecurityEvents;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Sqlite.Tests.Webhooks;

internal sealed class SqliteSecurityEventWebhookOutboxTests : SqliteTestBase
{
    private const string ValidSecret = "0123456789abcdef0123456789abcdef";
    private const string ChangedSecret = $"changed-{ValidSecret}";
    private const string CurrentSecret = $"current-{ValidSecret}";
    private const string OldSecret = $"old-{ValidSecret}";

    private static readonly string[] ExpectedIndexes =
    [
        "ix_ashlar_security_event_webhook_outbox_pending",
        "ix_ashlar_security_event_webhook_outbox_created_at",
        "ix_ashlar_security_event_webhook_outbox_locked_until",
        "ix_ashlar_security_event_webhook_outbox_sent_at",
        "ix_ashlar_security_event_webhook_outbox_failed_at",
        "ix_ashlar_security_event_webhook_outbox_discarded_at",
        "ix_ashlar_security_event_webhook_outbox_event"
    ];
    private static readonly JsonSerializerOptions WebJsonOptions = new(JsonSerializerDefaults.Web);

    private readonly DateTimeOffset _now = new(2026, 5, 24, 12, 0, 0, TimeSpan.Zero);
    private readonly List<ServiceProvider> _dispatcherProviders = [];
    private ServiceProvider _serviceProvider = null!;
    private FakeTimeProvider _timeProvider = null!;
    private CancellationTokenSource? _hostedCancellation;
    private int _hostedRequestCount;

    [SetUp]
    public async Task SetUpAsync()
    {
        _timeProvider = new FakeTimeProvider(_now);
        _hostedCancellation = null;
        _hostedRequestCount = 0;
        _dispatcherProviders.Clear();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAshlarSqlite(GetConnectionString());
        services.AddSqliteProviderContractTestServices();
        services.AddAshlarSqliteSecurityEventWebhookOutbox();
        services.AddSqliteWebhookProviderContractTestService();
        services.AddSingleton<TimeProvider>(_timeProvider);
        _serviceProvider = services.BuildServiceProvider();

        await _serviceProvider.InitializeAshlarSqliteSchemaAsync();
    }

    [TearDown]
    public async Task TearDownAsync()
    {
        foreach (var provider in _dispatcherProviders)
        {
            await provider.DisposeAsync();
        }

        _dispatcherProviders.Clear();
        await _serviceProvider.DisposeAsync();
    }

    [Test]
    public async Task SchemaInitializationCreatesWebhookOutboxTableAndIndexes()
    {
        await using var connection = await OpenConnectionAsync();

        var tableExists = await ExistsAsync(connection, "table", "ashlar_security_event_webhook_outbox");
        var indexes = await QueryIndexNamesAsync(connection);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(tableExists, Is.True);
            Assert.That(indexes, Is.SupersetOf(ExpectedIndexes));
        }
    }

    [Test]
    public void AddAshlarSqliteSecurityEventWebhookOutboxValidatesOptionsOnStart()
    {
        var services = new ServiceCollection();

        services.AddAshlarSqliteSecurityEventWebhookOutbox(options => options.BatchSize = 0);

        using var provider = services.BuildServiceProvider();

        var exception = Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IStartupValidator>().Validate());
        Assert.That(exception?.OptionsType, Is.EqualTo(typeof(SqliteSecurityEventWebhookOutboxOptions)));
    }

    [Test]
    public async Task EnqueueStoresSafeBodyHeadersAndSignatureWithoutSecret()
    {
        var delivery = CreateDelivery(ValidSecret);
        var enqueuer = _serviceProvider.GetRequiredService<IAshlarSecurityEventWebhookEnqueuer>();

        await enqueuer.EnqueueAsync(delivery);

        var row = await QuerySingleOutboxRowAsync();
        var headers = JsonSerializer.Deserialize<Dictionary<string, string>>(row.Headers)!;

        using (Assert.EnterMultipleScope())
        {
            Assert.That(row.EndpointName, Is.EqualTo("audit"));
            Assert.That(row.Uri, Is.EqualTo("https://example.test/security-events"));
            Assert.That(row.EventId, Is.EqualTo(delivery.Payload.Id));
            Assert.That(row.EventType, Is.EqualTo(delivery.Payload.EventType));
            Assert.That(row.Outcome, Is.EqualTo(delivery.Payload.Outcome));
            Assert.That(row.OccurredAt, Is.EqualTo(delivery.Payload.OccurredAt));
            Assert.That(row.TimeoutMs, Is.EqualTo(10000));
            Assert.That(row.Body, Is.EqualTo(delivery.Body.ToArray()));
            Assert.That(Encoding.UTF8.GetString(row.Body), Does.Contain("\"eventType\":\"ashlar.sign_in.failed\""));
            Assert.That(Encoding.UTF8.GetString(row.Body), Does.Not.Contain("203.0.113.10"));
            Assert.That(headers["X-Ashlar-Signature"], Is.EqualTo(CreateSignature(ValidSecret, delivery.Body.Span)));
            Assert.That(headers["X-Ashlar-Signature"], Is.Not.EqualTo(CreateSignature(ChangedSecret, delivery.Body.Span)));
            Assert.That(row.Headers, Does.Not.Contain(ValidSecret));
            Assert.That(row.CreatedAt, Is.EqualTo(_timeProvider.GetUtcNow()));
            Assert.That(row.AvailableAt, Is.EqualTo(_timeProvider.GetUtcNow()));
        }
    }

    [Test]
    public async Task EnqueueRollsBackInsideAshlarTransaction()
    {
        var txProvider = _serviceProvider.GetRequiredService<AshlarDurableTransactionProvider>();
        var enqueuer = _serviceProvider.GetRequiredService<IAshlarSecurityEventWebhookEnqueuer>();

        await using (await txProvider.BeginTransactionAsync())
        {
            await enqueuer.EnqueueAsync(CreateDelivery());
        }

        Assert.That(await CountRowsAsync(), Is.Zero);
    }

    [Test]
    public async Task DispatcherSendsPendingWebhookAndMarksItSent()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        await EnqueueAsync(CreateDelivery());

        var count = await CreateDispatcher(transport).ProcessBatchAsync();
        var row = await QuerySingleOutboxRowAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(count, Is.EqualTo(1));
            Assert.That(transport.Requests, Has.Count.EqualTo(1));
            Assert.That(transport.Requests[0].Body, Is.EqualTo(Encoding.UTF8.GetString(CreateDelivery().Body.Span)));
            Assert.That(transport.Requests[0].ContentType, Is.EqualTo("application/json"));
            Assert.That(transport.Requests[0].Headers["X-Ashlar-Event-Type"].Single(), Is.EqualTo("ashlar.sign_in.failed"));
            Assert.That(row.SentAt, Is.EqualTo(_now));
            Assert.That(row.AttemptCount, Is.EqualTo(1));
            Assert.That(row.LockedBy, Is.Null);
        }
    }

    [Test]
    public async Task DispatcherDoesNotMarkSentWhenLockOwnerChangesAfterSuccessfulWebhookSend()
    {
        await EnqueueAsync(CreateDelivery());
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted)
        {
            OnRequestAsync = () => ExecuteAsync(
                "UPDATE ashlar_security_event_webhook_outbox SET locked_by = $lockedBy",
                command => command.AddParameter("$lockedBy", "other-dispatcher"))
        };

        var count = await CreateDispatcher(transport).ProcessBatchAsync();
        var row = await QuerySingleOutboxRowAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(count, Is.EqualTo(1));
            Assert.That(transport.Requests, Has.Count.EqualTo(1));
            Assert.That(row.SentAt, Is.Null);
            Assert.That(row.FailedAt, Is.Null);
            Assert.That(row.AttemptCount, Is.Zero);
            Assert.That(row.LastError, Is.Null);
            Assert.That(row.LockedBy, Is.EqualTo("other-dispatcher"));
        }
    }

    [Test]
    public async Task DispatcherDoesNotSendLaterBatchEntryAfterLeaseExpires()
    {
        await EnqueueAsync(CreateDelivery());
        await EnqueueAsync(CreateDelivery());
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted)
        {
            OnRequestAsync = () =>
            {
                _timeProvider.Advance(TimeSpan.FromMinutes(2));
                return Task.CompletedTask;
            }
        };

        var count = await CreateDispatcher(transport, new SqliteSecurityEventWebhookOutboxOptions
        {
            BatchSize = 2,
            LockDuration = TimeSpan.FromMinutes(1)
        }).ProcessBatchAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(count, Is.EqualTo(2));
            Assert.That(transport.Requests, Has.Count.EqualTo(1));
        }
    }

    [Test]
    public async Task DispatcherDoesNotMarkSentWhenWebhookRowBecomesTerminalAfterSuccessfulSend()
    {
        await EnqueueAsync(CreateDelivery());
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted)
        {
            OnRequestAsync = () => ExecuteAsync(
                "UPDATE ashlar_security_event_webhook_outbox SET failed_at = $failedAt",
                command => command.AddDateTimeOffsetParameter("$failedAt", _timeProvider.GetUtcNow()))
        };

        await CreateDispatcher(transport).ProcessBatchAsync();
        var row = await QuerySingleOutboxRowAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(transport.Requests, Has.Count.EqualTo(1));
            Assert.That(row.SentAt, Is.Null);
            Assert.That(row.FailedAt, Is.EqualTo(_timeProvider.GetUtcNow()));
            Assert.That(row.AttemptCount, Is.Zero);
            Assert.That(row.LastError, Is.Null);
        }
    }

    [Test]
    public async Task DispatcherRegeneratesSignatureAtSendTime()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        await EnqueueAsync(CreateDelivery(OldSecret));

        await CreateDispatcher(transport, webhookOptions: CreateWebhookOptions(CurrentSecret)).ProcessBatchAsync();

        var request = transport.Requests.Single();
        var result = AshlarSecurityEventWebhookSignature.Verify(new AshlarSecurityEventWebhookVerificationRequest
        {
            Body = Encoding.UTF8.GetBytes(request.Body),
            Headers = request.Headers.ToDictionary(header => header.Key, header => header.Value.Single(), StringComparer.Ordinal),
            SharedSecret = CurrentSecret,
            EventId = new Guid("11111111-1111-1111-1111-111111111111"),
            EndpointName = "audit",
            DestinationPathAndQuery = "/security-events",
            TimeProvider = _timeProvider,
            Options = new AshlarSecurityEventWebhookVerificationOptions
            {
                ReplayStore = new AcceptingReplayStore()
            }
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsValid, Is.True);
            Assert.That(request.Headers[AshlarSecurityEventWebhookSignature.SignatureHeaderName].Single(), Is.Not.EqualTo(CreateSignature(OldSecret, Encoding.UTF8.GetBytes(request.Body))));
        }
    }

    [TestCase(true)]
    [TestCase(false)]
    public async Task DispatcherFailsSafelyWhenSigningConfigurationIsUnavailable(bool missingEndpoint)
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        await EnqueueAsync(CreateDelivery());
        var webhookOptions = missingEndpoint ? new AshlarSecurityEventWebhookOptions() : CreateWebhookOptionsWithoutSecret();

        await CreateDispatcher(
            transport,
            new SqliteSecurityEventWebhookOutboxOptions { MaxAttempts = 1 },
            webhookOptions: webhookOptions).ProcessBatchAsync();

        var row = await QuerySingleOutboxRowAsync();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(transport.Requests, Is.Empty);
            Assert.That(row.FailedAt, Is.EqualTo(_now));
            Assert.That(row.AttemptCount, Is.EqualTo(1));
            Assert.That(row.LastError, Is.EqualTo("kind=unknown;reason=unknown_failure"));
        }
    }

    [Test]
    public async Task DispatcherConcurrentCallsOnSameInstanceDoNotSendSameWebhookTwice()
    {
        var firstSendStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseFirstSend = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var transport = new BlockingFirstHttpMessageHandler(firstSendStarted, releaseFirstSend);
        await EnqueueAsync(CreateDelivery());
        var dispatcher = CreateDispatcher(transport);

        var first = dispatcher.ProcessBatchAsync();
        await firstSendStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var second = await dispatcher.ProcessBatchAsync().WaitAsync(TimeSpan.FromSeconds(5));

        releaseFirstSend.SetResult();
        var firstCount = await first.WaitAsync(TimeSpan.FromSeconds(5));
        var row = await QuerySingleOutboxRowAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(firstCount, Is.EqualTo(1));
            Assert.That(second, Is.Zero);
            Assert.That(firstCount + second, Is.EqualTo(1));
            Assert.That(transport.Requests, Has.Count.EqualTo(1));
            Assert.That(row.SentAt, Is.EqualTo(_now));
            Assert.That(row.AttemptCount, Is.EqualTo(1));
            Assert.That(row.LockedBy, Is.Null);
        }
    }

    [Test]
    public async Task DispatcherKeepsLeaseForInFlightSendTimeout()
    {
        await EnqueueAsync(CreateDelivery(timeout: TimeSpan.FromMinutes(5)));
        var firstSendStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseFirstSend = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var transport = new BlockingFirstHttpMessageHandler(firstSendStarted, releaseFirstSend);
        var options = new SqliteSecurityEventWebhookOutboxOptions { LockDuration = TimeSpan.FromMinutes(1) };
        var first = CreateDispatcher(transport, options).ProcessBatchAsync();
        await firstSendStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));

        _timeProvider.Advance(TimeSpan.FromMinutes(5.5));
        var second = await CreateDispatcher(transport, options).ProcessBatchAsync().WaitAsync(TimeSpan.FromSeconds(5));
        releaseFirstSend.SetResult();
        await first.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.That(second, Is.Zero);
    }

    [Test]
    public async Task DispatcherReportsDeliveryObserver()
    {
        var observer = new RecordingDeliveryObserver();
        await EnqueueAsync(CreateDelivery());

        await CreateDispatcher(new RecordingHttpMessageHandler(HttpStatusCode.Accepted), observer: observer).ProcessBatchAsync();

        var telemetry = observer.Attempts.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(telemetry.DeliveryMode, Is.EqualTo(AshlarSecurityEventWebhookDeliveryTelemetry.DurableOutboxDeliveryMode));
            Assert.That(telemetry.Outcome, Is.EqualTo(AshlarSecurityEventWebhookDeliveryTelemetry.SuccessOutcome));
            Assert.That(telemetry.EventType, Is.EqualTo("ashlar.sign_in.failed"));
            Assert.That(telemetry.EndpointName, Is.EqualTo("audit"));
        }
    }

    [Test]
    public async Task DispatcherReportsDeliveryObserverFailures()
    {
        var observer = new RecordingDeliveryObserver();
        await EnqueueAsync(CreateDelivery());

        await CreateDispatcher(new RecordingHttpMessageHandler(HttpStatusCode.BadGateway), observer: observer).ProcessBatchAsync();

        var telemetry = observer.Attempts.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(telemetry.Outcome, Is.EqualTo(AshlarSecurityEventWebhookDeliveryTelemetry.FailureOutcome));
            Assert.That(telemetry.FailureKind, Is.EqualTo(AshlarSecurityEventWebhookDeliveryTelemetry.HttpStatusFailureKind));
        }
    }

    [Test]
    public async Task DispatcherRetriesFailedSends()
    {
        await EnqueueAsync(CreateDelivery());
        var dispatcher = CreateDispatcher(
            new RecordingHttpMessageHandler(HttpStatusCode.BadGateway),
            new SqliteSecurityEventWebhookOutboxOptions { MaxAttempts = 2, InitialRetryDelay = TimeSpan.FromSeconds(30) });

        await dispatcher.ProcessBatchAsync();
        var row = await QuerySingleOutboxRowAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(row.SentAt, Is.Null);
            Assert.That(row.FailedAt, Is.Null);
            Assert.That(row.AttemptCount, Is.EqualTo(1));
            Assert.That(row.LastAttemptAt, Is.EqualTo(_now));
            Assert.That(row.AvailableAt, Is.EqualTo(_now.AddSeconds(30)));
            Assert.That(row.LastError, Is.EqualTo("kind=http_status;status=502;reason=non_success_status"));
        }
    }

    [TestCase("sent_at")]
    [TestCase("failed_at")]
    [TestCase("discarded_at")]
    public async Task DispatcherDoesNotOverwriteTerminalWebhookRowDuringFailedDelivery(string terminalColumn)
    {
        await EnqueueAsync(CreateDelivery());
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.BadGateway)
        {
            OnRequestAsync = () => ExecuteAsync(
                $"UPDATE ashlar_security_event_webhook_outbox SET {terminalColumn} = $terminalAt",
                command => command.AddDateTimeOffsetParameter("$terminalAt", _timeProvider.GetUtcNow()))
        };
        var dispatcher = CreateDispatcher(transport, new SqliteSecurityEventWebhookOutboxOptions { MaxAttempts = 1 });

        await dispatcher.ProcessBatchAsync();
        var row = await QuerySingleOutboxRowAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(row.SentAt, terminalColumn == "sent_at" ? Is.EqualTo(_now) : Is.Null);
            Assert.That(row.FailedAt, terminalColumn == "failed_at" ? Is.EqualTo(_now) : Is.Null);
            Assert.That(row.DiscardedAt, terminalColumn == "discarded_at" ? Is.EqualTo(_now) : Is.Null);
            Assert.That(row.AttemptCount, Is.Zero);
            Assert.That(row.LastError, Is.Null);
        }
    }

    [Test]
    public async Task DispatcherMarksTerminalFailuresWhenMaxAttemptsReached()
    {
        await EnqueueAsync(CreateDelivery());
        var dispatcher = CreateDispatcher(
            new RecordingHttpMessageHandler(HttpStatusCode.BadGateway),
            new SqliteSecurityEventWebhookOutboxOptions { MaxAttempts = 1 });

        await dispatcher.ProcessBatchAsync();
        var row = await QuerySingleOutboxRowAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(row.SentAt, Is.Null);
            Assert.That(row.FailedAt, Is.EqualTo(_now));
            Assert.That(row.AttemptCount, Is.EqualTo(1));
            Assert.That(row.AvailableAt, Is.EqualTo(_now));
        }
    }

    [Test]
    public async Task ActiveLockedRowsAreSkipped()
    {
        await EnqueueAsync(CreateDelivery());
        await ExecuteAsync("UPDATE ashlar_security_event_webhook_outbox SET locked_until = $lockedUntil, locked_by = 'other'", command =>
            command.AddDateTimeOffsetParameter("$lockedUntil", _now.AddMinutes(5)));
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);

        var count = await CreateDispatcher(transport).ProcessBatchAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(count, Is.Zero);
            Assert.That(transport.Requests, Is.Empty);
        }
    }

    [Test]
    public async Task ExpiredLocksCanBeReclaimed()
    {
        await EnqueueAsync(CreateDelivery());
        await ExecuteAsync("UPDATE ashlar_security_event_webhook_outbox SET locked_until = $lockedUntil, locked_by = 'other'", command =>
            command.AddDateTimeOffsetParameter("$lockedUntil", _now.AddMinutes(-1)));
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);

        var count = await CreateDispatcher(transport).ProcessBatchAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(count, Is.EqualTo(1));
            Assert.That(transport.Requests, Has.Count.EqualTo(1));
        }
    }

    [Test]
    public async Task LocksExpiringExactlyNowCanBeReclaimed()
    {
        await EnqueueAsync(CreateDelivery());
        await ExecuteAsync("UPDATE ashlar_security_event_webhook_outbox SET locked_until = $lockedUntil, locked_by = 'other'", command =>
            command.AddDateTimeOffsetParameter("$lockedUntil", _now));
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);

        var count = await CreateDispatcher(transport).ProcessBatchAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(count, Is.EqualTo(1));
            Assert.That(transport.Requests, Has.Count.EqualTo(1));
        }
    }

    [Test]
    public async Task DispatcherUsesPersistedTimeoutForHttpSend()
    {
        await EnqueueAsync(CreateDelivery(timeout: TimeSpan.FromMilliseconds(1)));
        var dispatcher = CreateDispatcher(
            new DelayingHttpMessageHandler(),
            new SqliteSecurityEventWebhookOutboxOptions { InitialRetryDelay = TimeSpan.FromSeconds(5) });

        await dispatcher.ProcessBatchAsync();
        var row = await QuerySingleOutboxRowAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(row.SentAt, Is.Null);
            Assert.That(row.FailedAt, Is.Null);
            Assert.That(row.AttemptCount, Is.EqualTo(1));
            Assert.That(row.LastError, Is.EqualTo("kind=timeout;reason=delivery_timeout"));
        }
    }

    [Test]
    public async Task DispatcherRejectsUnsafePersistedDestinationBeforeHttpSend()
    {
        await EnqueueAsync(CreateDelivery());
        await ExecuteAsync(
            "UPDATE ashlar_security_event_webhook_outbox SET uri = $uri",
            command => command.Parameters.AddWithValue("$uri", "https://127.0.0.1/security-events"));

        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var webhookOptions = CreateWebhookOptions();
        webhookOptions.Endpoints.Single().Uri = new Uri("https://127.0.0.1/security-events");

        await CreateDispatcher(
            transport,
            new SqliteSecurityEventWebhookOutboxOptions { MaxAttempts = 1 },
            webhookOptions: webhookOptions).ProcessBatchAsync();
        var row = await QuerySingleOutboxRowAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(transport.Requests, Is.Empty);
            Assert.That(row.SentAt, Is.Null);
            Assert.That(row.FailedAt, Is.EqualTo(_now));
            Assert.That(row.AttemptCount, Is.EqualTo(1));
            Assert.That(row.LastError, Is.EqualTo("kind=unsafe_destination;reason=unsafe_destination"));
            Assert.That(row.LastError, Does.Not.Contain("127.0.0.1"));
        }
    }

    [Test]
    public async Task SuccessfulSendWithMarkSentDatabaseFailureDoesNotMarkDeliveryFailed()
    {
        await EnqueueAsync(CreateDelivery());
        await using var provider = new ServiceCollection()
            .AddSingleton<ISqliteConnectionProvider>(new ThrowingAfterFirstConnectionProvider(_serviceProvider.GetRequiredService<ISqliteConnectionProvider>()))
            .BuildServiceProvider();
        var dispatcher = new SqliteSecurityEventWebhookOutboxDispatcher(
            provider,
            _timeProvider,
            Options.Create(new SqliteSecurityEventWebhookOutboxOptions()),
            Options.Create(CreateWebhookOptions()),
            new TestHttpClientFactory(new RecordingHttpMessageHandler(HttpStatusCode.Accepted)),
            CreateDestinationValidator());

        Assert.ThrowsAsync<InvalidOperationException>(() => dispatcher.ProcessBatchAsync());
        var row = await QuerySingleOutboxRowAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(row.SentAt, Is.Null);
            Assert.That(row.FailedAt, Is.Null);
            Assert.That(row.AttemptCount, Is.Zero);
            Assert.That(row.LastError, Is.Null);
            Assert.That(row.LockedBy, Is.Not.Null);
        }
    }

    [Test]
    public async Task DispatcherRespectsBatchSizeAndReturnsZeroWhenEmpty()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var dispatcher = CreateDispatcher(transport, new SqliteSecurityEventWebhookOutboxOptions { BatchSize = 2 });

        Assert.That(await dispatcher.ProcessBatchAsync(), Is.Zero);
        await EnqueueAsync(CreateDelivery());
        await EnqueueAsync(CreateDelivery());
        await EnqueueAsync(CreateDelivery());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(await dispatcher.ProcessBatchAsync(), Is.EqualTo(2));
            Assert.That(transport.Requests, Has.Count.EqualTo(2));
        }
    }

    [Test]
    public async Task DispatcherRethrowsWhenCallerCancelsDuringSend()
    {
        await EnqueueAsync(CreateDelivery());
        using var cts = new CancellationTokenSource();
        var dispatcher = CreateDispatcher(new CancelingHttpMessageHandler(cts));

        Assert.ThrowsAsync(Is.InstanceOf<OperationCanceledException>(), () => dispatcher.ProcessBatchAsync(cts.Token));
    }

    [Test]
    public async Task DispatcherCancellationBeforeClaimThrows()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        var dispatcher = CreateDispatcher(new RecordingHttpMessageHandler(HttpStatusCode.Accepted));

        Assert.ThrowsAsync(Is.InstanceOf<OperationCanceledException>(), () => dispatcher.ProcessBatchAsync(cts.Token));
    }

    [Test]
    public void OptionsValidateAndNullArguments()
    {
        var connectionProvider = _serviceProvider.GetRequiredService<ISqliteConnectionProvider>();
        var options = Options.Create(new SqliteSecurityEventWebhookOutboxOptions());
        var destinationValidator = CreateDestinationValidator();
        var deliveryFactory = _serviceProvider.GetRequiredService<AshlarSecurityEventWebhookDeliveryFactory>();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(SqliteSecurityEventWebhookOutboxOptions.Validate(new SqliteSecurityEventWebhookOutboxOptions()), Is.True);
            Assert.That(SqliteSecurityEventWebhookOutboxOptions.Validate(new SqliteSecurityEventWebhookOutboxOptions { BatchSize = 0 }), Is.False);
            Assert.That(SqliteSecurityEventWebhookOutboxOptions.Validate(new SqliteSecurityEventWebhookOutboxOptions { LockDuration = TimeSpan.Zero }), Is.False);
            Assert.That(SqliteSecurityEventWebhookOutboxOptions.Validate(new SqliteSecurityEventWebhookOutboxOptions { MaxAttempts = 0 }), Is.False);
            Assert.That(SqliteSecurityEventWebhookOutboxOptions.Validate(new SqliteSecurityEventWebhookOutboxOptions { InitialRetryDelay = TimeSpan.Zero }), Is.False);
            Assert.That(SqliteSecurityEventWebhookOutboxOptions.Validate(new SqliteSecurityEventWebhookOutboxOptions { PollingInterval = TimeSpan.Zero }), Is.False);
            Assert.Throws<ArgumentNullException>(() => SqliteSecurityEventWebhookOutboxOptions.Validate(null!));
            Assert.Throws<ArgumentNullException>(() => new SqliteSecurityEventWebhookEnqueuer(null!, _timeProvider, deliveryFactory));
            Assert.Throws<ArgumentNullException>(() => new SqliteSecurityEventWebhookEnqueuer(connectionProvider, null!, deliveryFactory));
            Assert.Throws<ArgumentNullException>(() => new SqliteSecurityEventWebhookEnqueuer(connectionProvider, _timeProvider, null!));
            Assert.Throws<ArgumentNullException>(() => new SqliteSecurityEventWebhookOutboxDispatcher(null!, _timeProvider, options, Options.Create(CreateWebhookOptions()), new TestHttpClientFactory(new RecordingHttpMessageHandler(HttpStatusCode.OK)), destinationValidator));
            Assert.Throws<ArgumentNullException>(() => new SqliteSecurityEventWebhookOutboxDispatcher(_serviceProvider, null!, options, Options.Create(CreateWebhookOptions()), new TestHttpClientFactory(new RecordingHttpMessageHandler(HttpStatusCode.OK)), destinationValidator));
            Assert.Throws<ArgumentNullException>(() => new SqliteSecurityEventWebhookOutboxDispatcher(_serviceProvider, _timeProvider, null!, Options.Create(CreateWebhookOptions()), new TestHttpClientFactory(new RecordingHttpMessageHandler(HttpStatusCode.OK)), destinationValidator));
            Assert.Throws<ArgumentNullException>(() => new SqliteSecurityEventWebhookOutboxDispatcher(_serviceProvider, _timeProvider, options, null!, new TestHttpClientFactory(new RecordingHttpMessageHandler(HttpStatusCode.OK)), destinationValidator));
            Assert.Throws<ArgumentNullException>(() => new SqliteSecurityEventWebhookOutboxDispatcher(_serviceProvider, _timeProvider, options, Options.Create(CreateWebhookOptions()), null!, destinationValidator));
            Assert.Throws<ArgumentNullException>(() => new SqliteSecurityEventWebhookOutboxDispatcher(_serviceProvider, _timeProvider, options, Options.Create(CreateWebhookOptions()), new TestHttpClientFactory(new RecordingHttpMessageHandler(HttpStatusCode.OK)), null!));
            Assert.Throws<ArgumentNullException>(() => new SqliteSecurityEventWebhookOutboxHostedService(null!, options));
            Assert.Throws<ArgumentNullException>(() => new SqliteSecurityEventWebhookOutboxHostedService(_serviceProvider, null!));
        }
    }

    [Test]
    public async Task DispatcherThrowsForInvalidOptions()
    {
        var dispatcher = CreateDispatcher(
            new RecordingHttpMessageHandler(HttpStatusCode.Accepted),
            new SqliteSecurityEventWebhookOutboxOptions { BatchSize = 0 });

        Assert.ThrowsAsync<InvalidOperationException>(() => dispatcher.ProcessBatchAsync());
    }

    [Test]
    public void SharedDispatchHelpersHandleHeadersAndErrors()
    {
        var failure = AshlarSecurityEventWebhookOutboxDispatch.CreateFailureUpdate(
            0,
            5,
            TimeSpan.FromSeconds(1),
            _timeProvider.GetUtcNow(),
            new InvalidOperationException(new string('X', 2000)));
        using var contentHeaderRequest = AshlarSecurityEventWebhookOutboxDispatch.MapToHttpRequest(new AshlarSecurityEventWebhookOutboxEntry
        {
            Id = Guid.NewGuid(),
            EndpointName = "audit",
            Uri = "https://example.test/security-events",
            EventId = Guid.NewGuid(),
            EventType = "ashlar.test",
            Outcome = SecurityEventOutcomes.Success,
            OccurredAt = _now,
            Body = Encoding.UTF8.GetBytes("{}"),
            Headers = """{"Content-Encoding":"gzip","X-Ashlar-Event-Type":"ashlar.test"}""",
            TimeoutMs = 1000,
            AttemptCount = 0
        });
        using var nullHeaderRequest = AshlarSecurityEventWebhookOutboxDispatch.MapToHttpRequest(new AshlarSecurityEventWebhookOutboxEntry
        {
            Id = Guid.NewGuid(),
            EndpointName = "audit",
            Uri = "https://example.test/security-events",
            EventId = Guid.NewGuid(),
            EventType = "ashlar.test",
            Outcome = SecurityEventOutcomes.Success,
            OccurredAt = _now,
            Body = Encoding.UTF8.GetBytes("{}"),
            Headers = "null",
            TimeoutMs = 1000,
            AttemptCount = 0
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(failure.LastError, Is.EqualTo("kind=unknown;reason=unknown_failure"));
            Assert.That(failure.LastError, Has.Length.LessThanOrEqualTo(AshlarSecurityEventWebhookOutboxDispatch.MaxPersistedFailureDetailLength));
            Assert.That(contentHeaderRequest.Headers.TryGetValues("X-Ashlar-Event-Type", out var requestValues), Is.True);
            Assert.That(requestValues!.Single(), Is.EqualTo("ashlar.test"));
            Assert.That(contentHeaderRequest.Content!.Headers.ContentEncoding.Single(), Is.EqualTo("gzip"));
            Assert.That(nullHeaderRequest.Headers, Is.Empty);
        }

        Assert.Throws<ArgumentNullException>(() => AshlarSecurityEventWebhookOutboxDispatch.MapToHttpRequest(null!));
        Assert.Throws<ArgumentNullException>(() => AshlarSecurityEventWebhookOutboxDispatch.CreateFailureUpdate(0, 1, TimeSpan.FromSeconds(1), _now, null!));
    }

    [Test]
    public async Task DiRegistrationsResolveExpectedServicesAndHostedServiceIsOptIn()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAshlarSqlite("Data Source=:memory:");
        services.AddAshlarSqliteSecurityEventWebhookDispatcher(
            options => options.BatchSize = 7,
            webhooks => webhooks.DestinationPolicy = AshlarSecurityEventWebhookDestinationPolicy.AllowPrivateNetworks,
            client => client.DefaultRequestHeaders.Add("X-Test", "configured"));

        await using var provider = services.BuildServiceProvider();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.GetService<IAshlarSecurityEventWebhookEnqueuer>(), Is.Null);
            Assert.That(provider.GetService<IAshlarSecurityEventWebhookOutboxBrowser>(), Is.InstanceOf<SqliteSecurityEventWebhookOutboxBrowser>());
            Assert.That(provider.GetService<SqliteSecurityEventWebhookOutboxDispatcher>(), Is.Not.Null);
            Assert.That(provider.GetServices<IHostedService>(), Is.Empty);
            Assert.That(provider.GetRequiredService<IOptions<SqliteSecurityEventWebhookOutboxOptions>>().Value.BatchSize, Is.EqualTo(7));
            Assert.That(provider.GetRequiredService<IOptions<AshlarSecurityEventWebhookOptions>>().Value.DestinationPolicy, Is.EqualTo(AshlarSecurityEventWebhookDestinationPolicy.AllowPrivateNetworks));
            Assert.That(provider.GetRequiredService<IHttpClientFactory>().CreateClient(SqliteSecurityEventWebhookOutboxDispatcher.HttpClientName).DefaultRequestHeaders.GetValues("X-Test").Single(), Is.EqualTo("configured"));
        }
    }

    [Test]
    public async Task HostedServiceRegistrationIsOptInAndPassesThroughHttpClientConfigure()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAshlarSqlite("Data Source=:memory:");
        services.AddAshlarSqliteSecurityEventWebhookHostedService(
            configureHttpClient: client => client.DefaultRequestHeaders.Add("X-Test", "configured"));

        await using var provider = services.BuildServiceProvider();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.GetServices<IHostedService>().Any(service => service is SqliteSecurityEventWebhookOutboxHostedService), Is.True);
            Assert.That(provider.GetService<IAshlarSecurityEventWebhookEnqueuer>(), Is.Null);
            Assert.That(provider.GetService<SqliteSecurityEventWebhookOutboxDispatcher>(), Is.Not.Null);
            Assert.That(provider.GetRequiredService<IHttpClientFactory>().CreateClient(SqliteSecurityEventWebhookOutboxDispatcher.HttpClientName).DefaultRequestHeaders.GetValues("X-Test").Single(), Is.EqualTo("configured"));
        }
    }

    [Test]
    public async Task DurableWebhookHandlerResolvesWithScopedSqliteEnqueuerUnderScopeValidation()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAshlarSqlite(GetConnectionString());
        services.AddAshlarSqliteSecurityEventWebhookOutbox();
        services.AddAshlarSecurityEventWebhookOutbox();
        services.AddSqliteProviderContractTestServices();
        services.AddSqliteWebhookProviderContractTestService();

        await using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        await using var scope = provider.CreateAsyncScope();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scope.ServiceProvider.GetRequiredService<ISecurityEventSink>(), Is.TypeOf<SecurityEventFanOutSink>());
            Assert.That(scope.ServiceProvider.GetServices<IDurableSecurityEventFanOutHandler>().Single(), Is.TypeOf<SqliteSecurityEventWebhookEnqueuer>());
            Assert.That(scope.ServiceProvider.GetServices<ISecurityEventHandler>(), Is.Empty);
            Assert.That(scope.ServiceProvider.GetRequiredService<IAshlarSecurityEventWebhookEnqueuer>(), Is.TypeOf<SqliteSecurityEventWebhookEnqueuer>());
        }
    }

    [Test]
    public async Task HostedServiceStartValidationAndLoopAreCovered()
    {
        var invalid = new SqliteSecurityEventWebhookOutboxHostedService(
            _serviceProvider,
            Options.Create(new SqliteSecurityEventWebhookOutboxOptions { BatchSize = 0 }));
        Assert.ThrowsAsync<InvalidOperationException>(() => invalid.StartAsync(CancellationToken.None));

        await EnqueueAsync(CreateDelivery());
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted)
        {
            OnRequestAsync = () =>
            {
                if (Interlocked.Increment(ref _hostedRequestCount) >= 1)
                {
                    _ = _hostedCancellation!.CancelAsync();
                }

                return Task.CompletedTask;
            }
        };
        await using var provider = CreateHostedServiceProvider(transport, new SqliteSecurityEventWebhookOutboxOptions { PollingInterval = TimeSpan.FromMilliseconds(1) });
        var hosted = new SqliteSecurityEventWebhookOutboxHostedService(
            provider,
            Options.Create(new SqliteSecurityEventWebhookOutboxOptions { PollingInterval = TimeSpan.FromMilliseconds(1) }));
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        _hostedCancellation = cts;

        await hosted.StartAsync(cts.Token);
        await hosted.ExecuteTask!.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.That(_hostedRequestCount, Is.EqualTo(1));
    }

    [Test]
    public async Task HostedServiceContinuesImmediatelyWhenBatchIsFullAndContinuesOnErrorUntilCanceled()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await EnqueueAsync(CreateDelivery());
        await EnqueueAsync(CreateDelivery());
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted)
        {
            OnRequestAsync = () =>
            {
                if (Interlocked.Increment(ref _hostedRequestCount) >= 2)
                {
                    cts.Cancel();
                }

                return Task.CompletedTask;
            }
        };
        await using var provider = CreateHostedServiceProvider(
            transport,
            new SqliteSecurityEventWebhookOutboxOptions { BatchSize = 1, PollingInterval = TimeSpan.FromHours(1) });
        var hosted = new SqliteSecurityEventWebhookOutboxHostedService(
            provider,
            Options.Create(new SqliteSecurityEventWebhookOutboxOptions { BatchSize = 1, PollingInterval = TimeSpan.FromHours(1) }));

        await hosted.StartAsync(cts.Token);
        await hosted.ExecuteTask!.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.That(_hostedRequestCount, Is.EqualTo(2));

        using var errorCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await using var emptyProvider = new ServiceCollection().BuildServiceProvider();
        var errorHosted = new SqliteSecurityEventWebhookOutboxHostedService(
            emptyProvider,
            Options.Create(new SqliteSecurityEventWebhookOutboxOptions { PollingInterval = TimeSpan.FromMilliseconds(1) }));
        await errorHosted.StartAsync(errorCts.Token);
        await Task.Delay(30, TestContext.CurrentContext.CancellationToken);
        await errorCts.CancelAsync();
        await errorHosted.ExecuteTask!;

        Assert.That(errorHosted.ExecuteTask.IsCompleted, Is.True);
    }

    private async Task EnqueueAsync(AshlarSecurityEventWebhookDelivery delivery)
    {
        await _serviceProvider.GetRequiredService<IAshlarSecurityEventWebhookEnqueuer>().EnqueueAsync(delivery);
    }

    private SqliteSecurityEventWebhookOutboxDispatcher CreateDispatcher(
        HttpMessageHandler transport,
        SqliteSecurityEventWebhookOutboxOptions? options = null,
        IAshlarSecurityEventWebhookDeliveryObserver? observer = null,
        AshlarSecurityEventWebhookOptions? webhookOptions = null)
    {
        return new SqliteSecurityEventWebhookOutboxDispatcher(
            CreateDispatcherProvider(observer),
            _timeProvider,
            Options.Create(options ?? new SqliteSecurityEventWebhookOutboxOptions()),
            Options.Create(webhookOptions ?? CreateWebhookOptions()),
            new TestHttpClientFactory(transport),
            CreateDestinationValidator());
    }

    private ServiceProvider CreateDispatcherProvider(IAshlarSecurityEventWebhookDeliveryObserver? observer = null)
    {
        var services = new ServiceCollection();
        services.AddAshlarSqlite(GetConnectionString());
        services.AddSingleton<TimeProvider>(_timeProvider);
        services.AddSingleton(CreateDestinationValidator());
        if (observer != null)
        {
            services.AddSingleton(observer);
        }

        var provider = services.BuildServiceProvider();
        _dispatcherProviders.Add(provider);
        return provider;
    }

    private ServiceProvider CreateHostedServiceProvider(HttpMessageHandler transport, SqliteSecurityEventWebhookOutboxOptions options)
    {
        var services = new ServiceCollection();
        services.AddAshlarSqlite(GetConnectionString());
        services.AddSingleton<TimeProvider>(_timeProvider);
        services.AddSingleton<IHttpClientFactory>(new TestHttpClientFactory(transport));
        services.AddSingleton(Options.Create(options));
        services.AddSingleton(Options.Create(CreateWebhookOptions()));
        services.AddSingleton(CreateDestinationValidator());
        services.AddScoped<SqliteSecurityEventWebhookOutboxDispatcher>();
        return services.BuildServiceProvider();
    }

    [Test]
    public async Task DispatcherNamedHttpClientPreservesHardenedHandlerWithSafeConfiguration()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAshlarSqlite("Data Source=:memory:");
        services.AddAshlarSqliteSecurityEventWebhookDispatcher(configureHttpClient: client =>
        {
            client.Timeout = TimeSpan.FromSeconds(12);
            client.DefaultRequestHeaders.Add("X-Test", "configured");
        });
        await using var provider = services.BuildServiceProvider();
        using var handler = provider.GetRequiredService<IHttpMessageHandlerFactory>()
            .CreateHandler(SqliteSecurityEventWebhookOutboxDispatcher.HttpClientName);
        var httpClient = provider.GetRequiredService<IHttpClientFactory>().CreateClient(SqliteSecurityEventWebhookOutboxDispatcher.HttpClientName);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(ContainsHardenedSocketsHandler(handler), Is.True);
            Assert.That(httpClient.Timeout, Is.EqualTo(TimeSpan.FromSeconds(12)));
            Assert.That(httpClient.DefaultRequestHeaders.GetValues("X-Test").Single(), Is.EqualTo("configured"));
        }
    }

    private static AshlarSecurityEventWebhookDestinationValidator CreateDestinationValidator()
    {
        return new AshlarSecurityEventWebhookDestinationValidator(new StaticDestinationResolver());
    }

    private static AshlarSecurityEventWebhookDelivery CreateDelivery(string? sharedSecret = ValidSecret, TimeSpan? timeout = null)
    {
        var securityEvent = new AshlarSecurityEvent
        {
            Id = new Guid("11111111-1111-1111-1111-111111111111"),
            EventType = "ashlar.sign_in.failed",
            OccurredAt = new DateTimeOffset(2026, 5, 24, 11, 0, 0, TimeSpan.Zero),
            Outcome = SecurityEventOutcomes.Failure,
            IpAddress = "203.0.113.10"
        };
        var payload = AshlarSecurityEventWebhookDeliveryFactory.CreatePayload(securityEvent);
        var body = JsonSerializer.SerializeToUtf8Bytes(payload, WebJsonOptions);
        var endpoint = new AshlarSecurityEventWebhookEndpointOptions
        {
            Name = "audit",
            Uri = new Uri("https://example.test/security-events"),
            SharedSecret = sharedSecret,
            AllowUnsigned = sharedSecret is null
        };
        var headers = AshlarSecurityEventWebhookDeliveryFactory.CreateHeaders(
            endpoint,
            payload,
            body,
            DateTimeOffset.FromUnixTimeSeconds(1_800_000_000));

        return new AshlarSecurityEventWebhookDelivery(
            "audit",
            new Uri("https://example.test/security-events"),
            timeout ?? TimeSpan.FromSeconds(10),
            headers,
            payload);
    }

    private static AshlarSecurityEventWebhookOptions CreateWebhookOptions(string sharedSecret = ValidSecret)
    {
        var options = new AshlarSecurityEventWebhookOptions();
        options.Endpoints.Add(new AshlarSecurityEventWebhookEndpointOptions
        {
            Name = "audit",
            Uri = new Uri("https://example.test/security-events"),
            SharedSecret = sharedSecret
        });
        return options;
    }

    private static AshlarSecurityEventWebhookOptions CreateWebhookOptionsWithoutSecret()
    {
        var options = new AshlarSecurityEventWebhookOptions();
        options.Endpoints.Add(new AshlarSecurityEventWebhookEndpointOptions
        {
            Name = "audit",
            Uri = new Uri("https://example.test/security-events")
        });
        return options;
    }

    private static string CreateSignature(string sharedSecret, ReadOnlySpan<byte> body)
    {
        return AshlarSecurityEventWebhookSignature.CreateSignature(
            sharedSecret,
            body,
            DateTimeOffset.FromUnixTimeSeconds(1_800_000_000),
            new DateTimeOffset(2026, 5, 24, 11, 0, 0, TimeSpan.Zero),
            new Guid("11111111-1111-1111-1111-111111111111"),
            "audit",
            "/security-events");
    }

    private async Task ExecuteAsync(string sql, Action<Microsoft.Data.Sqlite.SqliteCommand> bind)
    {
        await using var connection = await OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        bind(command);
        await command.ExecuteNonQueryAsync();
    }

    private async Task<int> CountRowsAsync()
    {
        await using var connection = await OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT count(*) FROM ashlar_security_event_webhook_outbox";
        return Convert.ToInt32(await command.ExecuteScalarAsync(), CultureInfo.InvariantCulture);
    }

    private async Task<RawWebhookRow> QuerySingleOutboxRowAsync()
    {
        await using var connection = await OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT endpoint_name, uri, event_id, event_type, outcome, occurred_at, timeout_ms, body, headers,
                   created_at, available_at, sent_at, failed_at, discarded_at, attempt_count, last_error,
                   locked_by, last_attempt_at
            FROM ashlar_security_event_webhook_outbox
            ORDER BY created_at, id
            LIMIT 1
            """;
        await using var reader = await command.ExecuteReaderAsync();
        Assert.That(await reader.ReadAsync(), Is.True);
        return new RawWebhookRow
        {
            EndpointName = reader.GetString(reader.GetOrdinal("endpoint_name")),
            Uri = reader.GetString(reader.GetOrdinal("uri")),
            EventId = reader.GetGuidFromText("event_id"),
            EventType = reader.GetString(reader.GetOrdinal("event_type")),
            Outcome = reader.GetString(reader.GetOrdinal("outcome")),
            OccurredAt = reader.GetDateTimeOffsetFromText("occurred_at"),
            TimeoutMs = reader.GetInt64(reader.GetOrdinal("timeout_ms")),
            Body = (byte[])reader["body"],
            Headers = reader.GetString(reader.GetOrdinal("headers")),
            CreatedAt = reader.GetDateTimeOffsetFromText("created_at"),
            AvailableAt = reader.GetDateTimeOffsetFromText("available_at"),
            SentAt = reader.GetNullableDateTimeOffsetFromText("sent_at"),
            FailedAt = reader.GetNullableDateTimeOffsetFromText("failed_at"),
            DiscardedAt = reader.GetNullableDateTimeOffsetFromText("discarded_at"),
            AttemptCount = reader.GetInt32ByName("attempt_count"),
            LastError = reader.GetNullableString("last_error"),
            LockedBy = reader.GetNullableString("locked_by"),
            LastAttemptAt = reader.GetNullableDateTimeOffsetFromText("last_attempt_at")
        };
    }

    private static async Task<bool> ExistsAsync(Microsoft.Data.Sqlite.SqliteConnection connection, string type, string name)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT 1 FROM sqlite_master WHERE type = $type AND name = $name LIMIT 1;";
        command.Parameters.AddWithValue("$type", type);
        command.Parameters.AddWithValue("$name", name);
        return await command.ExecuteScalarAsync() != null;
    }

    private static async Task<IReadOnlyList<string>> QueryIndexNamesAsync(Microsoft.Data.Sqlite.SqliteConnection connection)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'ashlar_security_event_webhook_outbox';";
        var indexes = new List<string>();
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            indexes.Add(reader.GetString(0));
        }

        return indexes;
    }

    private sealed class TestHttpClientFactory(HttpMessageHandler transport) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name)
        {
            Assert.That(name, Is.EqualTo(SqliteSecurityEventWebhookOutboxDispatcher.HttpClientName));
            return new HttpClient(transport, disposeHandler: false);
        }
    }

    private sealed class StaticDestinationResolver : IAshlarSecurityEventWebhookDestinationResolver
    {
        public ValueTask<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken = default)
        {
            IReadOnlyList<IPAddress> addresses = [IPAddress.Parse("93.184.216.34")];
            return ValueTask.FromResult(addresses);
        }
    }

    private sealed class RedirectServer : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);

        public RedirectServer()
        {
            _listener.Start();
            RedirectUri = new Uri($"http://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}/redirect");
        }

        public Uri RedirectUri { get; }

        public int RequestCount { get; private set; }

        public async ValueTask DisposeAsync()
        {
            _listener.Stop();
            await ValueTask.CompletedTask;
        }

        public async Task ServeAsync(CancellationToken cancellationToken)
        {
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    using var client = await _listener.AcceptTcpClientAsync(cancellationToken);
                    RequestCount++;
                    await ReadRequestAsync(client.GetStream(), cancellationToken);
                    var response = RequestCount == 1
                        ? "HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        : "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    await client.GetStream().WriteAsync(Encoding.ASCII.GetBytes(response), cancellationToken);
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
            }
        }

        private static async Task ReadRequestAsync(NetworkStream stream, CancellationToken cancellationToken)
        {
            var buffer = new byte[1024];
            var builder = new StringBuilder();
            do
            {
                var read = await stream.ReadAsync(buffer, cancellationToken);
                builder.Append(Encoding.ASCII.GetString(buffer, 0, read));
            }
            while (!builder.ToString().Contains("\r\n\r\n", StringComparison.Ordinal));
        }
    }

    private static bool ContainsHardenedSocketsHandler(HttpMessageHandler handler)
    {
        if (handler is SocketsHttpHandler socketsHandler)
        {
            return !socketsHandler.AllowAutoRedirect && socketsHandler.ConnectCallback != null;
        }

        if (handler is DelegatingHandler { InnerHandler: { } innerHandler })
        {
            return ContainsHardenedSocketsHandler(innerHandler);
        }

        var fields = handler.GetType().GetFields(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
        foreach (var field in fields)
        {
            if (field.GetValue(handler) is HttpMessageHandler nestedHandler && ContainsHardenedSocketsHandler(nestedHandler))
            {
                return true;
            }
        }

        return false;
    }

    private sealed class RecordingHttpMessageHandler(HttpStatusCode statusCode) : HttpMessageHandler
    {
        public List<RecordedRequest> Requests { get; } = [];
        public Func<Task>? OnRequestAsync { get; set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(await RecordedRequest.CreateAsync(request, cancellationToken));
            if (OnRequestAsync != null)
            {
                await OnRequestAsync();
            }

            return new HttpResponseMessage(statusCode);
        }
    }

    private sealed class BlockingFirstHttpMessageHandler(
        TaskCompletionSource firstSendStarted,
        TaskCompletionSource releaseFirstSend)
        : HttpMessageHandler
    {
        private readonly object _requestsGate = new();
        private int _requestCount;
        private readonly List<RecordedRequest> _requests = [];

        public IReadOnlyList<RecordedRequest> Requests
        {
            get
            {
                lock (_requestsGate)
                {
                    return _requests.ToArray();
                }
            }
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var recordedRequest = await RecordedRequest.CreateAsync(request, cancellationToken);
            lock (_requestsGate)
            {
                _requests.Add(recordedRequest);
            }

            if (Interlocked.Increment(ref _requestCount) == 1)
            {
                firstSendStarted.TrySetResult();
                await releaseFirstSend.Task;
            }

            return new HttpResponseMessage(HttpStatusCode.Accepted);
        }
    }

    private sealed class DelayingHttpMessageHandler : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.Accepted);
        }
    }

    private sealed class CancelingHttpMessageHandler(CancellationTokenSource cancellationTokenSource) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            await cancellationTokenSource.CancelAsync();
            throw new OperationCanceledException(cancellationToken);
        }
    }

    private sealed class ThrowingAfterFirstConnectionProvider(ISqliteConnectionProvider inner) : ISqliteConnectionProvider
    {
        private int _callCount;

        public async ValueTask<SqliteConnectionHandle> GetConnectionAsync(CancellationToken cancellationToken = default)
        {
            if (Interlocked.Increment(ref _callCount) > 1)
            {
                throw new InvalidOperationException("Database update failed.");
            }

            return await inner.GetConnectionAsync(cancellationToken);
        }
    }

    private sealed class RecordingDeliveryObserver : IAshlarSecurityEventWebhookDeliveryObserver
    {
        public List<AshlarSecurityEventWebhookDeliveryTelemetry> Attempts { get; } = [];

        public void RecordDeliveryAttempt(AshlarSecurityEventWebhookDeliveryTelemetry telemetry)
        {
            Attempts.Add(telemetry);
        }
    }

    private sealed record RecordedRequest(IReadOnlyDictionary<string, string[]> Headers, string Body, string? ContentType)
    {
        public static async Task<RecordedRequest> CreateAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var headers = request.Headers.ToDictionary(header => header.Key, header => header.Value.ToArray(), StringComparer.Ordinal);
            var body = request.Content is null ? string.Empty : Encoding.UTF8.GetString(await request.Content.ReadAsByteArrayAsync(cancellationToken));
            return new RecordedRequest(headers, body, request.Content?.Headers.ContentType?.ToString());
        }
    }

    private sealed class RawWebhookRow
    {
        public required string EndpointName { get; init; }
        public required string Uri { get; init; }
        public Guid EventId { get; init; }
        public required string EventType { get; init; }
        public string? Outcome { get; init; }
        public DateTimeOffset OccurredAt { get; init; }
        public long TimeoutMs { get; init; }
        public required byte[] Body { get; init; }
        public required string Headers { get; init; }
        public DateTimeOffset CreatedAt { get; init; }
        public DateTimeOffset AvailableAt { get; init; }
        public DateTimeOffset? SentAt { get; init; }
        public DateTimeOffset? FailedAt { get; init; }
        public DateTimeOffset? DiscardedAt { get; init; }
        public int AttemptCount { get; init; }
        public string? LastError { get; init; }
        public string? LockedBy { get; init; }
        public DateTimeOffset? LastAttemptAt { get; init; }
    }

    private sealed class AcceptingReplayStore : IAshlarSecurityEventWebhookReplayStore
    {
        public bool TryAccept(AshlarSecurityEventWebhookReplayKey key, DateTimeOffset expiresAt)
        {
            return true;
        }
    }
}
