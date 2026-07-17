using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Dapper;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Postgres.Tests.Webhooks;

internal sealed class PostgresSecurityEventWebhookOutboxTests : PostgresTestBase
{
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
    private IServiceProvider _serviceProvider = null!;
    private FakeTimeProvider _timeProvider = null!;

    public override async Task OneTimeSetUp()
    {
        await base.OneTimeSetUp();

        _timeProvider = new FakeTimeProvider(_now);
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAshlarPostgres(GetConnectionString());
        services.AddAshlarPostgresSecurityEventWebhookOutbox();
        services.AddSingleton<TimeProvider>(_timeProvider);
        _serviceProvider = services.BuildServiceProvider();

        await _serviceProvider.InitializeAshlarPostgresSchemaAsync();
    }

    [OneTimeTearDown]
    public async Task OneTimeTearDownAsync()
    {
        if (_serviceProvider is IAsyncDisposable asyncDisposable)
        {
            await asyncDisposable.DisposeAsync();
        }
    }

    [TearDown]
    public async Task TearDownAsync()
    {
        foreach (var provider in _dispatcherProviders)
        {
            await provider.DisposeAsync();
        }

        _dispatcherProviders.Clear();
    }

    [SetUp]
    public async Task SetUpAsync()
    {
        await using var connection = await GetDataSource().OpenConnectionAsync();
        await connection.ExecuteAsync("TRUNCATE ashlar_security_event_webhook_outbox;");
    }

    [Test]
    public async Task SchemaInitializationCreatesWebhookOutboxTableAndIndexes()
    {
        await using var connection = await GetDataSource().OpenConnectionAsync();

        var tableExists = await connection.ExecuteScalarAsync<bool>("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'public' AND table_name = 'ashlar_security_event_webhook_outbox')
            """);
        var indexes = await connection.QueryAsync<string>("""
            SELECT indexname FROM pg_indexes
            WHERE schemaname = 'public' AND tablename = 'ashlar_security_event_webhook_outbox'
            """);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(tableExists, Is.True);
            Assert.That(indexes, Is.SupersetOf(ExpectedIndexes));
        }
    }

    [Test]
    public void AddAshlarPostgresSecurityEventWebhookOutboxValidatesOptionsOnStart()
    {
        var services = new ServiceCollection();

        services.AddAshlarPostgresSecurityEventWebhookOutbox(options => options.BatchSize = 0);

        using var provider = services.BuildServiceProvider();

        var exception = Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IStartupValidator>().Validate());
        Assert.That(exception?.OptionsType, Is.EqualTo(typeof(PostgresSecurityEventWebhookOutboxOptions)));
    }

    [Test]
    public async Task EnqueueStoresSafeBodyHeadersAndSignatureWithoutSecret()
    {
        var delivery = CreateDelivery("shared-secret");
        var enqueuer = _serviceProvider.GetRequiredAshlarProviderService<IAshlarSecurityEventWebhookEnqueuer>();

        await enqueuer.EnqueueAsync(delivery);

        await using var connection = await GetDataSource().OpenConnectionAsync();
        var row = await connection.QuerySingleAsync<RawWebhookRow>("""
            SELECT endpoint_name AS EndpointName, uri AS Uri, event_id AS EventId,
                   event_type AS EventType, outcome AS Outcome, occurred_at AS OccurredAt, timeout_ms AS TimeoutMs, body AS Body,
                   headers::text AS Headers, created_at AS CreatedAt, available_at AS AvailableAt
            FROM ashlar_security_event_webhook_outbox
            """);
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
            Assert.That(headers["X-Ashlar-Signature"], Is.EqualTo(CreateSignature("shared-secret", delivery.Body.Span)));
            Assert.That(row.Headers, Does.Not.Contain("shared-secret"));
            Assert.That(row.CreatedAt, Is.EqualTo(_timeProvider.GetUtcNow()));
            Assert.That(row.AvailableAt, Is.EqualTo(_timeProvider.GetUtcNow()));
        }
    }

    [Test]
    public async Task EnqueueUsesPreparedSignatureEvenIfEndpointSecretLaterChanges()
    {
        var firstSecret = "first-secret";
        var delivery = CreateDelivery(firstSecret);
        var enqueuer = _serviceProvider.GetRequiredAshlarProviderService<IAshlarSecurityEventWebhookEnqueuer>();

        await enqueuer.EnqueueAsync(delivery);

        await using var connection = await GetDataSource().OpenConnectionAsync();
        var headersJson = await connection.ExecuteScalarAsync<string>("SELECT headers::text FROM ashlar_security_event_webhook_outbox");
        Assert.That(headersJson, Is.Not.Null);
        var headers = JsonSerializer.Deserialize<Dictionary<string, string>>(headersJson)!;

        using (Assert.EnterMultipleScope())
        {
            Assert.That(headers["X-Ashlar-Signature"], Is.EqualTo(CreateSignature(firstSecret, delivery.Body.Span)));
            Assert.That(headers["X-Ashlar-Signature"], Is.Not.EqualTo(CreateSignature("changed-secret", delivery.Body.Span)));
        }
    }

    [Test]
    public async Task EnqueueRollsBackInsideAshlarTransaction()
    {
        var txProvider = _serviceProvider.GetRequiredService<AshlarDurableTransactionProvider>();
        var enqueuer = _serviceProvider.GetRequiredAshlarProviderService<IAshlarSecurityEventWebhookEnqueuer>();

        await using (await txProvider.BeginTransactionAsync())
        {
            await enqueuer.EnqueueAsync(CreateDelivery());
        }

        await using var connection = await GetDataSource().OpenConnectionAsync();
        var count = await connection.ExecuteScalarAsync<int>("SELECT count(*) FROM ashlar_security_event_webhook_outbox");
        Assert.That(count, Is.Zero);
    }

    [Test]
    public async Task DispatcherSendsPendingWebhookAndMarksItSent()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        await EnqueueAsync(CreateDelivery());
        var start = _timeProvider.GetUtcNow();

        var dispatcher = CreateDispatcher(transport);
        var count = await dispatcher.ProcessBatchAsync();

        await using var connection = await GetDataSource().OpenConnectionAsync();
        var row = await connection.QuerySingleAsync<RawWebhookRow>("SELECT sent_at AS SentAt, attempt_count AS AttemptCount, locked_by AS LockedBy FROM ashlar_security_event_webhook_outbox");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(count, Is.EqualTo(1));
            Assert.That(transport.Requests, Has.Count.EqualTo(1));
            Assert.That(transport.Requests[0].Body, Is.EqualTo(Encoding.UTF8.GetString(CreateDelivery().Body.Span)));
            Assert.That(transport.Requests[0].ContentType, Is.EqualTo("application/json"));
            Assert.That(transport.Requests[0].Headers["X-Ashlar-Event-Type"].Single(), Is.EqualTo("ashlar.sign_in.failed"));
            Assert.That(row.SentAt, Is.EqualTo(start));
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
            OnRequestAsync = async () =>
            {
                await using var connection = await GetDataSource().OpenConnectionAsync();
                await connection.ExecuteAsync("UPDATE ashlar_security_event_webhook_outbox SET locked_by = 'other-dispatcher';");
            }
        };

        var count = await CreateDispatcher(transport).ProcessBatchAsync();

        await using var verifyConnection = await GetDataSource().OpenConnectionAsync();
        var row = await verifyConnection.QuerySingleAsync<RawWebhookRow>("""
            SELECT sent_at AS SentAt, failed_at AS FailedAt, attempt_count AS AttemptCount,
                   last_error AS LastError, locked_by AS LockedBy
            FROM ashlar_security_event_webhook_outbox
            """);

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

        var count = await CreateDispatcher(transport, new PostgresSecurityEventWebhookOutboxOptions
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
    public async Task DispatcherDoesNotLetStaleSameInstanceCompletionMarkNewerClaimSent()
    {
        await EnqueueAsync(CreateDelivery());
        var firstSendStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var secondSendStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseFirstSend = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseSecondSend = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var transport = new BlockingWebhookHandler(firstSendStarted, secondSendStarted, releaseFirstSend, releaseSecondSend);
        var dispatcher = CreateDispatcher(transport, new PostgresSecurityEventWebhookOutboxOptions { LockDuration = TimeSpan.FromMinutes(1) });

        var first = dispatcher.ProcessBatchAsync();
        await firstSendStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await ExpireSingleWebhookLockAsync();

        var second = dispatcher.ProcessBatchAsync();
        await secondSendStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var newerClaimRow = await QuerySingleWebhookDispatchStateAsync();

        releaseFirstSend.SetResult();
        var firstCount = await first.WaitAsync(TimeSpan.FromSeconds(5));
        var staleCompletionRow = await QuerySingleWebhookDispatchStateAsync();

        releaseSecondSend.SetResult();
        var secondCount = await second.WaitAsync(TimeSpan.FromSeconds(5));
        var finalRow = await QuerySingleWebhookDispatchStateAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(firstCount, Is.EqualTo(1));
            Assert.That(secondCount, Is.EqualTo(1));
            Assert.That(transport.Requests, Has.Count.EqualTo(2));
            Assert.That(newerClaimRow.LockedBy, Is.Not.Null);
            Assert.That(staleCompletionRow.SentAt, Is.Null);
            Assert.That(staleCompletionRow.AttemptCount, Is.Zero);
            Assert.That(staleCompletionRow.LockedBy, Is.EqualTo(newerClaimRow.LockedBy));
            Assert.That(finalRow.SentAt, Is.EqualTo(_timeProvider.GetUtcNow()));
            Assert.That(finalRow.AttemptCount, Is.EqualTo(1));
            Assert.That(finalRow.LockedBy, Is.Null);
        }
    }

    [Test]
    public async Task DispatcherKeepsLeaseForInFlightSendTimeout()
    {
        await EnqueueAsync(CreateDelivery(timeout: TimeSpan.FromMinutes(5)));
        var firstSendStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseFirstSend = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var transport = new BlockingWebhookHandler(
            firstSendStarted,
            new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously),
            releaseFirstSend,
            new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously));
        var options = new PostgresSecurityEventWebhookOutboxOptions { LockDuration = TimeSpan.FromMinutes(1) };
        var first = CreateDispatcher(transport, options).ProcessBatchAsync();
        await firstSendStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));

        _timeProvider.Advance(TimeSpan.FromMinutes(5.5));
        var second = await CreateDispatcher(transport, options).ProcessBatchAsync().WaitAsync(TimeSpan.FromSeconds(5));
        releaseFirstSend.SetResult();
        await first.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.That(second, Is.Zero);
    }

    [Test]
    public async Task DispatcherDoesNotMarkSentWhenWebhookRowBecomesTerminalAfterSuccessfulSend()
    {
        await EnqueueAsync(CreateDelivery());
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted)
        {
            OnRequestAsync = async () =>
            {
                await using var connection = await GetDataSource().OpenConnectionAsync();
                await connection.ExecuteAsync("UPDATE ashlar_security_event_webhook_outbox SET failed_at = @now;", new { now = _timeProvider.GetUtcNow() });
            }
        };

        await CreateDispatcher(transport).ProcessBatchAsync();

        await using var verifyConnection = await GetDataSource().OpenConnectionAsync();
        var row = await verifyConnection.QuerySingleAsync<RawWebhookRow>("""
            SELECT sent_at AS SentAt, failed_at AS FailedAt, attempt_count AS AttemptCount,
                   last_error AS LastError
            FROM ashlar_security_event_webhook_outbox
            """);

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
    public async Task DispatcherDoesNotMarkFailedWhenWebhookRowBecomesTerminalAfterFailedSend()
    {
        await EnqueueAsync(CreateDelivery());
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.BadGateway)
        {
            OnRequestAsync = async () =>
            {
                await using var connection = await GetDataSource().OpenConnectionAsync();
                await connection.ExecuteAsync("UPDATE ashlar_security_event_webhook_outbox SET discarded_at = @now;", new { now = _timeProvider.GetUtcNow() });
            }
        };

        await CreateDispatcher(transport).ProcessBatchAsync();

        await using var verifyConnection = await GetDataSource().OpenConnectionAsync();
        var row = await verifyConnection.QuerySingleAsync<RawWebhookRow>("""
            SELECT discarded_at AS DiscardedAt, failed_at AS FailedAt, attempt_count AS AttemptCount,
                   last_error AS LastError
            FROM ashlar_security_event_webhook_outbox
            """);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(transport.Requests, Has.Count.EqualTo(1));
            Assert.That(row.DiscardedAt, Is.EqualTo(_timeProvider.GetUtcNow()));
            Assert.That(row.FailedAt, Is.Null);
            Assert.That(row.AttemptCount, Is.Zero);
            Assert.That(row.LastError, Is.Null);
        }
    }

    [Test]
    public async Task DispatcherRegeneratesSignatureAtSendTime()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        await EnqueueAsync(CreateDelivery("old-secret"));

        await CreateDispatcher(transport, webhookOptions: CreateWebhookOptions("current-secret")).ProcessBatchAsync();

        var request = transport.Requests.Single();
        var result = AshlarSecurityEventWebhookSignature.Verify(new AshlarSecurityEventWebhookVerificationRequest
        {
            Body = Encoding.UTF8.GetBytes(request.Body),
            Headers = request.Headers.ToDictionary(header => header.Key, header => header.Value.Single(), StringComparer.Ordinal),
            SharedSecret = "current-secret",
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
            Assert.That(request.Headers[AshlarSecurityEventWebhookSignature.SignatureHeaderName].Single(), Is.Not.EqualTo(CreateSignature("old-secret", Encoding.UTF8.GetBytes(request.Body))));
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
            new PostgresSecurityEventWebhookOutboxOptions { MaxAttempts = 1 },
            webhookOptions: webhookOptions).ProcessBatchAsync();

        await using var connection = await GetDataSource().OpenConnectionAsync();
        var row = await connection.QuerySingleAsync<RawWebhookRow>("""
            SELECT failed_at AS FailedAt, sent_at AS SentAt, attempt_count AS AttemptCount,
                   last_error AS LastError
            FROM ashlar_security_event_webhook_outbox
            """);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(transport.Requests, Is.Empty);
            Assert.That(row.FailedAt, Is.EqualTo(_timeProvider.GetUtcNow()));
            Assert.That(row.AttemptCount, Is.EqualTo(1));
            Assert.That(row.LastError, Is.EqualTo("kind=unknown;reason=unknown_failure"));
        }
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
    public async Task DispatcherRetriesFailedSendsAndMarksFinalFailure()
    {
        await EnqueueAsync(CreateDelivery());
        var start = _timeProvider.GetUtcNow();
        var dispatcher = CreateDispatcher(
            new RecordingHttpMessageHandler(HttpStatusCode.BadGateway),
            new PostgresSecurityEventWebhookOutboxOptions { MaxAttempts = 2, InitialRetryDelay = TimeSpan.FromSeconds(30) });

        await dispatcher.ProcessBatchAsync();
        _timeProvider.Advance(TimeSpan.FromSeconds(30));
        await dispatcher.ProcessBatchAsync();

        await using var connection = await GetDataSource().OpenConnectionAsync();
        var row = await connection.QuerySingleAsync<RawWebhookRow>("""
            SELECT failed_at AS FailedAt, sent_at AS SentAt, attempt_count AS AttemptCount,
                   last_error AS LastError, available_at AS AvailableAt
            FROM ashlar_security_event_webhook_outbox
            """);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(row.SentAt, Is.Null);
            Assert.That(row.FailedAt, Is.EqualTo(start.AddSeconds(30)));
            Assert.That(row.AttemptCount, Is.EqualTo(2));
            Assert.That(row.LastError, Is.EqualTo("kind=http_status;status=502;reason=non_success_status"));
            Assert.That(row.AvailableAt, Is.EqualTo(start.AddSeconds(30)));
        }
    }

    [Test]
    public async Task DispatcherUsesPersistedTimeoutForHttpSend()
    {
        await EnqueueAsync(CreateDelivery(timeout: TimeSpan.FromMilliseconds(1)));
        var dispatcher = CreateDispatcher(
            new DelayingHttpMessageHandler(),
            new PostgresSecurityEventWebhookOutboxOptions { InitialRetryDelay = TimeSpan.FromSeconds(5) });

        await dispatcher.ProcessBatchAsync();

        await using var connection = await GetDataSource().OpenConnectionAsync();
        var row = await connection.QuerySingleAsync<RawWebhookRow>("""
            SELECT sent_at AS SentAt, failed_at AS FailedAt, attempt_count AS AttemptCount,
                   last_error AS LastError
            FROM ashlar_security_event_webhook_outbox
            """);

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
        await using (var connection = await GetDataSource().OpenConnectionAsync())
        {
            await connection.ExecuteAsync("UPDATE ashlar_security_event_webhook_outbox SET uri = 'https://127.0.0.1/security-events';");
        }

        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var webhookOptions = CreateWebhookOptions();
        webhookOptions.Endpoints.Single().Uri = new Uri("https://127.0.0.1/security-events");

        await CreateDispatcher(
            transport,
            new PostgresSecurityEventWebhookOutboxOptions { MaxAttempts = 1 },
            webhookOptions: webhookOptions).ProcessBatchAsync();

        await using var verifyConnection = await GetDataSource().OpenConnectionAsync();
        var row = await verifyConnection.QuerySingleAsync<RawWebhookRow>("""
            SELECT sent_at AS SentAt, failed_at AS FailedAt, attempt_count AS AttemptCount,
                   last_error AS LastError
            FROM ashlar_security_event_webhook_outbox
            """);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(transport.Requests, Is.Empty);
            Assert.That(row.SentAt, Is.Null);
            Assert.That(row.FailedAt, Is.EqualTo(_timeProvider.GetUtcNow()));
            Assert.That(row.AttemptCount, Is.EqualTo(1));
            Assert.That(row.LastError, Is.EqualTo("kind=unsafe_destination;reason=unsafe_destination"));
            Assert.That(row.LastError, Does.Not.Contain("127.0.0.1"));
        }
    }

    [Test]
    public async Task SuccessfulSendWithMarkSentDatabaseFailureDoesNotMarkDeliveryFailed()
    {
        await EnqueueAsync(CreateDelivery());
        var services = new ServiceCollection();
        services.AddSingleton<IPostgresConnectionProvider>(new ThrowingAfterFirstConnectionProvider(_serviceProvider.GetRequiredService<IPostgresConnectionProvider>()));
        var dispatcherProvider = services.BuildServiceProvider();
        var dispatcher = new PostgresSecurityEventWebhookOutboxDispatcher(
            dispatcherProvider,
            _timeProvider,
            Options.Create(new PostgresSecurityEventWebhookOutboxOptions()),
            Options.Create(CreateWebhookOptions()),
            new TestHttpClientFactory(new RecordingHttpMessageHandler(HttpStatusCode.Accepted)),
            CreateDestinationValidator());

        Assert.ThrowsAsync<InvalidOperationException>(() => dispatcher.ProcessBatchAsync());

        await using var connection = await GetDataSource().OpenConnectionAsync();
        var row = await connection.QuerySingleAsync<RawWebhookRow>("""
            SELECT sent_at AS SentAt, failed_at AS FailedAt, attempt_count AS AttemptCount,
                   last_error AS LastError, locked_by AS LockedBy
            FROM ashlar_security_event_webhook_outbox
            """);

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
    public async Task ExpiredLocksAreClaimableAndActiveLocksAreSkipped()
    {
        await EnqueueAsync(CreateDelivery());
        await EnqueueAsync(CreateDelivery());
        await using (var connection = await GetDataSource().OpenConnectionAsync())
        {
            var now = _timeProvider.GetUtcNow();
            await connection.ExecuteAsync("""
                UPDATE ashlar_security_event_webhook_outbox
                SET locked_until = CASE WHEN id = (SELECT id FROM ashlar_security_event_webhook_outbox ORDER BY id LIMIT 1) THEN @expired ELSE @active END,
                    locked_by = 'other'
                """, new { expired = now, active = now.AddMinutes(5) });
        }

        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var count = await CreateDispatcher(transport).ProcessBatchAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(count, Is.EqualTo(1));
            Assert.That(transport.Requests, Has.Count.EqualTo(1));
        }
    }

    [Test]
    public async Task ConcurrentDispatchersDoNotDoubleSend()
    {
        await EnqueueAsync(CreateDelivery());
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted, delay: TimeSpan.FromMilliseconds(100));
        var dispatcher1 = CreateDispatcher(transport);
        var dispatcher2 = CreateDispatcher(transport);

        var counts = await Task.WhenAll(dispatcher1.ProcessBatchAsync(), dispatcher2.ProcessBatchAsync());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(counts.Sum(), Is.EqualTo(1));
            Assert.That(transport.Requests, Has.Count.EqualTo(1));
        }
    }

    [Test]
    public void OptionsValidateAndNullArguments()
    {
        var connectionProvider = _serviceProvider.GetRequiredService<IPostgresConnectionProvider>();
        var destinationValidator = CreateDestinationValidator();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(PostgresSecurityEventWebhookOutboxOptions.Validate(new PostgresSecurityEventWebhookOutboxOptions()), Is.True);
            Assert.That(PostgresSecurityEventWebhookOutboxOptions.Validate(new PostgresSecurityEventWebhookOutboxOptions { BatchSize = 0 }), Is.False);
            Assert.That(PostgresSecurityEventWebhookOutboxOptions.Validate(new PostgresSecurityEventWebhookOutboxOptions { LockDuration = TimeSpan.Zero }), Is.False);
            Assert.That(PostgresSecurityEventWebhookOutboxOptions.Validate(new PostgresSecurityEventWebhookOutboxOptions { MaxAttempts = 0 }), Is.False);
            Assert.That(PostgresSecurityEventWebhookOutboxOptions.Validate(new PostgresSecurityEventWebhookOutboxOptions { InitialRetryDelay = TimeSpan.Zero }), Is.False);
            Assert.That(PostgresSecurityEventWebhookOutboxOptions.Validate(new PostgresSecurityEventWebhookOutboxOptions { PollingInterval = TimeSpan.Zero }), Is.False);
            Assert.Throws<ArgumentNullException>(() => PostgresSecurityEventWebhookOutboxOptions.Validate(null!));
            Assert.Throws<ArgumentNullException>(() => new PostgresSecurityEventWebhookEnqueuer(null!, _timeProvider));
            Assert.Throws<ArgumentNullException>(() => new PostgresSecurityEventWebhookEnqueuer(connectionProvider, null!));
            Assert.Throws<ArgumentNullException>(() => new PostgresSecurityEventWebhookOutboxDispatcher(null!, _timeProvider, Options.Create(new PostgresSecurityEventWebhookOutboxOptions()), Options.Create(CreateWebhookOptions()), new TestHttpClientFactory(new RecordingHttpMessageHandler(HttpStatusCode.OK)), destinationValidator));
            Assert.Throws<ArgumentNullException>(() => new PostgresSecurityEventWebhookOutboxDispatcher(_serviceProvider, null!, Options.Create(new PostgresSecurityEventWebhookOutboxOptions()), Options.Create(CreateWebhookOptions()), new TestHttpClientFactory(new RecordingHttpMessageHandler(HttpStatusCode.OK)), destinationValidator));
            Assert.Throws<ArgumentNullException>(() => new PostgresSecurityEventWebhookOutboxDispatcher(_serviceProvider, _timeProvider, null!, Options.Create(CreateWebhookOptions()), new TestHttpClientFactory(new RecordingHttpMessageHandler(HttpStatusCode.OK)), destinationValidator));
            Assert.Throws<ArgumentNullException>(() => new PostgresSecurityEventWebhookOutboxDispatcher(_serviceProvider, _timeProvider, Options.Create(new PostgresSecurityEventWebhookOutboxOptions()), null!, new TestHttpClientFactory(new RecordingHttpMessageHandler(HttpStatusCode.OK)), destinationValidator));
            Assert.Throws<ArgumentNullException>(() => new PostgresSecurityEventWebhookOutboxDispatcher(_serviceProvider, _timeProvider, Options.Create(new PostgresSecurityEventWebhookOutboxOptions()), Options.Create(CreateWebhookOptions()), null!, destinationValidator));
            Assert.Throws<ArgumentNullException>(() => new PostgresSecurityEventWebhookOutboxDispatcher(_serviceProvider, _timeProvider, Options.Create(new PostgresSecurityEventWebhookOutboxOptions()), Options.Create(CreateWebhookOptions()), new TestHttpClientFactory(new RecordingHttpMessageHandler(HttpStatusCode.OK)), null!));
            Assert.Throws<ArgumentNullException>(() => new PostgresSecurityEventWebhookOutboxHostedService(null!, Options.Create(new PostgresSecurityEventWebhookOutboxOptions())));
            Assert.Throws<ArgumentNullException>(() => new PostgresSecurityEventWebhookOutboxHostedService(_serviceProvider, null!));
        }
    }

    [Test]
    public async Task DispatcherCancellationAndInvalidOptionsBehaveAsExpected()
    {
        var dispatcher = CreateDispatcher(new RecordingHttpMessageHandler(HttpStatusCode.Accepted), new PostgresSecurityEventWebhookOutboxOptions { BatchSize = 0 });
        Assert.ThrowsAsync<InvalidOperationException>(() => dispatcher.ProcessBatchAsync());

        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        var canceled = CreateDispatcher(new RecordingHttpMessageHandler(HttpStatusCode.Accepted));
        Assert.ThrowsAsync(Is.InstanceOf<OperationCanceledException>(), () => canceled.ProcessBatchAsync(cts.Token));
    }

    [Test]
    public async Task DispatcherRethrowsWhenCallerCancelsDuringSend()
    {
        await EnqueueAsync(CreateDelivery());
        using var cts = new CancellationTokenSource();
        var transport = new CancelingHttpMessageHandler(cts);
        var dispatcher = CreateDispatcher(transport);

        Assert.ThrowsAsync(Is.InstanceOf<OperationCanceledException>(), () => dispatcher.ProcessBatchAsync(cts.Token));
    }

    [Test]
    public void FailureUpdatePersistsSafeFailureSummary()
    {
        var failure = AshlarSecurityEventWebhookOutboxDispatch.CreateFailureUpdate(
            0,
            5,
            TimeSpan.FromSeconds(1),
            _timeProvider.GetUtcNow(),
            new InvalidOperationException("https://example.test/path?token=secret\r\n   at Unsafe.Stack()"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(failure.LastError, Is.EqualTo("kind=unknown;reason=unknown_failure"));
            Assert.That(failure.LastError, Has.Length.LessThanOrEqualTo(AshlarSecurityEventWebhookOutboxDispatch.MaxPersistedFailureDetailLength));
            Assert.That(failure.LastError, Does.Not.Contain("https://example.test"));
            Assert.That(failure.LastError, Does.Not.Contain("token=secret"));
            Assert.That(failure.LastError, Does.Not.Contain("Unsafe.Stack"));
            Assert.That(failure.LastError, Does.Not.Contain("\r"));
            Assert.That(failure.LastError, Does.Not.Contain("\n"));
        }
    }

    [Test]
    public void MapToHttpRequestFallsBackToContentHeaders()
    {
        using var request = AshlarSecurityEventWebhookOutboxDispatch.MapToHttpRequest(new AshlarSecurityEventWebhookOutboxEntry
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

        using (Assert.EnterMultipleScope())
        {
            Assert.That(request.Headers.TryGetValues("X-Ashlar-Event-Type", out var requestValues), Is.True);
            Assert.That(requestValues!.Single(), Is.EqualTo("ashlar.test"));
            Assert.That(request.Content!.Headers.ContentEncoding.Single(), Is.EqualTo("gzip"));
        }
    }

    [Test]
    public void MapToHttpRequestAddsRequestHeaders()
    {
        using var request = AshlarSecurityEventWebhookOutboxDispatch.MapToHttpRequest(new AshlarSecurityEventWebhookOutboxEntry
        {
            Id = Guid.NewGuid(),
            EndpointName = "audit",
            Uri = "https://example.test/security-events",
            EventId = Guid.NewGuid(),
            EventType = "ashlar.test",
            Outcome = SecurityEventOutcomes.Success,
            OccurredAt = _now,
            Body = Encoding.UTF8.GetBytes("{}"),
            Headers = """{"X-Ashlar-Event-Type":"ashlar.test"}""",
            TimeoutMs = 1000,
            AttemptCount = 0
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(request.Headers.TryGetValues("X-Ashlar-Event-Type", out var requestValues), Is.True);
            Assert.That(requestValues!.Single(), Is.EqualTo("ashlar.test"));
            Assert.That(request.Content!.Headers.Contains("X-Ashlar-Event-Type"), Is.False);
        }
    }

    [Test]
    public void MapToHttpRequestHandlesEmptyHeaders()
    {
        using var request = AshlarSecurityEventWebhookOutboxDispatch.MapToHttpRequest(new AshlarSecurityEventWebhookOutboxEntry
        {
            Id = Guid.NewGuid(),
            EndpointName = "audit",
            Uri = "https://example.test/security-events",
            EventId = Guid.NewGuid(),
            EventType = "ashlar.test",
            Outcome = SecurityEventOutcomes.Success,
            OccurredAt = _now,
            Body = Encoding.UTF8.GetBytes("{}"),
            Headers = "{}",
            TimeoutMs = 1000,
            AttemptCount = 0
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(request.Headers, Is.Empty);
            Assert.That(request.Content!.Headers.ContentType?.ToString(), Is.EqualTo("application/json"));
        }
    }

    [Test]
    public void MapToHttpRequestHandlesNullHeadersJson()
    {
        using var request = AshlarSecurityEventWebhookOutboxDispatch.MapToHttpRequest(new AshlarSecurityEventWebhookOutboxEntry
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
            Assert.That(request.Headers, Is.Empty);
            Assert.That(request.Content!.Headers.ContentType?.ToString(), Is.EqualTo("application/json"));
        }
    }

    [Test]
    public async Task DiRegistrationsResolve()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAshlarPostgres("Host=localhost;Database=test");
        services.AddAshlarPostgresSecurityEventWebhookHostedService(
            options => options.BatchSize = 7,
            webhooks => webhooks.DestinationPolicy = AshlarSecurityEventWebhookDestinationPolicy.AllowPrivateNetworks,
            client => client.DefaultRequestHeaders.Add("X-Test", "configured"));

        await using var provider = services.BuildServiceProvider();
        var hostedServices = provider.GetServices<IHostedService>().ToList();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.GetService<IAshlarSecurityEventWebhookEnqueuer>(), Is.Null);
            Assert.That(provider.GetService<IAshlarSecurityEventWebhookOutboxBrowser>(), Is.InstanceOf<PostgresSecurityEventWebhookOutboxBrowser>());
            Assert.That(provider.GetService<PostgresSecurityEventWebhookOutboxDispatcher>(), Is.Not.Null);
            Assert.That(hostedServices.Any(service => service is PostgresSecurityEventWebhookOutboxHostedService), Is.True);
            Assert.That(provider.GetRequiredService<IOptions<PostgresSecurityEventWebhookOutboxOptions>>().Value.BatchSize, Is.EqualTo(7));
            Assert.That(provider.GetRequiredService<IOptions<AshlarSecurityEventWebhookOptions>>().Value.DestinationPolicy, Is.EqualTo(AshlarSecurityEventWebhookDestinationPolicy.AllowPrivateNetworks));
            Assert.That(provider.GetRequiredService<IHttpClientFactory>().CreateClient(PostgresSecurityEventWebhookOutboxDispatcher.HttpClientName).DefaultRequestHeaders.GetValues("X-Test").Single(), Is.EqualTo("configured"));
        }
    }

    [Test]
    public async Task DispatcherRegistrationAllowsNullHttpClientConfigure()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAshlarPostgres("Host=localhost;Database=test");
        services.AddAshlarPostgresSecurityEventWebhookDispatcher();

        await using var provider = services.BuildServiceProvider();

        Assert.That(provider.GetService<PostgresSecurityEventWebhookOutboxDispatcher>(), Is.Not.Null);
    }

    [Test]
    public async Task DurableWebhookHandlerResolvesWithScopedPostgresEnqueuerUnderScopeValidation()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAshlarPostgres(GetConnectionString());
        services.AddAshlarPostgresSecurityEventWebhookOutbox();
        services.AddAshlarSecurityEventWebhookOutbox();

        await using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        await using var scope = provider.CreateAsyncScope();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scope.ServiceProvider.GetRequiredService<ISecurityEventSink>(), Is.TypeOf<SecurityEventFanOutSink>());
            Assert.That(scope.ServiceProvider.GetServices<IDurableSecurityEventFanOutHandler>().Single(), Is.TypeOf<AshlarSecurityEventWebhookOutboxHandler>());
            Assert.That(scope.ServiceProvider.GetServices<ISecurityEventHandler>(), Is.Empty);
            Assert.That(scope.ServiceProvider.GetRequiredAshlarProviderService<IAshlarSecurityEventWebhookEnqueuer>(), Is.TypeOf<PostgresSecurityEventWebhookEnqueuer>());
        }
    }

    [Test]
    public async Task HostedServiceStartValidationAndLoopAreCovered()
    {
        var invalid = new PostgresSecurityEventWebhookOutboxHostedService(
            _serviceProvider,
            Options.Create(new PostgresSecurityEventWebhookOutboxOptions { BatchSize = 0 }));
        Assert.ThrowsAsync<InvalidOperationException>(() => invalid.StartAsync(CancellationToken.None));

        await using var provider = CreateHostedServiceProvider(new RecordingHttpMessageHandler(HttpStatusCode.Accepted));
        var hosted = new PostgresSecurityEventWebhookOutboxHostedService(
            provider,
            Options.Create(new PostgresSecurityEventWebhookOutboxOptions { PollingInterval = TimeSpan.FromMilliseconds(1) }));

        using var cts = new CancellationTokenSource();
        await hosted.StartAsync(cts.Token);
        await Task.Delay(TimeSpan.FromMilliseconds(25), TestContext.CurrentContext.CancellationToken);
        await cts.CancelAsync();
        await hosted.ExecuteTask!;

        Assert.That(hosted.ExecuteTask.IsCompleted, Is.True);
    }

    private async Task EnqueueAsync(AshlarSecurityEventWebhookDelivery delivery)
    {
        await _serviceProvider.GetRequiredAshlarProviderService<IAshlarSecurityEventWebhookEnqueuer>().EnqueueAsync(delivery);
    }

    private async Task ExpireSingleWebhookLockAsync()
    {
        await using var connection = await GetDataSource().OpenConnectionAsync();
        await connection.ExecuteAsync(
            "UPDATE ashlar_security_event_webhook_outbox SET locked_until = @LockedUntil",
            new { LockedUntil = _timeProvider.GetUtcNow().AddMinutes(-1) });
    }

    private async Task<RawWebhookRow> QuerySingleWebhookDispatchStateAsync()
    {
        await using var connection = await GetDataSource().OpenConnectionAsync();
        return await connection.QuerySingleAsync<RawWebhookRow>("""
            SELECT sent_at AS SentAt, attempt_count AS AttemptCount, locked_by AS LockedBy
            FROM ashlar_security_event_webhook_outbox
            """);
    }

    private PostgresSecurityEventWebhookOutboxDispatcher CreateDispatcher(
        HttpMessageHandler transport,
        PostgresSecurityEventWebhookOutboxOptions? options = null,
        IAshlarSecurityEventWebhookDeliveryObserver? observer = null,
        AshlarSecurityEventWebhookOptions? webhookOptions = null)
    {
        return new PostgresSecurityEventWebhookOutboxDispatcher(
            CreateDispatcherProvider(observer),
            _timeProvider,
            Options.Create(options ?? new PostgresSecurityEventWebhookOutboxOptions()),
            Options.Create(webhookOptions ?? CreateWebhookOptions()),
            new TestHttpClientFactory(transport),
            CreateDestinationValidator());
    }

    private ServiceProvider CreateDispatcherProvider(IAshlarSecurityEventWebhookDeliveryObserver? observer = null)
    {
        var services = new ServiceCollection();
        services.AddSingleton(_serviceProvider.GetRequiredService<IPostgresConnectionProvider>());
        if (observer != null)
        {
            services.AddSingleton(observer);
        }

        var provider = services.BuildServiceProvider();
        _dispatcherProviders.Add(provider);
        return provider;
    }

    private ServiceProvider CreateHostedServiceProvider(HttpMessageHandler transport)
    {
        var services = new ServiceCollection();
        services.AddSingleton(_serviceProvider.GetRequiredService<IPostgresConnectionProvider>());
        services.AddSingleton<TimeProvider>(_timeProvider);
        services.AddSingleton<IHttpClientFactory>(new TestHttpClientFactory(transport));
        services.AddSingleton(Options.Create(new PostgresSecurityEventWebhookOutboxOptions()));
        services.AddSingleton(Options.Create(CreateWebhookOptions()));
        services.AddSingleton(CreateDestinationValidator());
        services.AddScoped<PostgresSecurityEventWebhookOutboxDispatcher>();
        return services.BuildServiceProvider();
    }

    [Test]
    public async Task DispatcherNamedHttpClientPreservesHardenedHandlerWithSafeConfiguration()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAshlarPostgres("Host=localhost;Database=test");
        services.AddAshlarPostgresSecurityEventWebhookDispatcher(configureHttpClient: client =>
        {
            client.Timeout = TimeSpan.FromSeconds(12);
            client.DefaultRequestHeaders.Add("X-Test", "configured");
        });
        await using var provider = services.BuildServiceProvider();
        using var handler = provider.GetRequiredService<IHttpMessageHandlerFactory>()
            .CreateHandler(PostgresSecurityEventWebhookOutboxDispatcher.HttpClientName);
        var httpClient = provider.GetRequiredService<IHttpClientFactory>().CreateClient(PostgresSecurityEventWebhookOutboxDispatcher.HttpClientName);

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

    private static AshlarSecurityEventWebhookDelivery CreateDelivery(string? sharedSecret = "shared-secret", TimeSpan? timeout = null)
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

    private static AshlarSecurityEventWebhookOptions CreateWebhookOptions(string sharedSecret = "shared-secret")
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

    private sealed class TestHttpClientFactory(HttpMessageHandler transport) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name)
        {
            Assert.That(name, Is.EqualTo(PostgresSecurityEventWebhookOutboxDispatcher.HttpClientName));
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

    private sealed class RecordingHttpMessageHandler(HttpStatusCode statusCode, TimeSpan? delay = null) : HttpMessageHandler
    {
        public List<RecordedRequest> Requests { get; } = [];
        public Func<Task>? OnRequestAsync { get; set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (delay.HasValue)
            {
                await Task.Delay(delay.Value, cancellationToken);
            }

            Requests.Add(await RecordedRequest.CreateAsync(request, cancellationToken));
            if (OnRequestAsync != null)
            {
                await OnRequestAsync();
            }

            return new HttpResponseMessage(statusCode);
        }
    }

    private sealed class BlockingWebhookHandler(
        TaskCompletionSource firstSendStarted,
        TaskCompletionSource secondSendStarted,
        TaskCompletionSource releaseFirstSend,
        TaskCompletionSource releaseSecondSend)
        : HttpMessageHandler
    {
        private readonly object _requestsGate = new();
        private readonly List<RecordedRequest> _requests = [];
        private int _requestCount;

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
                await releaseFirstSend.Task.WaitAsync(cancellationToken);
                return new HttpResponseMessage(HttpStatusCode.Accepted);
            }

            secondSendStarted.TrySetResult();
            await releaseSecondSend.Task.WaitAsync(cancellationToken);
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

    private sealed class ThrowingAfterFirstConnectionProvider(IPostgresConnectionProvider inner) : IPostgresConnectionProvider
    {
        private int _callCount;

        public async ValueTask<PostgresConnectionHandle> GetConnectionAsync(CancellationToken cancellationToken = default)
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
        public required string EndpointName { get; set; }
        public required string Uri { get; set; }
        public Guid EventId { get; set; }
        public required string EventType { get; set; }
        public string? Outcome { get; set; }
        public DateTimeOffset OccurredAt { get; set; }
        public long TimeoutMs { get; set; }
        public required byte[] Body { get; set; }
        public required string Headers { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
        public DateTimeOffset AvailableAt { get; set; }
        public DateTimeOffset? SentAt { get; set; }
        public DateTimeOffset? FailedAt { get; set; }
        public DateTimeOffset? DiscardedAt { get; set; }
        public int AttemptCount { get; set; }
        public string? LastError { get; set; }
        public string? LockedBy { get; set; }
    }

    private sealed class AcceptingReplayStore : IAshlarSecurityEventWebhookReplayStore
    {
        public bool TryAccept(AshlarSecurityEventWebhookReplayKey key, DateTimeOffset expiresAt)
        {
            return true;
        }
    }
}
