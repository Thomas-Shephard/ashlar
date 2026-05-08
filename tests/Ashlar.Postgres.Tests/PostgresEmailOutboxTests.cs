using System.Diagnostics.CodeAnalysis;
using Ashlar.Identity.Abstractions;
using Ashlar.Messaging;
using Ashlar.Operational;
using Dapper;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Postgres.Tests;

public sealed class PostgresEmailOutboxTests : PostgresTestBase
{
    private IServiceProvider _serviceProvider;
    private FakeTimeProvider _timeProvider;
    private readonly DateTimeOffset _now = new(2026, 5, 8, 12, 0, 0, TimeSpan.Zero);

    public override async Task OneTimeSetUp()
    {
        await base.OneTimeSetUp();

        _timeProvider = new FakeTimeProvider(_now);
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAshlarPostgres(GetConnectionString());
        services.AddAshlarPostgresEmailOutbox();
        services.AddAshlarPostgresCleanup();
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

    [SetUp]
    public async Task SetUpAsync()
    {
        await using var connection = await GetDataSource().OpenConnectionAsync();
        await connection.ExecuteAsync("TRUNCATE ashlar_email_outbox;");
        _timeProvider.SetUtcNow(_now);
    }

    [Test]
    public void OptionsValidateReturnsTrueForValidOptions()
    {
        var options = new PostgresEmailOutboxOptions();
        Assert.That(PostgresEmailOutboxOptions.Validate(options), Is.True);
    }

    [Test]
    public void OptionsValidateReturnsFalseForInvalidOptions()
    {
        var options = new PostgresEmailOutboxOptions { LockDuration = TimeSpan.Zero };
        Assert.That(PostgresEmailOutboxOptions.Validate(options), Is.False);

        options = new PostgresEmailOutboxOptions { MaxAttempts = 0 };
        Assert.That(PostgresEmailOutboxOptions.Validate(options), Is.False);

        options = new PostgresEmailOutboxOptions { InitialRetryDelay = TimeSpan.Zero };
        Assert.That(PostgresEmailOutboxOptions.Validate(options), Is.False);

        options = new PostgresEmailOutboxOptions { BatchSize = 0 };
        Assert.That(PostgresEmailOutboxOptions.Validate(options), Is.False);

        options = new PostgresEmailOutboxOptions { PollingInterval = TimeSpan.Zero };
        Assert.That(PostgresEmailOutboxOptions.Validate(options), Is.False);
    }

    [Test]
    public void OptionsValidateThrowsForNullOptions()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => PostgresEmailOutboxOptions.Validate(null!));
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void SenderConstructorThrowsForNullArguments()
    {
        var provider = _serviceProvider.GetRequiredService<IPostgresConnectionProvider>();
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new PostgresEmailOutboxSender(null!, _timeProvider));
            Assert.Throws<ArgumentNullException>(() => _ = new PostgresEmailOutboxSender(provider, null!));
        }
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void DispatcherConstructorThrowsForNullArguments()
    {
        var services = new ServiceCollection().BuildServiceProvider();
        var options = Options.Create(new PostgresEmailOutboxOptions());

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new PostgresEmailOutboxDispatcher<TestTransport>(null!, _timeProvider, options));
            Assert.Throws<ArgumentNullException>(() => _ = new PostgresEmailOutboxDispatcher<TestTransport>(services, null!, options));
            Assert.Throws<ArgumentNullException>(() => _ = new PostgresEmailOutboxDispatcher<TestTransport>(services, _timeProvider, null!));
        }
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void HostedServiceConstructorThrowsForNullArguments()
    {
        var services = new ServiceCollection().BuildServiceProvider();
        var options = Options.Create(new PostgresEmailOutboxOptions());

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new PostgresEmailOutboxHostedService(null!, options));
            Assert.Throws<ArgumentNullException>(() => _ = new PostgresEmailOutboxHostedService(services, null!));
        }
    }

    [Test]
    public async Task SenderSendAsyncInsertsMessageWithTimeProvider()
    {
        var sender = new PostgresEmailOutboxSender(
            _serviceProvider.GetRequiredService<IPostgresConnectionProvider>(),
            _timeProvider);

        var message = new EmailMessage("to@example.com", "Subject", "Body");

        await sender.SendAsync(message);

        await using var connection = await GetDataSource().OpenConnectionAsync();
        var row = await connection.QuerySingleAsync<RawOutboxRow>("""
            SELECT created_at AS CreatedAt, available_at AS AvailableAt
            FROM ashlar_email_outbox
            """);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(row.CreatedAt, Is.EqualTo(_now));
            Assert.That(row.AvailableAt, Is.EqualTo(_now));
        }
    }

    [Test]
    public async Task SenderSendAsyncSerializesHeadersAndMetadata()
    {
        var sender = new PostgresEmailOutboxSender(
            _serviceProvider.GetRequiredService<IPostgresConnectionProvider>(),
            _timeProvider);

        var message = new EmailMessage(
            "to@example.com",
            "Subject",
            "Body",
            options: new EmailMessageOptions
            {
                Headers = new Dictionary<string, string> { ["X-Test"] = "Header" },
                Metadata = new Dictionary<string, string> { ["Test"] = "Metadata" }
            });

        await sender.SendAsync(message);

        await using var connection = await GetDataSource().OpenConnectionAsync();
        var row = await connection.QuerySingleAsync<RawOutboxRow>("""
            SELECT headers AS Headers, metadata AS Metadata
            FROM ashlar_email_outbox
            """);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(row.Headers, Does.Contain("\"X-Test\": \"Header\""));
            Assert.That(row.Metadata, Does.Contain("\"Test\": \"Metadata\""));
        }
    }

    [Test]
    public async Task SenderSendAsyncIsTransactional()
    {
        var provider = _serviceProvider.GetRequiredService<IPostgresConnectionProvider>();
        var txProvider = _serviceProvider.GetRequiredService<IAshlarTransactionProvider>();
        var sender = new PostgresEmailOutboxSender(provider, _timeProvider);

        await using (var tx = await txProvider.BeginTransactionAsync())
        {
            await sender.SendAsync(new EmailMessage("to@example.com", "Subject", "Body"));

            // Should not be visible outside transaction
            await using var connectionOutside = await GetDataSource().OpenConnectionAsync();
            var countOutside = await connectionOutside.ExecuteScalarAsync<int>("SELECT count(*) FROM ashlar_email_outbox");
            Assert.That(countOutside, Is.Zero);

            await tx.CommitAsync();
        }

        await using var connectionAfter = await GetDataSource().OpenConnectionAsync();
        var countAfter = await connectionAfter.ExecuteScalarAsync<int>("SELECT count(*) FROM ashlar_email_outbox");
        Assert.That(countAfter, Is.EqualTo(1));
    }

    [Test]
    public void DispatcherProcessBatchAsyncThrowsForInvalidOptions()
    {
        var services = new ServiceCollection().BuildServiceProvider();
        var dispatcher = new PostgresEmailOutboxDispatcher<TestTransport>(
            services,
            _timeProvider,
            Options.Create(new PostgresEmailOutboxOptions { BatchSize = 0 }));

        Assert.ThrowsAsync<InvalidOperationException>(() => dispatcher.ProcessBatchAsync(CancellationToken.None));
    }

    [Test]
    public async Task DispatcherProcessBatchAsyncClaimsAndSendsMessages()
    {
        var transport = new TestTransport();
        var services = new ServiceCollection();
        services.AddSingleton(transport);
        services.AddSingleton(_serviceProvider.GetRequiredService<IPostgresConnectionProvider>());
        var dispatcherProvider = services.BuildServiceProvider();

        await SeedMessageAsync("to@example.com");

        var dispatcher = new PostgresEmailOutboxDispatcher<TestTransport>(
            dispatcherProvider,
            _timeProvider,
            Options.Create(new PostgresEmailOutboxOptions()));

        var count = await dispatcher.ProcessBatchAsync(CancellationToken.None);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(count, Is.EqualTo(1));
            Assert.That(transport.DeliveredCount, Is.EqualTo(1));
        }

        await using var connection = await GetDataSource().OpenConnectionAsync();
        var row = await connection.QuerySingleAsync<RawOutboxRow>("SELECT sent_at AS SentAt, attempt_count AS AttemptCount FROM ashlar_email_outbox");
        using (Assert.EnterMultipleScope())
        {
            Assert.That(row.SentAt, Is.EqualTo(_now));
            Assert.That(row.AttemptCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task DispatcherProcessBatchAsyncHandlesFailureAndRetry()
    {
        var transport = new TestTransport { OnDeliver = (_, _) => throw new InvalidOperationException("Delivery failed") };
        var services = new ServiceCollection();
        services.AddSingleton(transport);
        services.AddSingleton(_serviceProvider.GetRequiredService<IPostgresConnectionProvider>());
        var dispatcherProvider = services.BuildServiceProvider();

        await SeedMessageAsync("fail@example.com");

        var options = new PostgresEmailOutboxOptions { InitialRetryDelay = TimeSpan.FromSeconds(30) };
        var dispatcher = new PostgresEmailOutboxDispatcher<TestTransport>(
            dispatcherProvider,
            _timeProvider,
            Options.Create(options));

        await dispatcher.ProcessBatchAsync(CancellationToken.None);

        await using var connection = await GetDataSource().OpenConnectionAsync();
        var row = await connection.QuerySingleAsync<RawOutboxRow>("""
            SELECT sent_at AS SentAt, failed_at AS FailedAt, attempt_count AS AttemptCount,
                   last_error AS LastError, last_attempt_at AS LastAttemptAt,
                   available_at AS AvailableAt
            FROM ashlar_email_outbox
            """);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(row.SentAt, Is.Null);
            Assert.That(row.FailedAt, Is.Null);
            Assert.That(row.AttemptCount, Is.EqualTo(1));
            Assert.That(row.LastError, Does.Contain("Delivery failed"));
            Assert.That(row.LastAttemptAt, Is.EqualTo(_now));
            Assert.That(row.AvailableAt, Is.EqualTo(_now.AddSeconds(30)));
        }
    }

    [Test]
    public async Task DispatcherProcessBatchAsyncRethrowsWhenCancellationRequested()
    {
        using var cts = new CancellationTokenSource();
        var transport = new TestTransport
        {
            OnDeliver = (_, _) =>
            {
                cts.Cancel();
                throw new OperationCanceledException();
            }
        };

        var services = new ServiceCollection();
        services.AddSingleton(transport);
        services.AddSingleton(_serviceProvider.GetRequiredService<IPostgresConnectionProvider>());
        var dispatcherProvider = services.BuildServiceProvider();

        await SeedMessageAsync("cancel@example.com");

        var dispatcher = new PostgresEmailOutboxDispatcher<TestTransport>(
            dispatcherProvider,
            _timeProvider,
            Options.Create(new PostgresEmailOutboxOptions()));

        Assert.ThrowsAsync<OperationCanceledException>(() => dispatcher.ProcessBatchAsync(cts.Token));
    }

    [Test]
    public async Task DispatcherProcessBatchAsyncTreatsInternalCancellationAsFailure()
    {
        var transport = new TestTransport { OnDeliver = (_, _) => throw new OperationCanceledException() };
        var services = new ServiceCollection();
        services.AddSingleton(transport);
        services.AddSingleton(_serviceProvider.GetRequiredService<IPostgresConnectionProvider>());
        var dispatcherProvider = services.BuildServiceProvider();

        await SeedMessageAsync("internal-cancel@example.com");

        var dispatcher = new PostgresEmailOutboxDispatcher<TestTransport>(
            dispatcherProvider,
            _timeProvider,
            Options.Create(new PostgresEmailOutboxOptions()));

        await dispatcher.ProcessBatchAsync(CancellationToken.None);

        await using var connection = await GetDataSource().OpenConnectionAsync();
        var row = await connection.QuerySingleAsync<RawOutboxRow>("""
            SELECT sent_at AS SentAt, failed_at AS FailedAt, attempt_count AS AttemptCount,
                   last_error AS LastError
            FROM ashlar_email_outbox
            WHERE to_address = 'internal-cancel@example.com'
            """);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(row.SentAt, Is.Null);
            Assert.That(row.FailedAt, Is.Null);
            Assert.That(row.AttemptCount, Is.EqualTo(1));
            Assert.That(row.LastError, Does.Contain("OperationCanceledException"));
        }
    }

    [Test]
    public async Task DispatcherProcessBatchAsyncHandlesMaxAttempts()
    {
        var transport = new TestTransport { OnDeliver = (_, _) => throw new InvalidOperationException("Persistent failure") };
        var services = new ServiceCollection();
        services.AddSingleton(transport);
        services.AddSingleton(_serviceProvider.GetRequiredService<IPostgresConnectionProvider>());
        var dispatcherProvider = services.BuildServiceProvider();

        await SeedMessageAsync("final-fail@example.com");

        var options = new PostgresEmailOutboxOptions { MaxAttempts = 1 };
        var dispatcher = new PostgresEmailOutboxDispatcher<TestTransport>(
            dispatcherProvider,
            _timeProvider,
            Options.Create(options));

        await dispatcher.ProcessBatchAsync(CancellationToken.None);

        await using var connection = await GetDataSource().OpenConnectionAsync();
        var row = await connection.QuerySingleAsync<RawOutboxRow>("""
            SELECT sent_at AS SentAt, failed_at AS FailedAt, attempt_count AS AttemptCount,
                   last_error AS LastError
            FROM ashlar_email_outbox
            """);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(row.SentAt, Is.Null);
            Assert.That(row.FailedAt, Is.EqualTo(_now));
            Assert.That(row.AttemptCount, Is.EqualTo(1));
            Assert.That(row.LastError, Does.Contain("Persistent failure"));
        }
    }

    [Test]
    public async Task DispatcherProcessBatchAsyncRespectsBatchSize()
    {
        var transport = new TestTransport();
        var services = new ServiceCollection();
        services.AddSingleton(transport);
        services.AddSingleton(_serviceProvider.GetRequiredService<IPostgresConnectionProvider>());
        var dispatcherProvider = services.BuildServiceProvider();

        for (int i = 0; i < 5; i++)
        {
            await SeedMessageAsync($"to{i}@example.com");
        }

        var options = new PostgresEmailOutboxOptions { BatchSize = 3 };
        var dispatcher = new PostgresEmailOutboxDispatcher<TestTransport>(
            dispatcherProvider,
            _timeProvider,
            Options.Create(options));

        var count = await dispatcher.ProcessBatchAsync(CancellationToken.None);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(count, Is.EqualTo(3));
            Assert.That(transport.DeliveredCount, Is.EqualTo(3));
        }
    }

    [Test]
    public async Task CleanupIntegrationRemovesSentAndFailedEmails()
    {
        await using var connection = await GetDataSource().OpenConnectionAsync();
        var old = _now.AddDays(-60);

        await connection.ExecuteAsync("""
            INSERT INTO ashlar_email_outbox (id, to_address, subject, text_body, created_at, available_at, sent_at) VALUES
            (@id1, 'sent@example.com', 'Sub', 'Body', @old, @old, @old),
            (@id2, 'recent-sent@example.com', 'Sub', 'Body', @now, @now, @now);

            INSERT INTO ashlar_email_outbox (id, to_address, subject, text_body, created_at, available_at, failed_at) VALUES
            (@id3, 'failed@example.com', 'Sub', 'Body', @old, @old, @old),
            (@id4, 'recent-failed@example.com', 'Sub', 'Body', @now, @now, @now);
            """, new { id1 = Guid.NewGuid(), id2 = Guid.NewGuid(), id3 = Guid.NewGuid(), id4 = Guid.NewGuid(), now = _now, old });

        var cleanupOptions = new AshlarCleanupOptions
        {
            RemoveSentEmailsAfter = TimeSpan.FromDays(30),
            RemoveFailedEmailsAfter = TimeSpan.FromDays(30)
        };

        var cleanupService = new PostgresAshlarCleanupService(
            GetDataSource(),
            _timeProvider,
            Options.Create(cleanupOptions));

        var result = await cleanupService.CleanupAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.SentEmails, Is.EqualTo(1));
            Assert.That(result.FailedEmails, Is.EqualTo(1));
        }

        var finalCount = await connection.ExecuteScalarAsync<int>("SELECT count(*) FROM ashlar_email_outbox");
        Assert.That(finalCount, Is.EqualTo(2));
    }

    [Test]
    public void MapToEmailMessageHandlesNullHeadersAndMetadata()
    {
        var entry = new PostgresEmailOutboxDispatcher<TestTransport>.OutboxEntry
        {
            Id = Guid.NewGuid(),
            ToAddress = "to@example.com",
            Subject = "Sub",
            TextBody = "Body",
            Headers = null,
            Metadata = null
        };

        var message = PostgresEmailOutboxDispatcher<TestTransport>.MapToEmailMessage(entry);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(message.To, Is.EqualTo("to@example.com"));
            Assert.That(message.Headers, Is.Null);
            Assert.That(message.Metadata, Is.Null);
        }
    }

    [Test]
    public void MapToEmailMessageHandlesValidHeadersAndMetadata()
    {
        var entry = new PostgresEmailOutboxDispatcher<TestTransport>.OutboxEntry
        {
            Id = Guid.NewGuid(),
            ToAddress = "to@example.com",
            Subject = "Sub",
            TextBody = "Body",
            Headers = "{\"X-Test\": \"Header\"}",
            Metadata = "{\"Test\": \"Metadata\"}"
        };

        var message = PostgresEmailOutboxDispatcher<TestTransport>.MapToEmailMessage(entry);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(message.Headers, Is.Not.Null);
            Assert.That(message.Headers, Does.ContainKey("X-Test").WithValue("Header"));
            Assert.That(message.Metadata, Is.Not.Null);
            Assert.That(message.Metadata, Does.ContainKey("Test").WithValue("Metadata"));
        }
    }

    [Test]
    public async Task DispatcherProcessBatchAsyncReturnsZeroWhenNoMessages()
    {
        var transport = new TestTransport();
        var services = new ServiceCollection();
        services.AddSingleton(transport);
        services.AddSingleton(_serviceProvider.GetRequiredService<IPostgresConnectionProvider>());
        var dispatcherProvider = services.BuildServiceProvider();

        var dispatcher = new PostgresEmailOutboxDispatcher<TestTransport>(
            dispatcherProvider,
            _timeProvider,
            Options.Create(new PostgresEmailOutboxOptions()));

        var count = await dispatcher.ProcessBatchAsync(CancellationToken.None);

        Assert.That(count, Is.Zero);
    }

    [Test]
    public async Task HostedServiceStopsOnCancellation()
    {
        var transport = new TestTransport();
        var services = new ServiceCollection();
        services.AddSingleton(transport);
        services.AddSingleton(_serviceProvider.GetRequiredService<IPostgresConnectionProvider>());
        services.AddSingleton<TimeProvider>(_timeProvider);
        services.AddAshlarPostgresEmailOutbox<TestTransport>();
        var dispatcherProvider = services.BuildServiceProvider();

        var hostedService = new PostgresEmailOutboxHostedService(
            dispatcherProvider,
            Options.Create(new PostgresEmailOutboxOptions { PollingInterval = TimeSpan.FromMilliseconds(1) }));

        var cts = new CancellationTokenSource();
        await hostedService.StartAsync(cts.Token);
        await Task.Delay(TimeSpan.FromMilliseconds(100), TestContext.CurrentContext.CancellationToken);
        await cts.CancelAsync();
        await hostedService.ExecuteTask!;

        Assert.That(hostedService.ExecuteTask.IsCompleted, Is.True);
    }

    [Test]
    public void HostedServiceThrowsForInvalidOptions()
    {
        var services = new ServiceCollection();
        services.AddSingleton(new TestTransport());
        services.AddSingleton(_serviceProvider.GetRequiredService<IPostgresConnectionProvider>());
        services.AddSingleton<TimeProvider>(_timeProvider);
        services.AddAshlarPostgresEmailOutbox<TestTransport>();
        var dispatcherProvider = services.BuildServiceProvider();

        var hostedService = new PostgresEmailOutboxHostedService(
            dispatcherProvider,
            Options.Create(new PostgresEmailOutboxOptions { BatchSize = 0 }));

        Assert.ThrowsAsync<InvalidOperationException>(() => hostedService.StartAsync(CancellationToken.None));
    }

    [Test]
    public async Task HostedServiceStopsWhenAlreadyCanceled()
    {
        var transport = new TestTransport();
        var services = new ServiceCollection();
        services.AddSingleton(transport);
        services.AddSingleton(_serviceProvider.GetRequiredService<IPostgresConnectionProvider>());
        services.AddSingleton<TimeProvider>(_timeProvider);
        services.AddAshlarPostgresEmailOutbox<TestTransport>();
        var dispatcherProvider = services.BuildServiceProvider();

        var hostedService = new PostgresEmailOutboxHostedService(
            dispatcherProvider,
            Options.Create(new PostgresEmailOutboxOptions()));

        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await hostedService.StartAsync(cts.Token);
        await hostedService.StopAsync(CancellationToken.None);

        Assert.That(transport.DeliveredCount, Is.Zero);
    }

    [Test]
    public async Task HostedServiceContinuesImmediatelyWhenBatchIsFull()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var deliveredCount = 0;
        var transport = new TestTransport
        {
            OnDeliver = (_, _) =>
            {
                if (Interlocked.Increment(ref deliveredCount) >= 2)
                {
                    cts.Cancel();
                }

                return Task.CompletedTask;
            }
        };

        var services = new ServiceCollection();
        services.AddSingleton(transport);
        services.AddSingleton(_serviceProvider.GetRequiredService<IPostgresConnectionProvider>());
        services.AddSingleton<TimeProvider>(_timeProvider);
        services.AddAshlarPostgresEmailOutbox<TestTransport>();
        var dispatcherProvider = services.BuildServiceProvider();

        await SeedMessageAsync("batch-one@example.com");
        await SeedMessageAsync("batch-two@example.com");

        var hostedService = new PostgresEmailOutboxHostedService(
            dispatcherProvider,
            Options.Create(new PostgresEmailOutboxOptions { BatchSize = 1, PollingInterval = TimeSpan.FromHours(1) }));

        await hostedService.StartAsync(cts.Token);
        try
        {
            await hostedService.ExecuteTask!.WaitAsync(TimeSpan.FromSeconds(5));
        }
        catch (OperationCanceledException) when (cts.IsCancellationRequested) { }

        Assert.That(deliveredCount, Is.EqualTo(2));
    }

    [Test]
    public async Task HostedServiceContinuesOnError()
    {
        var services = new ServiceCollection();
        var providerMock = new Mock<IPostgresConnectionProvider>();

        var callCount = 0;
        var tcs = new TaskCompletionSource();

        providerMock.Setup(p => p.GetConnectionAsync(It.IsAny<CancellationToken>()))
            .Returns(async () =>
            {
                if (Interlocked.Increment(ref callCount) >= 3)
                {
                    tcs.TrySetResult();
                }

                await Task.Yield();
                throw new InvalidOperationException("DB Down");
            });

        services.AddSingleton(providerMock.Object);
        services.AddSingleton<TimeProvider>(_timeProvider);
        services.AddSingleton(new TestTransport());
        services.AddAshlarPostgresEmailOutbox<TestTransport>();
        var dispatcherProvider = services.BuildServiceProvider();

        var hostedService = new PostgresEmailOutboxHostedService(
            dispatcherProvider,
            Options.Create(new PostgresEmailOutboxOptions { PollingInterval = TimeSpan.FromMilliseconds(1) }));

        var cts = new CancellationTokenSource();
        var task = hostedService.StartAsync(cts.Token);

        // Wait until we've seen multiple failed attempts
        await tcs.Task.WaitAsync(TimeSpan.FromSeconds(5));

        await cts.CancelAsync();
        try { await task; } catch (OperationCanceledException) { }

        using (Assert.EnterMultipleScope())
        {
            Assert.That(task.IsCompleted, Is.True);
            Assert.That(callCount, Is.AtLeast(3));
        }
    }

    [Test]
    public async Task DispatcherProcessBatchAsyncHandlesLargeLastError()
    {
        var transport = new TestTransport { OnDeliver = (_, _) => throw new InvalidOperationException(new string('X', 2000)) };
        var services = new ServiceCollection();
        services.AddSingleton(transport);
        services.AddSingleton(_serviceProvider.GetRequiredService<IPostgresConnectionProvider>());
        var dispatcherProvider = services.BuildServiceProvider();

        await SeedMessageAsync("large-error@example.com");

        var dispatcher = new PostgresEmailOutboxDispatcher<TestTransport>(
            dispatcherProvider,
            _timeProvider,
            Options.Create(new PostgresEmailOutboxOptions()));

        await dispatcher.ProcessBatchAsync(CancellationToken.None);

        await using var connection = await GetDataSource().OpenConnectionAsync();
        var row = await connection.QuerySingleAsync<RawOutboxRow>("SELECT last_error AS LastError FROM ashlar_email_outbox");
        Assert.That(row.LastError, Has.Length.EqualTo(1000));
    }

    [Test]
    public async Task ConcurrentDispatchersDoNotDoubleSend()
    {
        var transport = new TestTransport { OnDeliver = async (_, ct) => await Task.Delay(100, ct) };
        var services = new ServiceCollection();
        services.AddSingleton(transport);
        services.AddSingleton(_serviceProvider.GetRequiredService<IPostgresConnectionProvider>());
        var dispatcherProvider = services.BuildServiceProvider();

        await SeedMessageAsync("concurrent@example.com");

        var dispatcher1 = new PostgresEmailOutboxDispatcher<TestTransport>(dispatcherProvider, _timeProvider, Options.Create(new PostgresEmailOutboxOptions()));
        var dispatcher2 = new PostgresEmailOutboxDispatcher<TestTransport>(dispatcherProvider, _timeProvider, Options.Create(new PostgresEmailOutboxOptions()));

        var task1 = dispatcher1.ProcessBatchAsync(CancellationToken.None);
        var task2 = dispatcher2.ProcessBatchAsync(CancellationToken.None);

        var results = await Task.WhenAll(task1, task2);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(results.Sum(), Is.EqualTo(1));
            Assert.That(transport.DeliveredCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task ExpiredLocksBecomeClaimable()
    {
        await SeedMessageAsync("locked@example.com");
        await using (var connection = await GetDataSource().OpenConnectionAsync())
        {
            await connection.ExecuteAsync("UPDATE ashlar_email_outbox SET locked_until = @until, locked_by = 'other'", new { until = _now.AddMinutes(-1) });
        }

        var transport = new TestTransport();
        var services = new ServiceCollection();
        services.AddSingleton(transport);
        services.AddSingleton(_serviceProvider.GetRequiredService<IPostgresConnectionProvider>());
        var dispatcherProvider = services.BuildServiceProvider();

        var dispatcher = new PostgresEmailOutboxDispatcher<TestTransport>(dispatcherProvider, _timeProvider, Options.Create(new PostgresEmailOutboxOptions()));
        var count = await dispatcher.ProcessBatchAsync(CancellationToken.None);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(count, Is.EqualTo(1));
            Assert.That(transport.DeliveredCount, Is.EqualTo(1));
        }
    }

    private async Task SeedMessageAsync(string to)
    {
        await using var connection = await GetDataSource().OpenConnectionAsync();
        await connection.ExecuteAsync(
            "INSERT INTO ashlar_email_outbox (id, to_address, subject, text_body, created_at, available_at) VALUES (@id, @to, 'Subject', 'Body', @now, @now)",
            new { id = Guid.NewGuid(), to, now = _timeProvider.GetUtcNow() });
    }

    public class TestTransport : IEmailTransport
    {
        private int _deliveredCount;

        public Func<EmailMessage, CancellationToken, Task> OnDeliver { get; set; } = (_, _) => Task.CompletedTask;
        public int DeliveredCount => _deliveredCount;

        public Task DeliverAsync(EmailMessage message, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _deliveredCount);
            return OnDeliver(message, cancellationToken);
        }
    }

    public sealed class RawOutboxRow
    {
        public DateTimeOffset CreatedAt { get; set; }
        public required string ToAddress { get; set; }
        public string? FromAddress { get; set; }
        public string? ReplyToAddress { get; set; }
        public required string Subject { get; set; }
        public string? TextBody { get; set; }
        public string? HtmlBody { get; set; }
        public string? Headers { get; set; }
        public string? Metadata { get; set; }
        public int AttemptCount { get; set; }
        public DateTimeOffset? SentAt { get; set; }
        public DateTimeOffset? FailedAt { get; set; }
        public string? LastError { get; set; }
        public DateTimeOffset? LastAttemptAt { get; set; }
        public DateTimeOffset AvailableAt { get; set; }
    }
}
