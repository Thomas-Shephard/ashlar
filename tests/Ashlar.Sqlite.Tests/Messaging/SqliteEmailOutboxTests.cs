using Ashlar.Messaging;
using Ashlar.Security.Encryption;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using System.Globalization;

namespace Ashlar.Sqlite.Tests.Messaging;

internal sealed class SqliteEmailOutboxTests : SqliteTestBase
{
    private ServiceProvider _serviceProvider = null!;
    private FakeTimeProvider _timeProvider = null!;
    private readonly List<ServiceProvider> _dispatcherProviders = [];
    private readonly DateTimeOffset _now = new(2026, 5, 8, 12, 0, 0, TimeSpan.Zero);

    [SetUp]
    public async Task SetUpAsync()
    {
        _timeProvider = new FakeTimeProvider(_now);
        _hostedDeliveredCount = 0;
        _hostedCancellation = null;
        _dispatcherProviders.Clear();
        var services = new ServiceCollection();
        services.AddAshlarSqlite(GetConnectionString());
        services.AddAshlarSqliteEmailOutboxSender();
        services.AddSingleton<TimeProvider>(_timeProvider);
        services.AddSingleton<ISecretProtector, FakeSecretProtector>();
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
    public void OptionsValidateMatchesExpectedBounds()
    {
        Assert.That(SqliteEmailOutboxOptions.Validate(new SqliteEmailOutboxOptions()), Is.True);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(SqliteEmailOutboxOptions.Validate(new SqliteEmailOutboxOptions { LockDuration = TimeSpan.Zero }), Is.False);
            Assert.That(SqliteEmailOutboxOptions.Validate(new SqliteEmailOutboxOptions { MaxAttempts = 0 }), Is.False);
            Assert.That(SqliteEmailOutboxOptions.Validate(new SqliteEmailOutboxOptions { InitialRetryDelay = TimeSpan.Zero }), Is.False);
            Assert.That(SqliteEmailOutboxOptions.Validate(new SqliteEmailOutboxOptions { BatchSize = 0 }), Is.False);
            Assert.That(SqliteEmailOutboxOptions.Validate(new SqliteEmailOutboxOptions { PollingInterval = TimeSpan.Zero }), Is.False);
        }

        Assert.Throws<ArgumentNullException>(() => SqliteEmailOutboxOptions.Validate(null!));
    }

    [Test]
    public void ConstructorsThrowForNullArguments()
    {
        var provider = _serviceProvider.GetRequiredService<ISqliteConnectionProvider>();
        var options = Options.Create(new SqliteEmailOutboxOptions());
        using var services = new ServiceCollection().BuildServiceProvider();

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new SqliteEmailOutboxSender(null!, _timeProvider, null));
            Assert.Throws<ArgumentNullException>(() => _ = new SqliteEmailOutboxSender(provider, null!, null));
            Assert.Throws<ArgumentNullException>(() => _ = new SqliteEmailOutboxDispatcher<TestTransport>(null!, _timeProvider, options));
            Assert.Throws<ArgumentNullException>(() => _ = new SqliteEmailOutboxDispatcher<TestTransport>(services, null!, options));
            Assert.Throws<ArgumentNullException>(() => _ = new SqliteEmailOutboxDispatcher<TestTransport>(services, _timeProvider, null!));
            Assert.Throws<ArgumentNullException>(() => _ = new SqliteEmailOutboxHostedService<TestTransport>(null!, options));
            Assert.Throws<ArgumentNullException>(() => _ = new SqliteEmailOutboxHostedService<TestTransport>(services, null!));
        }
    }

    [Test]
    public void ConstructorsAcceptNonNullOptionalLogger()
    {
        var options = Options.Create(new SqliteEmailOutboxOptions());
        using var services = new ServiceCollection().BuildServiceProvider();

        using (Assert.EnterMultipleScope())
        {
            Assert.DoesNotThrow(() => _ = new SqliteEmailOutboxDispatcher<TestTransport>(services, _timeProvider, options, NullLogger<SqliteEmailOutboxDispatcher<TestTransport>>.Instance));
            Assert.DoesNotThrow(() => _ = new SqliteEmailOutboxHostedService<TestTransport>(services, options, NullLogger<SqliteEmailOutboxHostedService<TestTransport>>.Instance));
        }
    }

    [Test]
    public async Task SenderEnqueuesMessageOutsideTransaction()
    {
        var sender = _serviceProvider.GetRequiredService<IEmailSender>();
        await sender.SendAsync(new EmailMessage(
            "to@example.com",
            "Subject",
            "Text",
            "<p>Html</p>",
            new EmailMessageOptions
            {
                From = "from@example.com",
                ReplyTo = "reply@example.com",
                Cc = "cc@example.com",
                Bcc = "bcc@example.com",
                Headers = new Dictionary<string, string> { ["X-Test"] = "Header" },
                Metadata = new Dictionary<string, string> { ["Trace"] = "Metadata" },
                Sensitivity = EmailMessageSensitivity.ContainsLiveSecret
            }));

        var row = await QuerySingleOutboxRowAsync();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(row.ToAddress, Is.EqualTo("to@example.com"));
            Assert.That(row.FromAddress, Is.EqualTo("from@example.com"));
            Assert.That(row.ReplyToAddress, Is.EqualTo("reply@example.com"));
            Assert.That(row.CcAddress, Is.EqualTo("cc@example.com"));
            Assert.That(row.BccAddress, Is.EqualTo("bcc@example.com"));
            Assert.That(row.Subject, Is.EqualTo("Subject"));
            Assert.That(row.TextBody, Is.Not.EqualTo("Text"));
            Assert.That(row.TextBody, Does.Not.Contain("Text"));
            Assert.That(row.HtmlBody, Is.Not.EqualTo("<p>Html</p>"));
            Assert.That(row.HtmlBody, Does.Not.Contain("Html"));
            Assert.That(row.Headers, Does.Contain("\"X-Test\":\"Header\""));
            Assert.That(row.Metadata, Does.Contain("\"Trace\":\"Metadata\""));
            Assert.That(row.Sensitivity, Is.EqualTo(nameof(EmailMessageSensitivity.ContainsLiveSecret)));
            Assert.That(row.BodyProtection, Is.EqualTo(nameof(EmailOutboxBodyProtection.SecretProtector)));
            Assert.That(row.CreatedAt, Is.EqualTo(_now));
            Assert.That(row.AvailableAt, Is.EqualTo(_now));
        }
    }

    [Test]
    public async Task SenderStoresNormalBodyPlaintext()
    {
        var sender = _serviceProvider.GetRequiredService<IEmailSender>();
        await sender.SendAsync(new EmailMessage("to@example.com", "Subject", "Normal body"));

        var row = await QuerySingleOutboxRowAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(row.TextBody, Is.EqualTo("Normal body"));
            Assert.That(row.BodyProtection, Is.EqualTo(nameof(EmailOutboxBodyProtection.None)));
        }
    }

    [Test]
    public async Task SchemaRejectsSensitiveMessageWithoutProtectedBodies()
    {
        var exception = Assert.CatchAsync<Exception>(() => ExecuteAsync(
            """
            INSERT INTO ashlar_email_outbox (
                id, to_address, subject, text_body, sensitivity, body_protection, created_at, available_at
            ) VALUES (
                $id, 'mismatch@example.com', 'Subject', 'Plain secret', 'ContainsLiveSecret', 'None', $now, $now
            )
            """,
            command =>
            {
                command.AddGuidParameter("$id", Guid.NewGuid());
                command.AddDateTimeOffsetParameter("$now", _timeProvider.GetUtcNow());
            }));

        Assert.That(exception!.Message, Does.Contain("ck_ashlar_email_outbox_sensitive_body_protection"));
    }

    [Test]
    public void SenderThrowsForSensitiveMessageWithoutSecretProtector()
    {
        var sender = new SqliteEmailOutboxSender(
            _serviceProvider.GetRequiredService<ISqliteConnectionProvider>(),
            _timeProvider);

        var message = new EmailMessage(
            "to@example.com",
            "Subject",
            "Body",
            options: new EmailMessageOptions { Sensitivity = EmailMessageSensitivity.ContainsLiveSecret });

        var exception = Assert.ThrowsAsync<InvalidOperationException>(() => sender.SendAsync(message));

        Assert.That(exception!.Message, Does.Contain("ISecretProtector"));
    }

    [Test]
    public async Task SenderParticipatesInTransactionsAndRollback()
    {
        var sender = _serviceProvider.GetRequiredService<IEmailSender>();
        var txProvider = _serviceProvider.GetRequiredService<IAshlarTransactionProvider>();

        await using (var tx = await txProvider.BeginTransactionAsync())
        {
            await sender.SendAsync(new EmailMessage("rollback@example.com", "Subject", "Body"));
            Assert.That(await CountRowsOutsideScopeAsync(), Is.Zero);
            await tx.RollbackAsync();
        }

        Assert.That(await CountRowsOutsideScopeAsync(), Is.Zero);

        await using (var tx = await txProvider.BeginTransactionAsync())
        {
            await sender.SendAsync(new EmailMessage("commit@example.com", "Subject", "Body"));
            await tx.CommitAsync();
        }

        Assert.That(await CountRowsOutsideScopeAsync(), Is.EqualTo(1));
    }

    [Test]
    public async Task DispatcherMarksSuccessfulMessagesSent()
    {
        var transport = new TestTransport();
        var dispatcher = BuildDispatcher(transport);
        await SeedMessageAsync("sent@example.com");

        var count = await dispatcher.ProcessBatchAsync();
        var row = await QuerySingleOutboxRowAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(count, Is.EqualTo(1));
            Assert.That(transport.DeliveredCount, Is.EqualTo(1));
            Assert.That(row.SentAt, Is.EqualTo(_now));
            Assert.That(row.AttemptCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task DispatcherConcurrentCallsOnSameInstanceDoNotDeliverSameMessageTwice()
    {
        var firstDeliveryStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseFirstDelivery = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var deliveryCount = 0;
        var transport = new TestTransport
        {
            OnDeliver = async (_, _) =>
            {
                if (Interlocked.Increment(ref deliveryCount) == 1)
                {
                    firstDeliveryStarted.SetResult();
                    await releaseFirstDelivery.Task;
                }
            }
        };
        var dispatcher = BuildDispatcher(transport);
        await SeedMessageAsync("overlap@example.com");

        var first = dispatcher.ProcessBatchAsync();
        await firstDeliveryStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var second = await dispatcher.ProcessBatchAsync().WaitAsync(TimeSpan.FromSeconds(5));

        releaseFirstDelivery.SetResult();
        var firstCount = await first.WaitAsync(TimeSpan.FromSeconds(5));
        var row = await QuerySingleOutboxRowAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(firstCount, Is.EqualTo(1));
            Assert.That(second, Is.Zero);
            Assert.That(firstCount + second, Is.EqualTo(1));
            Assert.That(transport.DeliveredCount, Is.EqualTo(1));
            Assert.That(row.SentAt, Is.EqualTo(_now));
            Assert.That(row.AttemptCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task DispatcherUnprotectsSensitiveBodies()
    {
        var protector = _serviceProvider.GetRequiredService<ISecretProtector>();
        var transport = new TestTransport();
        var dispatcher = BuildDispatcher(transport, secretProtector: protector);
        await ExecuteAsync(
            """
            INSERT INTO ashlar_email_outbox (
                id, to_address, subject, text_body, html_body, sensitivity, body_protection, created_at, available_at
            ) VALUES (
                $id, 'protected@example.com', 'Subject', $textBody, $htmlBody, 'ContainsLiveSecret', 'SecretProtector', $now, $now
            )
            """,
            command =>
            {
                command.AddGuidParameter("$id", Guid.NewGuid());
                command.AddParameter("$textBody", protector.Protect("Secret text"));
                command.AddParameter("$htmlBody", protector.Protect("<p>Secret html</p>"));
                command.AddDateTimeOffsetParameter("$now", _timeProvider.GetUtcNow());
            });

        await dispatcher.ProcessBatchAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(transport.Messages.Single().TextBody, Is.EqualTo("Secret text"));
            Assert.That(transport.Messages.Single().HtmlBody, Is.EqualTo("<p>Secret html</p>"));
            Assert.That(transport.Messages.Single().Sensitivity, Is.EqualTo(EmailMessageSensitivity.ContainsLiveSecret));
        }
    }

    [Test]
    public async Task DispatcherDoesNotDispatchUnknownBodyProtectionAsPlaintext()
    {
        var transport = new TestTransport();
        var dispatcher = BuildDispatcher(transport);
        await ExecuteAsync(
            """
            PRAGMA ignore_check_constraints = ON;
            INSERT INTO ashlar_email_outbox (
                id, to_address, subject, text_body, body_protection, created_at, available_at
            ) VALUES (
                $id, 'unknown-protection@example.com', 'Subject', 'Plain secret', 'Unknown', $now, $now
            );
            PRAGMA ignore_check_constraints = OFF;
            """,
            command =>
            {
                command.AddGuidParameter("$id", Guid.NewGuid());
                command.AddDateTimeOffsetParameter("$now", _timeProvider.GetUtcNow());
            });

        await dispatcher.ProcessBatchAsync();

        var row = await QuerySingleOutboxRowAsync();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(transport.DeliveredCount, Is.Zero);
            Assert.That(row.AttemptCount, Is.EqualTo(1));
            Assert.That(row.LastError, Does.Contain("suppressed"));
            Assert.That(row.LastError, Does.Not.Contain("Plain secret"));
        }
    }

    [Test]
    public async Task DispatcherSuppressesSensitiveFailureDetails()
    {
        var protector = _serviceProvider.GetRequiredService<ISecretProtector>();
        var transport = new TestTransport { OnDeliver = (message, _) => throw new InvalidOperationException(message.TextBody) };
        var dispatcher = BuildDispatcher(transport, secretProtector: protector);
        await ExecuteAsync(
            """
            INSERT INTO ashlar_email_outbox (
                id, to_address, subject, text_body, sensitivity, body_protection, created_at, available_at
            ) VALUES (
                $id, 'protected-failure@example.com', 'Subject', $textBody, 'ContainsLiveSecret', 'SecretProtector', $now, $now
            )
            """,
            command =>
            {
                command.AddGuidParameter("$id", Guid.NewGuid());
                command.AddParameter("$textBody", protector.Protect("live-token-link"));
                command.AddDateTimeOffsetParameter("$now", _timeProvider.GetUtcNow());
            });

        await dispatcher.ProcessBatchAsync();

        var row = await QuerySingleOutboxRowAsync();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(transport.DeliveredCount, Is.EqualTo(1));
            Assert.That(row.LastError, Does.Contain("suppressed"));
            Assert.That(row.LastError, Does.Not.Contain("live-token-link"));
        }
    }

    [Test]
    public async Task DispatcherSchedulesRetryAfterFailure()
    {
        var transport = new TestTransport { OnDeliver = (_, _) => throw new InvalidOperationException("Delivery failed") };
        var dispatcher = BuildDispatcher(transport, new SqliteEmailOutboxOptions { InitialRetryDelay = TimeSpan.FromSeconds(30) });
        await SeedMessageAsync("retry@example.com");

        await dispatcher.ProcessBatchAsync();
        var row = await QuerySingleOutboxRowAsync();

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
    public async Task DispatcherMarksFailedAtWhenMaxAttemptsReached()
    {
        var transport = new TestTransport { OnDeliver = (_, _) => throw new InvalidOperationException("Persistent failure") };
        var dispatcher = BuildDispatcher(transport, new SqliteEmailOutboxOptions { MaxAttempts = 1 });
        await SeedMessageAsync("failed@example.com");

        await dispatcher.ProcessBatchAsync();
        var row = await QuerySingleOutboxRowAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(row.SentAt, Is.Null);
            Assert.That(row.FailedAt, Is.EqualTo(_now));
            Assert.That(row.AttemptCount, Is.EqualTo(1));
            Assert.That(row.LastError, Does.Contain("Persistent failure"));
        }
    }

    [Test]
    public async Task DispatcherRecoversExpiredLocks()
    {
        var transport = new TestTransport();
        var dispatcher = BuildDispatcher(transport);
        await SeedMessageAsync("locked@example.com");
        await ExecuteAsync("UPDATE ashlar_email_outbox SET locked_until = $lockedUntil, locked_by = 'other'", command =>
            command.AddDateTimeOffsetParameter("$lockedUntil", _now.AddMinutes(-1)));

        var count = await dispatcher.ProcessBatchAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(count, Is.EqualTo(1));
            Assert.That(transport.DeliveredCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task DispatcherRespectsBatchSizeAndReturnsZeroWhenEmpty()
    {
        var transport = new TestTransport();
        var dispatcher = BuildDispatcher(transport, new SqliteEmailOutboxOptions { BatchSize = 2 });
        Assert.That(await dispatcher.ProcessBatchAsync(), Is.Zero);

        await SeedMessageAsync("one@example.com");
        await SeedMessageAsync("two@example.com");
        await SeedMessageAsync("three@example.com");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(await dispatcher.ProcessBatchAsync(), Is.EqualTo(2));
            Assert.That(transport.DeliveredCount, Is.EqualTo(2));
        }
    }

    [Test]
    public async Task DispatcherThrowsForInvalidOptions()
    {
        var dispatcher = BuildDispatcher(new TestTransport(), new SqliteEmailOutboxOptions { BatchSize = 0 });
        Assert.ThrowsAsync<InvalidOperationException>(() => dispatcher.ProcessBatchAsync());
    }

    [Test]
    public async Task DispatcherRethrowsWhenCancellationRequested()
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
        var dispatcher = BuildDispatcher(transport);
        await SeedMessageAsync("cancel@example.com");

        Assert.ThrowsAsync<OperationCanceledException>(() => dispatcher.ProcessBatchAsync(cts.Token));
    }

    [Test]
    public async Task DispatcherTruncatesLargeLastError()
    {
        var transport = new TestTransport { OnDeliver = (_, _) => throw new InvalidOperationException(new string('X', 2000)) };
        var dispatcher = BuildDispatcher(transport);
        await SeedMessageAsync("large-error@example.com");

        await dispatcher.ProcessBatchAsync();
        var row = await QuerySingleOutboxRowAsync();

        Assert.That(row.LastError, Has.Length.EqualTo(1000));
    }

    [Test]
    public void MapToEmailMessageHandlesOptionalFields()
    {
        ISecretProtector protector = new FakeSecretProtector();
        var message = EmailOutboxDispatch.MapToEmailMessage(new EmailOutboxEntry
        {
            Id = Guid.NewGuid(),
            ToAddress = "to@example.com",
            FromAddress = "from@example.com",
            ReplyToAddress = "reply@example.com",
            CcAddress = "cc@example.com",
            BccAddress = "bcc@example.com",
            Subject = "Subject",
            TextBody = protector.Protect("Text"),
            HtmlBody = protector.Protect("Html"),
            Sensitivity = EmailMessageSensitivity.ContainsLiveSecret,
            BodyProtection = EmailOutboxBodyProtection.SecretProtector,
            Headers = "{\"X-Test\":\"Header\"}",
            Metadata = "{\"Trace\":\"Metadata\"}"
        }, protector);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(message.To, Is.EqualTo("to@example.com"));
            Assert.That(message.From, Is.EqualTo("from@example.com"));
            Assert.That(message.ReplyTo, Is.EqualTo("reply@example.com"));
            Assert.That(message.Cc, Is.EqualTo("cc@example.com"));
            Assert.That(message.Bcc, Is.EqualTo("bcc@example.com"));
            Assert.That(message.Headers, Does.ContainKey("X-Test").WithValue("Header"));
            Assert.That(message.Metadata, Does.ContainKey("Trace").WithValue("Metadata"));
            Assert.That(message.Sensitivity, Is.EqualTo(EmailMessageSensitivity.ContainsLiveSecret));
        }
    }

    [Test]
    public async Task HostedServiceDispatchesOneLoop()
    {
        var transport = new TestTransport
        {
            OnDeliver = (_, _) =>
            {
                _ = Task.Run(async () =>
                {
                    await Task.Delay(10);
                    await _hostedCancellation!.CancelAsync();
                }, CancellationToken.None);
                return Task.CompletedTask;
            }
        };
        await SeedMessageAsync("hosted@example.com");
        await using var provider = BuildDispatcherProvider(transport, new SqliteEmailOutboxOptions { PollingInterval = TimeSpan.FromMilliseconds(1) }, trackForTearDown: false);
        var hostedService = new SqliteEmailOutboxHostedService<TestTransport>(
            provider,
            Options.Create(new SqliteEmailOutboxOptions { PollingInterval = TimeSpan.FromMilliseconds(1) }));
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        _hostedCancellation = cts;

        await hostedService.StartAsync(cts.Token);
        await hostedService.ExecuteTask!.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.That(transport.DeliveredCount, Is.EqualTo(1));
    }

    [Test]
    public async Task HostedServiceThrowsForInvalidOptions()
    {
        await using var provider = new ServiceCollection().BuildServiceProvider();
        var hostedService = new SqliteEmailOutboxHostedService<TestTransport>(
            provider,
            Options.Create(new SqliteEmailOutboxOptions { BatchSize = 0 }));

        Assert.ThrowsAsync<InvalidOperationException>(() => hostedService.StartAsync(CancellationToken.None));
    }

    [Test]
    public async Task HostedServiceContinuesImmediatelyWhenBatchIsFull()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var transport = new TestTransport
        {
            OnDeliver = (_, _) =>
            {
                if (Interlocked.Increment(ref _hostedDeliveredCount) >= 2)
                {
                    cts.Cancel();
                }

                return Task.CompletedTask;
            }
        };
        await SeedMessageAsync("hosted-one@example.com");
        await SeedMessageAsync("hosted-two@example.com");
        await using var provider = BuildDispatcherProvider(transport, new SqliteEmailOutboxOptions { BatchSize = 1, PollingInterval = TimeSpan.FromHours(1) }, trackForTearDown: false);
        var hostedService = new SqliteEmailOutboxHostedService<TestTransport>(
            provider,
            Options.Create(new SqliteEmailOutboxOptions { BatchSize = 1, PollingInterval = TimeSpan.FromHours(1) }));

        await hostedService.StartAsync(cts.Token);
        await hostedService.ExecuteTask!.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.That(_hostedDeliveredCount, Is.EqualTo(2));
    }

    [Test]
    public async Task HostedServiceContinuesOnErrorUntilCanceled()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var services = new ServiceCollection();
        await using var provider = services.BuildServiceProvider();
        var hostedService = new SqliteEmailOutboxHostedService<TestTransport>(
            provider,
            Options.Create(new SqliteEmailOutboxOptions { PollingInterval = TimeSpan.FromMilliseconds(1) }));

        await hostedService.StartAsync(cts.Token);
        await Task.Delay(30, TestContext.CurrentContext.CancellationToken);
        await cts.CancelAsync();
        await hostedService.ExecuteTask!;

        Assert.That(hostedService.ExecuteTask.IsCompleted, Is.True);
    }

    private CancellationTokenSource? _hostedCancellation;
    private int _hostedDeliveredCount;

    private SqliteEmailOutboxDispatcher<TestTransport> BuildDispatcher(
        TestTransport transport,
        SqliteEmailOutboxOptions? options = null,
        ISecretProtector? secretProtector = null)
    {
        var provider = BuildDispatcherProvider(transport, options, secretProtector: secretProtector);
        return new SqliteEmailOutboxDispatcher<TestTransport>(
            provider,
            _timeProvider,
            Options.Create(options ?? new SqliteEmailOutboxOptions()));
    }

    private ServiceProvider BuildDispatcherProvider(
        TestTransport transport,
        SqliteEmailOutboxOptions? options = null,
        bool trackForTearDown = true,
        ISecretProtector? secretProtector = null)
    {
        var services = new ServiceCollection();
        services.AddAshlarSqlite(GetConnectionString());
        services.AddSingleton(transport);
        services.AddSingleton<TimeProvider>(_timeProvider);
        if (secretProtector != null)
        {
            services.AddSingleton(secretProtector);
        }

        services.AddAshlarSqliteEmailOutboxDispatcher<TestTransport>(_ =>
        {
            if (options != null)
            {
                _.BatchSize = options.BatchSize;
                _.InitialRetryDelay = options.InitialRetryDelay;
                _.LockDuration = options.LockDuration;
                _.MaxAttempts = options.MaxAttempts;
                _.PollingInterval = options.PollingInterval;
            }
        });
        var provider = services.BuildServiceProvider();
        if (trackForTearDown)
        {
            _dispatcherProviders.Add(provider);
        }

        return provider;
    }

    private async Task SeedMessageAsync(string to)
    {
        await ExecuteAsync(
            "INSERT INTO ashlar_email_outbox (id, to_address, subject, text_body, created_at, available_at) VALUES ($id, $to, 'Subject', 'Body', $now, $now)",
            command =>
            {
                command.AddGuidParameter("$id", Guid.NewGuid());
                command.AddParameter("$to", to);
                command.AddDateTimeOffsetParameter("$now", _timeProvider.GetUtcNow());
            });
    }

    private async Task ExecuteAsync(string sql, Action<Microsoft.Data.Sqlite.SqliteCommand> bind)
    {
        await using var connection = await OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        bind(command);
        await command.ExecuteNonQueryAsync();
    }

    private async Task<int> CountRowsOutsideScopeAsync()
    {
        await using var connection = await OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT count(*) FROM ashlar_email_outbox";
        return Convert.ToInt32(await command.ExecuteScalarAsync(), CultureInfo.InvariantCulture);
    }

    private async Task<RawOutboxRow> QuerySingleOutboxRowAsync()
    {
        await using var connection = await OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT to_address, from_address, reply_to_address, cc_address, bcc_address, subject, text_body, html_body,
                   sensitivity, body_protection, headers, metadata, created_at, available_at, attempt_count, sent_at,
                   failed_at, last_error, last_attempt_at
            FROM ashlar_email_outbox
            ORDER BY created_at, id
            LIMIT 1
            """;
        await using var reader = await command.ExecuteReaderAsync();
        Assert.That(await reader.ReadAsync(), Is.True);
        return new RawOutboxRow
        {
            ToAddress = reader.GetString(reader.GetOrdinal("to_address")),
            FromAddress = reader.GetNullableString("from_address"),
            ReplyToAddress = reader.GetNullableString("reply_to_address"),
            CcAddress = reader.GetNullableString("cc_address"),
            BccAddress = reader.GetNullableString("bcc_address"),
            Subject = reader.GetString(reader.GetOrdinal("subject")),
            TextBody = reader.GetNullableString("text_body"),
            HtmlBody = reader.GetNullableString("html_body"),
            Sensitivity = reader.GetString(reader.GetOrdinal("sensitivity")),
            BodyProtection = reader.GetString(reader.GetOrdinal("body_protection")),
            Headers = reader.GetNullableString("headers"),
            Metadata = reader.GetNullableString("metadata"),
            CreatedAt = reader.GetDateTimeOffsetFromText("created_at"),
            AvailableAt = reader.GetDateTimeOffsetFromText("available_at"),
            AttemptCount = reader.GetInt32ByName("attempt_count"),
            SentAt = reader.GetNullableDateTimeOffsetFromText("sent_at"),
            FailedAt = reader.GetNullableDateTimeOffsetFromText("failed_at"),
            LastError = reader.GetNullableString("last_error"),
            LastAttemptAt = reader.GetNullableDateTimeOffsetFromText("last_attempt_at")
        };
    }

    private sealed class TestTransport : IEmailTransport
    {
        private int _deliveredCount;
        private readonly List<EmailMessage> _messages = [];

        public Func<EmailMessage, CancellationToken, Task> OnDeliver { get; set; } = (_, _) => Task.CompletedTask;
        public int DeliveredCount => _deliveredCount;
        public IReadOnlyList<EmailMessage> Messages => _messages;

        public Task DeliverAsync(EmailMessage message, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _deliveredCount);
            _messages.Add(message);
            return OnDeliver(message, cancellationToken);
        }
    }

    private sealed class FakeSecretProtector : ISecretProtector
    {
        private static readonly byte[] Prefix = "protected:"u8.ToArray();

        public byte[] Protect(byte[] data)
        {
            ArgumentNullException.ThrowIfNull(data);

            var protectedData = new byte[Prefix.Length + data.Length];
            Buffer.BlockCopy(Prefix, 0, protectedData, 0, Prefix.Length);
            Buffer.BlockCopy(data, 0, protectedData, Prefix.Length, data.Length);
            return protectedData;
        }

        public byte[] Unprotect(byte[] data)
        {
            ArgumentNullException.ThrowIfNull(data);

            return data.Skip(Prefix.Length).ToArray();
        }
    }

    private sealed class RawOutboxRow
    {
        public required string ToAddress { get; init; }
        public string? FromAddress { get; init; }
        public string? ReplyToAddress { get; init; }
        public string? CcAddress { get; init; }
        public string? BccAddress { get; init; }
        public required string Subject { get; init; }
        public string? TextBody { get; init; }
        public string? HtmlBody { get; init; }
        public required string Sensitivity { get; init; }
        public required string BodyProtection { get; init; }
        public string? Headers { get; init; }
        public string? Metadata { get; init; }
        public DateTimeOffset CreatedAt { get; init; }
        public DateTimeOffset AvailableAt { get; init; }
        public int AttemptCount { get; init; }
        public DateTimeOffset? SentAt { get; init; }
        public DateTimeOffset? FailedAt { get; init; }
        public string? LastError { get; init; }
        public DateTimeOffset? LastAttemptAt { get; init; }
    }
}
