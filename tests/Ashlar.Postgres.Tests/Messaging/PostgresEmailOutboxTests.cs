using System.Diagnostics.CodeAnalysis;
using Ashlar.Messaging;
using Ashlar.Operational;
using Ashlar.Security.Encryption;
using Dapper;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Npgsql;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Postgres.Tests.Messaging;

internal sealed class PostgresEmailOutboxTests : PostgresTestBase
{
    [Test]
    public async Task SchemaRequiresExplicitSensitivity()
    {
        await using var connection = await GetDataSource().OpenConnectionAsync();

        var exception = Assert.ThrowsAsync<PostgresException>(() => connection.ExecuteAsync(
            "INSERT INTO ashlar_email_outbox (id, to_address, subject, text_body, created_at, available_at) VALUES (@id, 'to@example.com', 'Subject', 'Body', @now, @now)",
            new { id = Guid.NewGuid(), now = _now }));

        Assert.That(exception!.SqlState, Is.EqualTo(PostgresErrorCodes.NotNullViolation));
    }

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
        services.AddAshlarPostgresEmailOutboxSender();
        services.AddAshlarPostgresCleanup();
        services.AddSingleton<TimeProvider>(_timeProvider);
        services.AddSingleton<ISecretProtector, FakeSecretProtector>();
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
            Assert.Throws<ArgumentNullException>(() => _ = new PostgresEmailOutboxSender(null!, _timeProvider, null));
            Assert.Throws<ArgumentNullException>(() => _ = new PostgresEmailOutboxSender(provider, null!, null));
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
            _timeProvider,
            _serviceProvider.GetRequiredService<ISecretProtector>());

        var message = new EmailMessage(
            "to@example.com",
            "Subject", EmailMessageSensitivity.Normal,
            "Body",
            options: new EmailMessageOptions
            {
                From = "from@example.com",
                ReplyTo = "reply@example.com",
                Cc = "cc@example.com",
                Bcc = "bcc@example.com"
            });

        await sender.SendAsync(message);

        await using var connection = await GetDataSource().OpenConnectionAsync();
        var row = await connection.QuerySingleAsync<RawOutboxRow>("""
            SELECT from_address AS FromAddress, reply_to_address AS ReplyToAddress,
                   cc_address AS CcAddress, bcc_address AS BccAddress,
                   created_at AS CreatedAt, available_at AS AvailableAt
            FROM ashlar_email_outbox
            """);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(row.FromAddress, Is.EqualTo("from@example.com"));
            Assert.That(row.ReplyToAddress, Is.EqualTo("reply@example.com"));
            Assert.That(row.CcAddress, Is.EqualTo("cc@example.com"));
            Assert.That(row.BccAddress, Is.EqualTo("bcc@example.com"));
            Assert.That(row.CreatedAt, Is.EqualTo(_now));
            Assert.That(row.AvailableAt, Is.EqualTo(_now));
        }
    }

    [Test]
    public async Task SenderSendAsyncSerializesHeadersAndMetadata()
    {
        var sender = new PostgresEmailOutboxSender(
            _serviceProvider.GetRequiredService<IPostgresConnectionProvider>(),
            _timeProvider,
            _serviceProvider.GetRequiredService<ISecretProtector>());

        var message = new EmailMessage(
            "to@example.com",
            "Subject", EmailMessageSensitivity.Normal,
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
    public async Task SenderSendAsyncPersistsSensitivity()
    {
        var sender = new PostgresEmailOutboxSender(
            _serviceProvider.GetRequiredService<IPostgresConnectionProvider>(),
            _timeProvider,
            _serviceProvider.GetRequiredService<ISecretProtector>());

        await sender.SendAsync(new EmailMessage(
            "to@example.com",
            "Subject", EmailMessageSensitivity.ContainsLiveSecret,
            "Body"));

        await using var connection = await GetDataSource().OpenConnectionAsync();
        var row = await connection.QuerySingleAsync<RawOutboxRow>("SELECT sensitivity AS Sensitivity, body_protection AS BodyProtection, text_body AS TextBody FROM ashlar_email_outbox");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(row.Sensitivity, Is.EqualTo(nameof(EmailMessageSensitivity.ContainsLiveSecret)));
            Assert.That(row.BodyProtection, Is.EqualTo(nameof(EmailOutboxBodyProtection.SecretProtector)));
            Assert.That(row.TextBody, Is.Not.EqualTo("Body"));
            Assert.That(row.TextBody, Does.Not.Contain("Body"));
        }
    }

    [Test]
    public async Task SenderSendAsyncStoresNormalBodyPlaintext()
    {
        var sender = new PostgresEmailOutboxSender(
            _serviceProvider.GetRequiredService<IPostgresConnectionProvider>(),
            _timeProvider,
            _serviceProvider.GetRequiredService<ISecretProtector>());

        await sender.SendAsync(new EmailMessage("to@example.com", "Subject", EmailMessageSensitivity.Normal, "Normal body"));

        await using var connection = await GetDataSource().OpenConnectionAsync();
        var row = await connection.QuerySingleAsync<RawOutboxRow>("SELECT body_protection AS BodyProtection, text_body AS TextBody FROM ashlar_email_outbox");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(row.BodyProtection, Is.EqualTo(nameof(EmailOutboxBodyProtection.None)));
            Assert.That(row.TextBody, Is.EqualTo("Normal body"));
        }
    }

    [Test]
    public async Task SchemaRejectsSensitiveMessageWithoutProtectedBodies()
    {
        await using var connection = await GetDataSource().OpenConnectionAsync();

        var exception = Assert.CatchAsync<Exception>(async () => await connection.ExecuteAsync(
            """
            INSERT INTO ashlar_email_outbox (
                id, to_address, subject, text_body, sensitivity, body_protection, created_at, available_at
            ) VALUES (
                @id, 'mismatch@example.com', 'Subject', 'Plain secret', 'ContainsLiveSecret', 'None', @now, @now
            )
            """,
            new { id = Guid.NewGuid(), now = _timeProvider.GetUtcNow() }));

        Assert.That(exception!.Message, Does.Contain("ck_ashlar_email_outbox_sensitive_body_protection"));
    }

    [Test]
    public void SenderSendAsyncThrowsForSensitiveMessageWithoutSecretProtector()
    {
        var sender = new PostgresEmailOutboxSender(
            _serviceProvider.GetRequiredService<IPostgresConnectionProvider>(),
            _timeProvider);

        var message = new EmailMessage(
            "to@example.com",
            "Subject", EmailMessageSensitivity.ContainsLiveSecret,
            "Body");

        var exception = Assert.ThrowsAsync<InvalidOperationException>(() => sender.SendAsync(message));

        Assert.That(exception!.Message, Does.Contain("ISecretProtector"));
    }

    [Test]
    public async Task SenderSendAsyncIsTransactional()
    {
        var provider = _serviceProvider.GetRequiredService<IPostgresConnectionProvider>();
        var txProvider = _serviceProvider.GetRequiredService<AshlarDurableTransactionProvider>();
        var sender = new PostgresEmailOutboxSender(provider, _timeProvider);

        await using (var tx = await txProvider.BeginTransactionAsync())
        {
            await sender.SendAsync(new EmailMessage("to@example.com", "Subject", EmailMessageSensitivity.Normal, "Body"));

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
    public async Task DispatcherProcessBatchAsyncDoesNotMarkSentWhenLockOwnerChangesAfterSuccessfulDelivery()
    {
        var transport = new TestTransport
        {
            OnDeliver = async (_, _) =>
            {
                await using var connection = await GetDataSource().OpenConnectionAsync(CancellationToken.None);
                await connection.ExecuteAsync("UPDATE ashlar_email_outbox SET locked_by = 'other-dispatcher';");
            }
        };
        var services = new ServiceCollection();
        services.AddSingleton(transport);
        services.AddSingleton(_serviceProvider.GetRequiredService<IPostgresConnectionProvider>());
        var dispatcherProvider = services.BuildServiceProvider();
        await SeedMessageAsync("lost-lock@example.com");

        var dispatcher = new PostgresEmailOutboxDispatcher<TestTransport>(
            dispatcherProvider,
            _timeProvider,
            Options.Create(new PostgresEmailOutboxOptions()));

        var count = await dispatcher.ProcessBatchAsync(CancellationToken.None);

        await using var connection = await GetDataSource().OpenConnectionAsync();
        var row = await connection.QuerySingleAsync<RawOutboxRow>("""
            SELECT sent_at AS SentAt, failed_at AS FailedAt, attempt_count AS AttemptCount,
                   last_error AS LastError
            FROM ashlar_email_outbox
            """);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(count, Is.EqualTo(1));
            Assert.That(transport.DeliveredCount, Is.EqualTo(1));
            Assert.That(row.SentAt, Is.Null);
            Assert.That(row.FailedAt, Is.Null);
            Assert.That(row.AttemptCount, Is.Zero);
            Assert.That(row.LastError, Is.Null);
        }
    }

    [Test]
    public async Task DispatcherProcessBatchAsyncDoesNotLetStaleSameInstanceCompletionMarkNewerClaimSent()
    {
        var firstDeliveryStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var secondDeliveryStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseFirstDelivery = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseSecondDelivery = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var transport = new BlockingEmailTransport(firstDeliveryStarted, secondDeliveryStarted, releaseFirstDelivery, releaseSecondDelivery);
        var services = new ServiceCollection();
        services.AddSingleton(transport);
        services.AddSingleton(_serviceProvider.GetRequiredService<IPostgresConnectionProvider>());
        var dispatcherProvider = services.BuildServiceProvider();
        await SeedMessageAsync("same-instance-expired@example.com");

        var dispatcher = new PostgresEmailOutboxDispatcher<BlockingEmailTransport>(
            dispatcherProvider,
            _timeProvider,
            Options.Create(new PostgresEmailOutboxOptions { LockDuration = TimeSpan.FromMinutes(1) }));

        var first = dispatcher.ProcessBatchAsync(CancellationToken.None);
        await firstDeliveryStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await ExpireSingleEmailLockAsync();

        var second = dispatcher.ProcessBatchAsync(CancellationToken.None);
        await secondDeliveryStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var newerClaimRow = await QuerySingleEmailDispatchStateAsync();

        releaseFirstDelivery.SetResult();
        var firstCount = await first.WaitAsync(TimeSpan.FromSeconds(5));
        var staleCompletionRow = await QuerySingleEmailDispatchStateAsync();

        releaseSecondDelivery.SetResult();
        var secondCount = await second.WaitAsync(TimeSpan.FromSeconds(5));
        var finalRow = await QuerySingleEmailDispatchStateAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(firstCount, Is.EqualTo(1));
            Assert.That(secondCount, Is.EqualTo(1));
            Assert.That(transport.DeliveredCount, Is.EqualTo(2));
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
    public async Task DispatcherProcessBatchAsyncDoesNotMarkSentWhenEmailRowBecomesTerminalAfterSuccessfulDelivery()
    {
        var transport = new TestTransport
        {
            OnDeliver = async (_, _) =>
            {
                await using var connection = await GetDataSource().OpenConnectionAsync(CancellationToken.None);
                await connection.ExecuteAsync("UPDATE ashlar_email_outbox SET failed_at = @now;", new { now = _timeProvider.GetUtcNow() });
            }
        };
        var services = new ServiceCollection();
        services.AddSingleton(transport);
        services.AddSingleton(_serviceProvider.GetRequiredService<IPostgresConnectionProvider>());
        var dispatcherProvider = services.BuildServiceProvider();
        await SeedMessageAsync("terminal@example.com");

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
            """);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(transport.DeliveredCount, Is.EqualTo(1));
            Assert.That(row.SentAt, Is.Null);
            Assert.That(row.FailedAt, Is.EqualTo(_timeProvider.GetUtcNow()));
            Assert.That(row.AttemptCount, Is.Zero);
            Assert.That(row.LastError, Is.Null);
        }
    }

    [Test]
    public async Task DispatcherProcessBatchAsyncDoesNotMarkFailedWhenEmailRowBecomesTerminalAfterFailedDelivery()
    {
        var transport = new TestTransport
        {
            OnDeliver = async (_, _) =>
            {
                await using var connection = await GetDataSource().OpenConnectionAsync(CancellationToken.None);
                await connection.ExecuteAsync("UPDATE ashlar_email_outbox SET discarded_at = @now;", new { now = _timeProvider.GetUtcNow() });
                throw new InvalidOperationException("discarded while delivering");
            }
        };
        var services = new ServiceCollection();
        services.AddSingleton(transport);
        services.AddSingleton(_serviceProvider.GetRequiredService<IPostgresConnectionProvider>());
        var dispatcherProvider = services.BuildServiceProvider();
        await SeedMessageAsync("terminal-failure@example.com");

        var dispatcher = new PostgresEmailOutboxDispatcher<TestTransport>(
            dispatcherProvider,
            _timeProvider,
            Options.Create(new PostgresEmailOutboxOptions()));

        await dispatcher.ProcessBatchAsync(CancellationToken.None);

        await using var connection = await GetDataSource().OpenConnectionAsync();
        var row = await connection.QuerySingleAsync<RawOutboxRow>("""
            SELECT discarded_at AS DiscardedAt, failed_at AS FailedAt, attempt_count AS AttemptCount,
                   last_error AS LastError
            FROM ashlar_email_outbox
            """);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(transport.DeliveredCount, Is.EqualTo(1));
            Assert.That(row.DiscardedAt, Is.EqualTo(_timeProvider.GetUtcNow()));
            Assert.That(row.FailedAt, Is.Null);
            Assert.That(row.AttemptCount, Is.Zero);
            Assert.That(row.LastError, Is.Null);
        }
    }

    [Test]
    public async Task DispatcherProcessBatchAsyncUnprotectsSensitiveBodies()
    {
        var protector = _serviceProvider.GetRequiredService<ISecretProtector>();
        var transport = new TestTransport();
        var services = new ServiceCollection();
        services.AddSingleton(transport);
        services.AddSingleton(_serviceProvider.GetRequiredService<IPostgresConnectionProvider>());
        services.AddSingleton(protector);
        var dispatcherProvider = services.BuildServiceProvider();

        await using (var connection = await GetDataSource().OpenConnectionAsync())
        {
            await connection.ExecuteAsync(
                """
                INSERT INTO ashlar_email_outbox (
                    id, to_address, subject, text_body, html_body, sensitivity, body_protection, created_at, available_at
                ) VALUES (
                    @id, 'protected@example.com', 'Subject', @textBody, @htmlBody, 'ContainsLiveSecret', 'SecretProtector', @now, @now
                )
                """,
                new { id = Guid.NewGuid(), textBody = protector.Protect("Secret text"), htmlBody = protector.Protect("<p>Secret html</p>"), now = _timeProvider.GetUtcNow() });
        }

        var dispatcher = new PostgresEmailOutboxDispatcher<TestTransport>(
            dispatcherProvider,
            _timeProvider,
            Options.Create(new PostgresEmailOutboxOptions()));

        await dispatcher.ProcessBatchAsync(CancellationToken.None);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(transport.Messages.Single().TextBody, Is.EqualTo("Secret text"));
            Assert.That(transport.Messages.Single().HtmlBody, Is.EqualTo("<p>Secret html</p>"));
            Assert.That(transport.Messages.Single().Sensitivity, Is.EqualTo(EmailMessageSensitivity.ContainsLiveSecret));
        }
    }

    [Test]
    public async Task DispatcherProcessBatchAsyncDoesNotDispatchUnknownBodyProtectionAsPlaintext()
    {
        var transport = new TestTransport();
        var services = new ServiceCollection();
        services.AddSingleton(transport);
        services.AddSingleton(_serviceProvider.GetRequiredService<IPostgresConnectionProvider>());
        var dispatcherProvider = services.BuildServiceProvider();

        await using (var connection = await GetDataSource().OpenConnectionAsync())
        {
            await connection.ExecuteAsync("ALTER TABLE ashlar_email_outbox DROP CONSTRAINT ck_ashlar_email_outbox_body_protection;");
            await connection.ExecuteAsync(
                """
                INSERT INTO ashlar_email_outbox (
                    id, to_address, subject, text_body, sensitivity, body_protection, created_at, available_at
                ) VALUES (
                    @id, 'unknown-protection@example.com', 'Subject', 'Plain secret', 'Normal', 'Unknown', @now, @now
                )
                """,
                new { id = Guid.NewGuid(), now = _timeProvider.GetUtcNow() });
        }

        var dispatcher = new PostgresEmailOutboxDispatcher<TestTransport>(
            dispatcherProvider,
            _timeProvider,
            Options.Create(new PostgresEmailOutboxOptions()));

        try
        {
            await dispatcher.ProcessBatchAsync(CancellationToken.None);

            await using var verifyConnection = await GetDataSource().OpenConnectionAsync();
            var row = await verifyConnection.QuerySingleAsync<RawOutboxRow>("SELECT attempt_count AS AttemptCount, last_error AS LastError FROM ashlar_email_outbox");
            using (Assert.EnterMultipleScope())
            {
                Assert.That(transport.DeliveredCount, Is.Zero);
                Assert.That(row.AttemptCount, Is.EqualTo(1));
                Assert.That(row.LastError, Does.Contain("suppressed"));
                Assert.That(row.LastError, Does.Not.Contain("Plain secret"));
            }
        }
        finally
        {
            await using var connection = await GetDataSource().OpenConnectionAsync();
            await connection.ExecuteAsync("UPDATE ashlar_email_outbox SET body_protection = 'None' WHERE body_protection = 'Unknown';");
            await connection.ExecuteAsync("ALTER TABLE ashlar_email_outbox ADD CONSTRAINT ck_ashlar_email_outbox_body_protection CHECK (body_protection IN ('None', 'SecretProtector'));");
        }
    }

    [Test]
    public async Task DispatcherProcessBatchAsyncSuppressesSensitiveFailureDetails()
    {
        var protector = _serviceProvider.GetRequiredService<ISecretProtector>();
        var transport = new TestTransport { OnDeliver = (message, _) => throw new InvalidOperationException(message.TextBody) };
        var services = new ServiceCollection();
        services.AddSingleton(transport);
        services.AddSingleton(_serviceProvider.GetRequiredService<IPostgresConnectionProvider>());
        services.AddSingleton(protector);
        var dispatcherProvider = services.BuildServiceProvider();

        await using (var connection = await GetDataSource().OpenConnectionAsync())
        {
            await connection.ExecuteAsync(
                """
                INSERT INTO ashlar_email_outbox (
                    id, to_address, subject, text_body, sensitivity, body_protection, created_at, available_at
                ) VALUES (
                    @id, 'protected-failure@example.com', 'Subject', @textBody, 'ContainsLiveSecret', 'SecretProtector', @now, @now
                )
                """,
                new { id = Guid.NewGuid(), textBody = protector.Protect("live-token-link"), now = _timeProvider.GetUtcNow() });
        }

        var dispatcher = new PostgresEmailOutboxDispatcher<TestTransport>(
            dispatcherProvider,
            _timeProvider,
            Options.Create(new PostgresEmailOutboxOptions()));

        await dispatcher.ProcessBatchAsync(CancellationToken.None);

        await using var verifyConnection = await GetDataSource().OpenConnectionAsync();
        var row = await verifyConnection.QuerySingleAsync<RawOutboxRow>("SELECT last_error AS LastError FROM ashlar_email_outbox");
        using (Assert.EnterMultipleScope())
        {
            Assert.That(transport.DeliveredCount, Is.EqualTo(1));
            Assert.That(row.LastError, Does.Contain("suppressed"));
            Assert.That(row.LastError, Does.Not.Contain("live-token-link"));
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
            INSERT INTO ashlar_email_outbox (id, to_address, subject, text_body, sensitivity, created_at, available_at, sent_at) VALUES
            (@id1, 'sent@example.com', 'Sub', 'Body', 'Normal', @old, @old, @old),
            (@id2, 'recent-sent@example.com', 'Sub', 'Body', 'Normal', @now, @now, @now);

            INSERT INTO ashlar_email_outbox (id, to_address, subject, text_body, sensitivity, created_at, available_at, failed_at) VALUES
            (@id3, 'failed@example.com', 'Sub', 'Body', 'Normal', @old, @old, @old),
            (@id4, 'recent-failed@example.com', 'Sub', 'Body', 'Normal', @now, @now, @now);
            """, new { id1 = Guid.NewGuid(), id2 = Guid.NewGuid(), id3 = Guid.NewGuid(), id4 = Guid.NewGuid(), now = _now, old });

        var cleanupOptions = new AshlarCleanupOptions
        {
            RemoveSentEmailsAfter = TimeSpan.FromDays(30),
            RemoveFailedEmailsAfter = TimeSpan.FromDays(30)
        };
        await using var connectionProvider = new PostgresTransactionManager(GetDataSource());
        var cleanupService = new PostgresAshlarCleanupService(connectionProvider, _timeProvider, Options.Create(cleanupOptions));

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
        var entry = new EmailOutboxEntry
        {
            Id = Guid.NewGuid(),
            ToAddress = "to@example.com",
            FromAddress = "from@example.com",
            ReplyToAddress = "reply@example.com",
            CcAddress = "cc@example.com",
            BccAddress = "bcc@example.com",
            Subject = "Sub",
            TextBody = "Body",
            Headers = null,
            Metadata = null,
            Sensitivity = EmailMessageSensitivity.Normal
        };

        var message = EmailOutboxDispatch.MapToEmailMessage(entry);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(message.To, Is.EqualTo("to@example.com"));
            Assert.That(message.From, Is.EqualTo("from@example.com"));
            Assert.That(message.ReplyTo, Is.EqualTo("reply@example.com"));
            Assert.That(message.Cc, Is.EqualTo("cc@example.com"));
            Assert.That(message.Bcc, Is.EqualTo("bcc@example.com"));
            Assert.That(message.Headers, Is.Null);
            Assert.That(message.Metadata, Is.Null);
        }
    }

    [Test]
    public void MapToEmailMessageHandlesValidHeadersAndMetadata()
    {
        ISecretProtector protector = new FakeSecretProtector();
        var entry = new EmailOutboxEntry
        {
            Id = Guid.NewGuid(),
            ToAddress = "to@example.com",
            Subject = "Sub",
            TextBody = protector.Protect("Body"),
            Headers = "{\"X-Test\": \"Header\"}",
            Metadata = "{\"Test\": \"Metadata\"}",
            Sensitivity = EmailMessageSensitivity.ContainsLiveSecret,
            BodyProtection = EmailOutboxBodyProtection.SecretProtector
        };

        var message = EmailOutboxDispatch.MapToEmailMessage(entry, protector);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(message.Headers, Is.Not.Null);
            Assert.That(message.Headers, Does.ContainKey("X-Test").WithValue("Header"));
            Assert.That(message.Metadata, Is.Not.Null);
            Assert.That(message.Metadata, Does.ContainKey("Test").WithValue("Metadata"));
            Assert.That(message.Sensitivity, Is.EqualTo(EmailMessageSensitivity.ContainsLiveSecret));
        }
    }

    [Test]
    public void MapToEmailMessageDefaultsUnknownSensitivityToContainsLiveSecret()
    {
        Assert.That(EmailOutboxDispatch.ParseSensitivity("Unknown"), Is.EqualTo(EmailMessageSensitivity.ContainsLiveSecret));
    }

    [Test]
    public void MapToEmailMessageParsesSensitivityCaseInsensitively()
    {
        Assert.That(EmailOutboxDispatch.ParseSensitivity("containslivesecret"), Is.EqualTo(EmailMessageSensitivity.ContainsLiveSecret));
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
        services.AddAshlarPostgresEmailOutboxDispatcher<TestTransport>();
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
        services.AddAshlarPostgresEmailOutboxDispatcher<TestTransport>();
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
        services.AddAshlarPostgresEmailOutboxDispatcher<TestTransport>();
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
        services.AddAshlarPostgresEmailOutboxDispatcher<TestTransport>();
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

        var tcs = new TaskCompletionSource();
        var connectionProvider = new ThrowingConnectionProvider(tcs);

        services.AddSingleton<IPostgresConnectionProvider>(connectionProvider);
        services.AddSingleton<TimeProvider>(_timeProvider);
        services.AddSingleton(new TestTransport());
        services.AddAshlarPostgresEmailOutboxDispatcher<TestTransport>();
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
            Assert.That(connectionProvider.CallCount, Is.AtLeast(3));
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
            "INSERT INTO ashlar_email_outbox (id, to_address, subject, text_body, sensitivity, created_at, available_at) VALUES (@id, @to, 'Subject', 'Body', 'Normal', @now, @now)",
            new { id = Guid.NewGuid(), to, now = _timeProvider.GetUtcNow() });
    }

    private async Task ExpireSingleEmailLockAsync()
    {
        await using var connection = await GetDataSource().OpenConnectionAsync();
        await connection.ExecuteAsync(
            "UPDATE ashlar_email_outbox SET locked_until = @LockedUntil",
            new { LockedUntil = _timeProvider.GetUtcNow().AddMinutes(-1) });
    }

    private async Task<RawOutboxRow> QuerySingleEmailDispatchStateAsync()
    {
        await using var connection = await GetDataSource().OpenConnectionAsync();
        return await connection.QuerySingleAsync<RawOutboxRow>("""
            SELECT sent_at AS SentAt, attempt_count AS AttemptCount, locked_by AS LockedBy
            FROM ashlar_email_outbox
            """);
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

    private sealed class BlockingEmailTransport(
        TaskCompletionSource firstDeliveryStarted,
        TaskCompletionSource secondDeliveryStarted,
        TaskCompletionSource releaseFirstDelivery,
        TaskCompletionSource releaseSecondDelivery)
        : IEmailTransport
    {
        private int _deliveredCount;

        public int DeliveredCount => _deliveredCount;

        public async Task DeliverAsync(EmailMessage message, CancellationToken cancellationToken = default)
        {
            if (Interlocked.Increment(ref _deliveredCount) == 1)
            {
                firstDeliveryStarted.TrySetResult();
                await releaseFirstDelivery.Task.WaitAsync(cancellationToken);
                return;
            }

            secondDeliveryStarted.TrySetResult();
            await releaseSecondDelivery.Task.WaitAsync(cancellationToken);
        }
    }

    private sealed class ThrowingConnectionProvider(TaskCompletionSource afterThirdCall) : IPostgresConnectionProvider
    {
        private int _callCount;

        public int CallCount => _callCount;

        public async ValueTask<PostgresConnectionHandle> GetConnectionAsync(CancellationToken cancellationToken)
        {
            if (Interlocked.Increment(ref _callCount) >= 3)
            {
                afterThirdCall.TrySetResult();
            }

            await Task.Yield();
            throw new InvalidOperationException("DB Down");
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

    public sealed class RawOutboxRow
    {
        public DateTimeOffset CreatedAt { get; set; }
        public required string ToAddress { get; set; }
        public string? FromAddress { get; set; }
        public string? ReplyToAddress { get; set; }
        public string? CcAddress { get; set; }
        public string? BccAddress { get; set; }
        public required string Subject { get; set; }
        public string? TextBody { get; set; }
        public string? HtmlBody { get; set; }
        public string? Sensitivity { get; set; }
        public string? BodyProtection { get; set; }
        public string? Headers { get; set; }
        public string? Metadata { get; set; }
        public int AttemptCount { get; set; }
        public DateTimeOffset? SentAt { get; set; }
        public DateTimeOffset? FailedAt { get; set; }
        public DateTimeOffset? DiscardedAt { get; set; }
        public string? LastError { get; set; }
        public DateTimeOffset? LastAttemptAt { get; set; }
        public DateTimeOffset AvailableAt { get; set; }
        public string? LockedBy { get; set; }
    }
}
