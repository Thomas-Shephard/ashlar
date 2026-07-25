using Ashlar.Messaging;

namespace Ashlar.ProviderContractTests.Messaging;

internal abstract class EmailOutboxContractTests : ProviderContractFixture
{
    protected static readonly DateTimeOffset ContractNow = new(2026, 5, 8, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan RetryDelay = TimeSpan.FromMinutes(1);
    private static readonly string[] RetryableRecipients = ["retryable@example.com", "retryable@example.com"];
    private const string SensitiveTextBody = "Reset token: live-token-text";
    private const string SensitiveHtmlBody = "<p>Reset token: live-token-html</p>";

    protected abstract Task<EmailOutboxRowState> ReadSingleEmailOutboxRowAsync();

    protected abstract Task SeedEmailOutboxRowAsync(SeedEmailOutboxRow row);

    protected abstract Task SeedUnknownBodyProtectionEmailOutboxRowAsync(SeedEmailOutboxRow row);

    [Test]
    public async Task SendAsyncEnqueuesMessageThatDispatcherDeliversWithEnvelopeBodyHeadersAndMetadata()
    {
        await using var scope = CreateAsyncScope();
        var transport = GetRecordingEmailTransport(scope.ServiceProvider);
        var message = CreateRichMessage("contract-rich@example.com");

        await GetEmailSender(scope.ServiceProvider).SendAsync(message);
        var count = await GetEmailOutboxDispatcher(scope.ServiceProvider).ProcessBatchAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(count, Is.EqualTo(1));
            Assert.That(transport.Messages, Has.Count.EqualTo(1));
        }

        AssertEmailMessage(transport.Messages.Single(), message);
    }

    [Test]
    public async Task NormalEmailPersistsWithNormalSensitivityAndNoBodyProtection()
    {
        await using var scope = CreateAsyncScope();
        var message = new EmailMessage("contract-normal@example.com", "Subject", EmailMessageSensitivity.Normal, "Normal text", "<p>Normal html</p>");

        await GetEmailSender(scope.ServiceProvider).SendAsync(message);

        var row = await ReadSingleEmailOutboxRowAsync();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(row.Sensitivity, Is.EqualTo(nameof(EmailMessageSensitivity.Normal)));
            Assert.That(row.BodyProtection, Is.EqualTo(nameof(EmailOutboxBodyProtection.None)));
            Assert.That(row.TextBody, Is.EqualTo("Normal text"));
            Assert.That(row.HtmlBody, Is.EqualTo("<p>Normal html</p>"));
        }
    }

    [Test]
    public async Task SensitiveEmailPersistsProtectedBodiesAndDispatcherRestoresThem()
    {
        await using var scope = CreateAsyncScope();
        var transport = GetRecordingEmailTransport(scope.ServiceProvider);
        var message = new EmailMessage(
            "contract-sensitive@example.com",
            "Subject", EmailMessageSensitivity.ContainsLiveSecret,
            SensitiveTextBody,
            SensitiveHtmlBody);

        await GetEmailSender(scope.ServiceProvider).SendAsync(message);
        var row = await ReadSingleEmailOutboxRowAsync();
        var count = await GetEmailOutboxDispatcher(scope.ServiceProvider).ProcessBatchAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(row.Sensitivity, Is.EqualTo(nameof(EmailMessageSensitivity.ContainsLiveSecret)));
            Assert.That(row.BodyProtection, Is.EqualTo(nameof(EmailOutboxBodyProtection.SecretProtector)));
            Assert.That(row.TextBody, Does.Not.Contain(SensitiveTextBody));
            Assert.That(row.TextBody, Does.Not.Contain("live-token-text"));
            Assert.That(row.HtmlBody, Does.Not.Contain(SensitiveHtmlBody));
            Assert.That(row.HtmlBody, Does.Not.Contain("live-token-html"));
            Assert.That(count, Is.EqualTo(1));
            Assert.That(transport.Messages.Single().TextBody, Is.EqualTo(SensitiveTextBody));
            Assert.That(transport.Messages.Single().HtmlBody, Is.EqualTo(SensitiveHtmlBody));
            Assert.That(transport.Messages.Single().Sensitivity, Is.EqualTo(EmailMessageSensitivity.ContainsLiveSecret));
        }
    }

    [Test]
    public async Task EmailOutboxSenderAdvertisesTransactionalDurableOutbox()
    {
        await using var scope = CreateAsyncScope();

        Assert.That(GetEmailSender(scope.ServiceProvider), Is.InstanceOf<ITransactionalEmailOutboxSender>());
    }

    [Test]
    public async Task ProcessBatchAsyncReturnsZeroWhenThereIsNoWork()
    {
        await using var scope = CreateAsyncScope();

        var count = await GetEmailOutboxDispatcher(scope.ServiceProvider).ProcessBatchAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(count, Is.Zero);
            Assert.That(GetRecordingEmailTransport(scope.ServiceProvider).DeliveredCount, Is.Zero);
        }
    }

    [Test]
    public async Task SuccessfulDispatchDoesNotResendMessageOnLaterBatch()
    {
        await using var scope = CreateAsyncScope();
        var sender = GetEmailSender(scope.ServiceProvider);
        var dispatcher = GetEmailOutboxDispatcher(scope.ServiceProvider);
        var transport = GetRecordingEmailTransport(scope.ServiceProvider);

        await sender.SendAsync(new EmailMessage("once@example.com", "Subject", EmailMessageSensitivity.Normal, "Text"));

        var first = await dispatcher.ProcessBatchAsync();
        var second = await dispatcher.ProcessBatchAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(first, Is.EqualTo(1));
            Assert.That(second, Is.Zero);
            Assert.That(transport.DeliveredCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task ProcessBatchAsyncRespectsConfiguredBatchSize()
    {
        await using var scope = CreateAsyncScope();
        var sender = GetEmailSender(scope.ServiceProvider);
        var dispatcher = GetEmailOutboxDispatcher(scope.ServiceProvider);
        var transport = GetRecordingEmailTransport(scope.ServiceProvider);

        await sender.SendAsync(new EmailMessage("batch-one@example.com", "Subject", EmailMessageSensitivity.Normal, "Text"));
        await sender.SendAsync(new EmailMessage("batch-two@example.com", "Subject", EmailMessageSensitivity.Normal, "Text"));
        await sender.SendAsync(new EmailMessage("batch-three@example.com", "Subject", EmailMessageSensitivity.Normal, "Text"));

        var count = await dispatcher.ProcessBatchAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(count, Is.EqualTo(2));
            Assert.That(transport.DeliveredCount, Is.EqualTo(2));
        }
    }

    [Test]
    public async Task FailedDeliveryRemainsRetryableAfterRetryDelay()
    {
        await using var scope = CreateAsyncScope();
        var sender = GetEmailSender(scope.ServiceProvider);
        var dispatcher = GetEmailOutboxDispatcher(scope.ServiceProvider);
        var transport = GetRecordingEmailTransport(scope.ServiceProvider);
        var failed = false;
        transport.OnDeliver = (_, _) =>
        {
            if (!failed)
            {
                failed = true;
                throw new InvalidOperationException("Delivery failed");
            }

            return Task.CompletedTask;
        };

        await sender.SendAsync(new EmailMessage("retryable@example.com", "Subject", EmailMessageSensitivity.Normal, "Text"));

        var first = await dispatcher.ProcessBatchAsync();
        await AdvanceEmailOutboxTimeAsync(RetryDelay);
        var second = await dispatcher.ProcessBatchAsync();
        var third = await dispatcher.ProcessBatchAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(first, Is.EqualTo(1));
            Assert.That(second, Is.EqualTo(1));
            Assert.That(third, Is.Zero);
            Assert.That(transport.DeliveredCount, Is.EqualTo(2));
            Assert.That(transport.Messages.Select(message => message.To), Is.EqualTo(RetryableRecipients));
        }
    }

    [Test]
    public async Task SensitiveProtectedMessageFailsSafeWhenBodyCannotBeRestored()
    {
        await using var scope = CreateAsyncScope();
        await SeedEmailOutboxRowAsync(SeedEmailOutboxRow.Pending(
            textBody: CreateMalformedProtectedBody(SensitiveTextBody),
            htmlBody: CreateMalformedProtectedBody(SensitiveHtmlBody),
            sensitivity: nameof(EmailMessageSensitivity.ContainsLiveSecret),
            bodyProtection: nameof(EmailOutboxBodyProtection.SecretProtector)));

        var count = await GetEmailOutboxDispatcher(scope.ServiceProvider).ProcessBatchAsync();
        var row = await ReadSingleEmailOutboxRowAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(count, Is.EqualTo(1));
            Assert.That(GetRecordingEmailTransport(scope.ServiceProvider).DeliveredCount, Is.Zero);
            Assert.That(row.AttemptCount, Is.EqualTo(1));
            AssertFailureDetailsSuppressed(row.LastError);
        }
    }

    [Test]
    public async Task UnknownBodyProtectionFailsSafeWithoutDispatchingPlaintext()
    {
        await using var scope = CreateAsyncScope();
        await SeedUnknownBodyProtectionEmailOutboxRowAsync(SeedEmailOutboxRow.Pending(
            textBody: SensitiveTextBody,
            htmlBody: SensitiveHtmlBody,
            bodyProtection: "Unknown"));

        var count = await GetEmailOutboxDispatcher(scope.ServiceProvider).ProcessBatchAsync();
        var row = await ReadSingleEmailOutboxRowAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(count, Is.EqualTo(1));
            Assert.That(GetRecordingEmailTransport(scope.ServiceProvider).DeliveredCount, Is.Zero);
            Assert.That(row.AttemptCount, Is.EqualTo(1));
            AssertFailureDetailsSuppressed(row.LastError);
        }
    }

    [Test]
    public async Task SensitiveDispatchFailureSuppressesStoredExceptionDetail()
    {
        await using var scope = CreateAsyncScope();
        var transport = GetRecordingEmailTransport(scope.ServiceProvider);
        transport.OnDeliver = (message, _) => throw new InvalidOperationException($"Failed to deliver {message.TextBody} {message.HtmlBody}");
        var message = new EmailMessage(
            "contract-sensitive-failure@example.com",
            "Subject", EmailMessageSensitivity.ContainsLiveSecret,
            SensitiveTextBody,
            SensitiveHtmlBody);

        await GetEmailSender(scope.ServiceProvider).SendAsync(message);
        var count = await GetEmailOutboxDispatcher(scope.ServiceProvider).ProcessBatchAsync();
        var row = await ReadSingleEmailOutboxRowAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(count, Is.EqualTo(1));
            Assert.That(transport.DeliveredCount, Is.EqualTo(1));
            Assert.That(row.AttemptCount, Is.EqualTo(1));
            AssertFailureDetailsSuppressed(row.LastError);
        }
    }

    [Test]
    public async Task DiagnosticsExposeOnlyAggregateSensitiveCounts()
    {
        await SeedEmailOutboxRowAsync(SeedEmailOutboxRow.Pending(
            toAddress: "sensitive-pending@example.com",
            textBody: SensitiveTextBody,
            sensitivity: nameof(EmailMessageSensitivity.ContainsLiveSecret),
            bodyProtection: nameof(EmailOutboxBodyProtection.SecretProtector)));
        await SeedEmailOutboxRowAsync(SeedEmailOutboxRow.Pending(
            toAddress: "sensitive-scheduled@example.com",
            textBody: SensitiveHtmlBody,
            availableAt: ContractNow.AddMinutes(5),
            sensitivity: nameof(EmailMessageSensitivity.ContainsLiveSecret),
            bodyProtection: nameof(EmailOutboxBodyProtection.SecretProtector)));
        await SeedEmailOutboxRowAsync(SeedEmailOutboxRow.Pending(
            toAddress: "sensitive-locked@example.com",
            textBody: "locked live-token",
            lockedBy: "worker",
            lockedUntil: ContractNow.AddMinutes(5),
            sensitivity: nameof(EmailMessageSensitivity.ContainsLiveSecret),
            bodyProtection: nameof(EmailOutboxBodyProtection.SecretProtector)));
        await SeedEmailOutboxRowAsync(SeedEmailOutboxRow.Failed(
            textBody: "failed live-token",
            sensitivity: nameof(EmailMessageSensitivity.ContainsLiveSecret),
            bodyProtection: nameof(EmailOutboxBodyProtection.SecretProtector),
            lastError: "suppressed"));
        await using var scope = CreateAsyncScope();

        var result = await GetEmailOutboxDiagnostics(scope.ServiceProvider).CheckAsync();
        var rendered = result.ToString();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.SensitivePendingCount, Is.EqualTo(1));
            Assert.That(result.SensitiveScheduledCount, Is.EqualTo(1));
            Assert.That(result.SensitiveLockedCount, Is.EqualTo(1));
            Assert.That(result.SensitiveFailedCount, Is.EqualTo(1));
            Assert.That(rendered, Does.Not.Contain(SensitiveTextBody));
            Assert.That(rendered, Does.Not.Contain(SensitiveHtmlBody));
            Assert.That(rendered, Does.Not.Contain("live-token"));
            Assert.That(rendered, Does.Not.Contain("sensitive-pending@example.com"));
            Assert.That(rendered, Does.Not.Contain("sensitive-scheduled@example.com"));
            Assert.That(rendered, Does.Not.Contain("sensitive-locked@example.com"));
        }
    }

    [Test]
    public async Task EnqueueParticipatesInAshlarTransactions()
    {
        await using var scope = CreateAsyncScope();
        var transactionProvider = GetTransactionProvider(scope.ServiceProvider)
            ?? throw new InvalidOperationException("Transaction provider is not registered.");
        var sender = GetEmailSender(scope.ServiceProvider);
        var dispatcher = GetEmailOutboxDispatcher(scope.ServiceProvider);

        await using (var transaction = await transactionProvider.BeginTransactionAsync())
        {
            await sender.SendAsync(new EmailMessage("rollback@example.com", "Subject", EmailMessageSensitivity.Normal, "Text"));
            await transaction.RollbackAsync();
        }

        Assert.That(await dispatcher.ProcessBatchAsync(), Is.Zero);

        await using (var transaction = await transactionProvider.BeginTransactionAsync())
        {
            await sender.SendAsync(new EmailMessage("commit@example.com", "Subject", EmailMessageSensitivity.Normal, "Text"));
            await transaction.CommitAsync();
        }

        using (Assert.EnterMultipleScope())
        {
            Assert.That(await dispatcher.ProcessBatchAsync(), Is.EqualTo(1));
            Assert.That(GetRecordingEmailTransport(scope.ServiceProvider).Messages.Single().To, Is.EqualTo("commit@example.com"));
        }
    }

    private static EmailMessage CreateRichMessage(string to)
    {
        return new EmailMessage(
            to,
            "Contract Subject", EmailMessageSensitivity.ContainsLiveSecret,
            "Plain text body",
            "<p>HTML body</p>",
            new EmailMessageOptions
            {
                From = "from@example.com",
                ReplyTo = "reply@example.com",
                Cc = "cc@example.com",
                Bcc = "bcc@example.com",
                Headers = new Dictionary<string, string> { ["X-Test"] = "Header" },
                Metadata = new Dictionary<string, string> { ["Trace"] = "Metadata" },
            });
    }

    private static void AssertEmailMessage(EmailMessage actual, EmailMessage expected)
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(actual.To, Is.EqualTo(expected.To));
            Assert.That(actual.From, Is.EqualTo(expected.From));
            Assert.That(actual.ReplyTo, Is.EqualTo(expected.ReplyTo));
            Assert.That(actual.Cc, Is.EqualTo(expected.Cc));
            Assert.That(actual.Bcc, Is.EqualTo(expected.Bcc));
            Assert.That(actual.Subject, Is.EqualTo(expected.Subject));
            Assert.That(actual.TextBody, Is.EqualTo(expected.TextBody));
            Assert.That(actual.HtmlBody, Is.EqualTo(expected.HtmlBody));
            Assert.That(actual.Headers, Is.Not.Null);
            Assert.That(actual.Headers, Does.ContainKey("X-Test").WithValue("Header"));
            Assert.That(actual.Metadata, Is.Not.Null);
            Assert.That(actual.Metadata, Does.ContainKey("Trace").WithValue("Metadata"));
            Assert.That(actual.Sensitivity, Is.EqualTo(expected.Sensitivity));
        }
    }

    private static void AssertFailureDetailsSuppressed(string? lastError)
    {
        Assert.That(lastError, Does.Contain("suppressed"));
        Assert.That(lastError, Does.Not.Contain(SensitiveTextBody));
        Assert.That(lastError, Does.Not.Contain(SensitiveHtmlBody));
        Assert.That(lastError, Does.Not.Contain("live-token"));
    }

    private static string CreateMalformedProtectedBody(string body)
    {
        return Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"unprotected:{body}"));
    }

    protected sealed record SeedEmailOutboxRow(
        string ToAddress,
        string Subject,
        string? TextBody,
        string? HtmlBody,
        string Sensitivity,
        string BodyProtection,
        DateTimeOffset CreatedAt,
        DateTimeOffset AvailableAt,
        DateTimeOffset? FailedAt,
        string? LockedBy,
        DateTimeOffset? LockedUntil,
        int AttemptCount,
        string? LastError)
    {
        public Guid Id { get; } = Guid.NewGuid();

        public static SeedEmailOutboxRow Pending(
            string toAddress = "seeded@example.com",
            string subject = "Subject",
            string? textBody = "Body",
            string? htmlBody = null,
            DateTimeOffset? createdAt = null,
            DateTimeOffset? availableAt = null,
            string sensitivity = nameof(EmailMessageSensitivity.Normal),
            string bodyProtection = nameof(EmailOutboxBodyProtection.None),
            string? lockedBy = null,
            DateTimeOffset? lockedUntil = null)
        {
            return new SeedEmailOutboxRow(
                toAddress,
                subject,
                textBody,
                htmlBody,
                sensitivity,
                bodyProtection,
                createdAt ?? ContractNow,
                availableAt ?? ContractNow,
                null,
                lockedBy,
                lockedUntil,
                0,
                null);
        }

        public static SeedEmailOutboxRow Failed(
            string toAddress = "failed@example.com",
            string subject = "Subject",
            string? textBody = "Body",
            string? htmlBody = null,
            DateTimeOffset? createdAt = null,
            DateTimeOffset? availableAt = null,
            DateTimeOffset? failedAt = null,
            string sensitivity = nameof(EmailMessageSensitivity.Normal),
            string bodyProtection = nameof(EmailOutboxBodyProtection.None),
            string? lastError = "failure")
        {
            return new SeedEmailOutboxRow(
                toAddress,
                subject,
                textBody,
                htmlBody,
                sensitivity,
                bodyProtection,
                createdAt ?? ContractNow,
                availableAt ?? ContractNow,
                failedAt ?? ContractNow.AddMinutes(-1),
                null,
                null,
                1,
                lastError);
        }
    }

    protected sealed record EmailOutboxRowState(
        string? TextBody,
        string? HtmlBody,
        string Sensitivity,
        string BodyProtection,
        int AttemptCount,
        string? LastError);
}
