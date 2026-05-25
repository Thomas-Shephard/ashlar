using Ashlar.Messaging;

namespace Ashlar.ProviderContractTests.Messaging;

internal abstract class EmailOutboxContractTests : ProviderContractFixture
{
    private static readonly TimeSpan RetryDelay = TimeSpan.FromMinutes(1);
    private static readonly string[] RetryableRecipients = ["retryable@example.com", "retryable@example.com"];

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
    public async Task SendAsyncEnqueuesSensitivityThatDispatcherRestores()
    {
        await using var scope = CreateAsyncScope();
        var transport = GetRecordingEmailTransport(scope.ServiceProvider);
        var message = new EmailMessage(
            "contract-sensitive@example.com",
            "Subject",
            "Secret text",
            options: new EmailMessageOptions { Sensitivity = EmailMessageSensitivity.ContainsLiveSecret });

        await GetEmailSender(scope.ServiceProvider).SendAsync(message);
        await GetEmailOutboxDispatcher(scope.ServiceProvider).ProcessBatchAsync();

        Assert.That(transport.Messages.Single().Sensitivity, Is.EqualTo(EmailMessageSensitivity.ContainsLiveSecret));
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

        await sender.SendAsync(new EmailMessage("once@example.com", "Subject", "Text"));

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

        await sender.SendAsync(new EmailMessage("batch-one@example.com", "Subject", "Text"));
        await sender.SendAsync(new EmailMessage("batch-two@example.com", "Subject", "Text"));
        await sender.SendAsync(new EmailMessage("batch-three@example.com", "Subject", "Text"));

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

        await sender.SendAsync(new EmailMessage("retryable@example.com", "Subject", "Text"));

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
    public async Task EnqueueParticipatesInAshlarTransactions()
    {
        await using var scope = CreateAsyncScope();
        var transactionProvider = GetTransactionProvider(scope.ServiceProvider)
            ?? throw new InvalidOperationException("Transaction provider is not registered.");
        var sender = GetEmailSender(scope.ServiceProvider);
        var dispatcher = GetEmailOutboxDispatcher(scope.ServiceProvider);

        await using (var transaction = await transactionProvider.BeginTransactionAsync())
        {
            await sender.SendAsync(new EmailMessage("rollback@example.com", "Subject", "Text"));
            await transaction.RollbackAsync();
        }

        Assert.That(await dispatcher.ProcessBatchAsync(), Is.Zero);

        await using (var transaction = await transactionProvider.BeginTransactionAsync())
        {
            await sender.SendAsync(new EmailMessage("commit@example.com", "Subject", "Text"));
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
            "Contract Subject",
            "Plain text body",
            "<p>HTML body</p>",
            new EmailMessageOptions
            {
                From = "from@example.com",
                ReplyTo = "reply@example.com",
                Headers = new Dictionary<string, string> { ["X-Test"] = "Header" },
                Metadata = new Dictionary<string, string> { ["Trace"] = "Metadata" },
                Sensitivity = EmailMessageSensitivity.ContainsLiveSecret
            });
    }

    private static void AssertEmailMessage(EmailMessage actual, EmailMessage expected)
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(actual.To, Is.EqualTo(expected.To));
            Assert.That(actual.From, Is.EqualTo(expected.From));
            Assert.That(actual.ReplyTo, Is.EqualTo(expected.ReplyTo));
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
}
