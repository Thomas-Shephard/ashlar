using Ashlar.Messaging;

namespace Ashlar.Tests.Identity.Features.Email;

internal sealed class TransactionalEmailDeliveryTests
{
    private static readonly string[] SendBeforeCommitEvents = ["send"];
    private static readonly string[] DurableCommitEvents = ["send", "commit"];
    private static readonly string[] DirectCommitEvents = ["commit", "send"];

    [Test]
    public async Task TransactionalDurableOutboxSenderIsCalledBeforeCommit()
    {
        var events = new List<string>();
        var sender = new RecordingTransactionalOutboxSender(events);
        var transaction = new RecordingTransaction(events);
        var message = SensitiveMessage();

        await TransactionalEmailDelivery.SendOrRegisterPostCommitAsync(sender, transaction, message, CancellationToken.None);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(events, Is.EqualTo(SendBeforeCommitEvents));
            Assert.That(sender.Messages.Single().Sensitivity, Is.EqualTo(EmailMessageSensitivity.ContainsLiveSecret));
            Assert.That(sender.Messages.Single().Metadata, Is.Null);
        }

        await transaction.CommitAsync();

        Assert.That(events, Is.EqualTo(DurableCommitEvents));
    }

    [Test]
    public async Task NonTransactionalSenderIsCalledAfterCommit()
    {
        var events = new List<string>();
        var sender = new RecordingEmailSender(events);
        var transaction = new RecordingTransaction(events);

        await TransactionalEmailDelivery.SendOrRegisterPostCommitAsync(sender, transaction, SensitiveMessage(), CancellationToken.None);

        Assert.That(events, Is.Empty);

        await transaction.CommitAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(events, Is.EqualTo(DirectCommitEvents));
            Assert.That(sender.Messages.Single().Sensitivity, Is.EqualTo(EmailMessageSensitivity.ContainsLiveSecret));
            Assert.That(sender.Messages.Single().Metadata, Is.Null);
        }
    }

    private static EmailMessage SensitiveMessage()
    {
        return new EmailMessage(
            "user@example.com",
            "Subject",
            "secret-token",
            options: new EmailMessageOptions { Sensitivity = EmailMessageSensitivity.ContainsLiveSecret });
    }

    private class RecordingEmailSender(List<string> events) : IEmailSender
    {
        public List<EmailMessage> Messages { get; } = [];

        public Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
        {
            events.Add("send");
            Messages.Add(message);
            return Task.CompletedTask;
        }
    }

    private sealed class RecordingTransactionalOutboxSender(List<string> events)
        : RecordingEmailSender(events), ITransactionalEmailOutboxSender;

    private sealed class RecordingTransaction(List<string> events) : IAshlarTransaction
    {
        private readonly List<Func<CancellationToken, Task>> _hooks = [];

        public async Task CommitAsync(CancellationToken cancellationToken = default)
        {
            events.Add("commit");
            foreach (var hook in _hooks)
            {
                await hook(cancellationToken);
            }
        }

        public Task RollbackAsync(CancellationToken cancellationToken = default)
        {
            _hooks.Clear();
            return Task.CompletedTask;
        }

        public void OnCommitted(Func<CancellationToken, Task> action)
        {
            _hooks.Add(action);
        }

        public ValueTask DisposeAsync()
        {
            return ValueTask.CompletedTask;
        }
    }
}
