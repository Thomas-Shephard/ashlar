using Ashlar.Messaging;

namespace Ashlar.ProviderContractTests.Messaging;

internal sealed class RecordingEmailTransport : IEmailTransport
{
    private readonly List<EmailMessage> _messages = [];

    public Func<EmailMessage, CancellationToken, Task> OnDeliver { get; set; } = (_, _) => Task.CompletedTask;

    public IReadOnlyList<EmailMessage> Messages => _messages;

    public int DeliveredCount => _messages.Count;

    public void Clear()
    {
        _messages.Clear();
        OnDeliver = (_, _) => Task.CompletedTask;
    }

    public async Task DeliverAsync(EmailMessage message, CancellationToken cancellationToken = default)
    {
        _messages.Add(message);
        await OnDeliver(message, cancellationToken);
    }
}
