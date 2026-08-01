using Ashlar.Messaging;

namespace Ashlar.ProviderContractTests.Messaging;

/// <summary>Captures delivered messages for email outbox assertions.</summary>
public sealed class RecordingEmailTransport : IEmailTransport
{
    private readonly List<EmailMessage> _messages = [];

    /// <summary>Optional callback invoked for each captured delivery.</summary>
    public Func<EmailMessage, CancellationToken, Task> OnDeliver { get; set; } = (_, _) => Task.CompletedTask;

    /// <summary>Messages captured since the last reset.</summary>
    public IReadOnlyList<EmailMessage> Messages => _messages;

    /// <summary>Number of messages captured since the last reset.</summary>
    public int DeliveredCount => _messages.Count;

    /// <summary>Clears captured messages and delivery callbacks.</summary>
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
