using Ashlar.Identity.Models;

namespace Ashlar.Identity.Notifications;

public sealed record SecurityNotification
{
    public required SecurityNotificationType Type { get; init; }
    public required string RecipientEmail { get; init; }
    public required DateTimeOffset OccurredAt { get; init; }
    public string? IpAddress { get; init; }
    public string? UserAgent { get; init; }
    public Guid? SessionId { get; init; }
    public IReadOnlyDictionary<string, string>? Metadata { get; init; }

    public static SecurityNotification FromContext(
        SecurityNotificationType type,
        string recipientEmail,
        DateTimeOffset occurredAt,
        AuthenticationContext? context = null,
        Guid? sessionId = null,
        IReadOnlyDictionary<string, string>? metadata = null)
    {
        return new SecurityNotification
        {
            Type = type,
            RecipientEmail = recipientEmail,
            OccurredAt = occurredAt,
            IpAddress = context?.IpAddress,
            UserAgent = context?.UserAgent,
            SessionId = sessionId,
            Metadata = metadata
        };
    }
}
