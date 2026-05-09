namespace Ashlar.Identity.Notifications;

public sealed record SecurityNotificationTemplate
{
    public required string Subject { get; init; }
    public required string Body { get; init; }
}
