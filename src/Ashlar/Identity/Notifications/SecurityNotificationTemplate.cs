namespace Ashlar.Identity.Notifications;

/// <summary>
/// Defines subject and body text for a security notification.
/// </summary>
public sealed record SecurityNotificationTemplate
{
    /// <summary>
    /// Email subject template. Do not include secrets or credential values.
    /// </summary>
    public required string Subject { get; init; }
    /// <summary>
    /// Email body template. Do not include secrets or credential values in rendered output.
    /// </summary>
    public required string Body { get; init; }
}
