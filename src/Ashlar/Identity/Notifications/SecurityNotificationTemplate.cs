namespace Ashlar.Identity.Notifications;

/// <summary>
/// Represents the security notification template data model.
/// </summary>
public sealed record SecurityNotificationTemplate
{
    /// <summary>
    /// Gets or sets the subject value.
    /// </summary>
    public required string Subject { get; init; }
    /// <summary>
    /// Gets or sets the body value.
    /// </summary>
    public required string Body { get; init; }
}
