using Ashlar.Identity.Models;

namespace Ashlar.Identity.Notifications;

/// <summary>
/// Represents the security notification data model.
/// </summary>
public sealed record SecurityNotification
{
    /// <summary>
    /// Gets or sets the type value.
    /// </summary>
    public required SecurityNotificationType Type { get; init; }
    /// <summary>
    /// Gets or sets the recipient email value.
    /// </summary>
    public required string RecipientEmail { get; init; }
    /// <summary>
    /// Gets or sets the occurred at value.
    /// </summary>
    public required DateTimeOffset OccurredAt { get; init; }
    /// <summary>
    /// Gets or sets the ip address value.
    /// </summary>
    public string? IpAddress { get; init; }
    /// <summary>
    /// Gets or sets the user agent value.
    /// </summary>
    public string? UserAgent { get; init; }
    /// <summary>
    /// Gets or sets the session id value.
    /// </summary>
    public Guid? SessionId { get; init; }
    /// <summary>
    /// Gets or sets the metadata value.
    /// </summary>
    public IReadOnlyDictionary<string, string>? Metadata { get; init; }

    /// <summary>
    /// Creates a security notification from an authentication context.
    /// </summary>
    /// <param name="type">The notification type.</param>
    /// <param name="recipientEmail">The recipient email address.</param>
    /// <param name="occurredAt">The occurrence time.</param>
    /// <param name="context">The authentication context.</param>
    /// <param name="sessionId">The session id value.</param>
    /// <param name="metadata">The metadata value.</param>
    /// <returns>The created security notification.</returns>
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
