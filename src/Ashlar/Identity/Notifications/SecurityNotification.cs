namespace Ashlar.Identity.Notifications;

/// <summary>
/// Describes a security-sensitive account event that may be sent to a user.
/// </summary>
public sealed record SecurityNotification
{
    /// <summary>
    /// Kind of account event being reported.
    /// </summary>
    public required SecurityNotificationType Type { get; init; }
    /// <summary>
    /// Email address that should receive the notification.
    /// </summary>
    public required string RecipientEmail { get; init; }
    /// <summary>
    /// UTC time when the event occurred.
    /// </summary>
    public required DateTimeOffset OccurredAt { get; init; }
    /// <summary>
    /// Client IP address to include when configured. Treat as personal data.
    /// </summary>
    public string? IpAddress { get; init; }
    /// <summary>
    /// Client user-agent text to include when configured. It may be user supplied.
    /// </summary>
    public string? UserAgent { get; init; }
    /// <summary>
    /// Related application session identifier, when the event concerns a session.
    /// </summary>
    public Guid? SessionId { get; init; }
    /// <summary>
    /// Optional event metadata for templates and delivery decisions. Do not include secrets.
    /// </summary>
    public IReadOnlyDictionary<string, string>? Metadata { get; init; }

    /// <summary>
    /// Creates a security notification from an authentication context.
    /// </summary>
    /// <param name="type">Kind of account event being reported.</param>
    /// <param name="recipientEmail">The recipient email address.</param>
    /// <param name="occurredAt">UTC time when the account event occurred.</param>
    /// <param name="context">Authentication context used to copy client IP address and user-agent values into the notification.</param>
    /// <param name="sessionId">Related application session identifier, when available.</param>
    /// <param name="metadata">Optional event metadata. Do not include secrets.</param>
    /// <returns>Security notification populated with request context values when available.</returns>
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
