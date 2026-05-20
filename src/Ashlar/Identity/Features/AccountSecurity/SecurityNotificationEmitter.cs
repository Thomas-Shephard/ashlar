using Ashlar.Identity.Notifications;

namespace Ashlar.Identity.Features.AccountSecurity;

/// <summary>
/// Provides security notification emitter behavior.
/// </summary>
/// <param name="notificationService">The notification service value.</param>
public sealed class SecurityNotificationEmitter(ISecurityNotificationService? notificationService)
{
    /// <summary>
    /// Sends a security notification to a user.
    /// </summary>
    /// <param name="type">The notification type.</param>
    /// <param name="user">The recipient user.</param>
    /// <param name="occurredAt">The occurrence time.</param>
    /// <param name="context">The authentication context.</param>
    /// <param name="sessionId">The session id value.</param>
    /// <param name="metadata">The metadata value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task NotifyAsync(
        SecurityNotificationType type,
        IUser user,
        DateTimeOffset occurredAt,
        AuthenticationContext? context = null,
        Guid? sessionId = null,
        IReadOnlyDictionary<string, string>? metadata = null,
        CancellationToken cancellationToken = default)
    {
        if (notificationService == null) return;

        await notificationService.NotifyAsync(new SecurityNotification
        {
            Type = type,
            RecipientEmail = user.Email,
            OccurredAt = occurredAt,
            IpAddress = context?.IpAddress,
            UserAgent = context?.UserAgent,
            SessionId = sessionId,
            Metadata = metadata
        }, cancellationToken);
    }

    /// <summary>
    /// Sends a security notification to an email recipient.
    /// </summary>
    /// <param name="type">The notification type.</param>
    /// <param name="recipientEmail">The recipient email address.</param>
    /// <param name="occurredAt">The occurrence time.</param>
    /// <param name="context">The authentication context.</param>
    /// <param name="sessionId">The session id value.</param>
    /// <param name="metadata">The metadata value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task NotifyAsync(
        SecurityNotificationType type,
        string recipientEmail,
        DateTimeOffset occurredAt,
        AuthenticationContext? context = null,
        Guid? sessionId = null,
        IReadOnlyDictionary<string, string>? metadata = null,
        CancellationToken cancellationToken = default)
    {
        if (notificationService == null) return;

        await notificationService.NotifyAsync(new SecurityNotification
        {
            Type = type,
            RecipientEmail = recipientEmail,
            OccurredAt = occurredAt,
            IpAddress = context?.IpAddress,
            UserAgent = context?.UserAgent,
            SessionId = sessionId,
            Metadata = metadata
        }, cancellationToken);
    }
}



