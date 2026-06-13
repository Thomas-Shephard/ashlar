using Ashlar.Identity.Notifications;

namespace Ashlar.Identity.Features.AccountSecurity;

/// <summary>
/// Builds and emits account security notifications when notification delivery is configured.
/// </summary>
/// <param name="notificationService">Optional notification service used to deliver messages.</param>
public sealed class SecurityNotificationEmitter(ISecurityNotificationService? notificationService)
{
    /// <summary>
    /// Sends a security notification to a user.
    /// </summary>
    /// <param name="type">Kind of account event being reported.</param>
    /// <param name="user">The recipient user.</param>
    /// <param name="occurredAt">UTC time when the account event occurred.</param>
    /// <param name="context">Authentication context used to copy client IP address and user-agent values into the notification.</param>
    /// <param name="sessionId">Related application session identifier, when available.</param>
    /// <param name="metadata">Optional template metadata. Do not include secrets or credential values.</param>
    /// <param name="cancellationToken">A token that can cancel notification delivery.</param>
    /// <returns>A task that completes when notification processing finishes or is skipped.</returns>
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
    /// <param name="type">Kind of account event being reported.</param>
    /// <param name="recipientEmail">The recipient email address.</param>
    /// <param name="occurredAt">UTC time when the account event occurred.</param>
    /// <param name="context">Authentication context used to copy client IP address and user-agent values into the notification.</param>
    /// <param name="sessionId">Related application session identifier, when available.</param>
    /// <param name="metadata">Optional template metadata. Do not include secrets or credential values.</param>
    /// <param name="cancellationToken">A token that can cancel notification delivery.</param>
    /// <returns>A task that completes when notification processing finishes or is skipped.</returns>
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
