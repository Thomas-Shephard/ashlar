using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.Notifications;

namespace Ashlar.Identity;

public sealed class SecurityNotificationEmitter(ISecurityNotificationService? notificationService)
{
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
