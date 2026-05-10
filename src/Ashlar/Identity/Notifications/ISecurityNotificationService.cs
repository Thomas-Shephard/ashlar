namespace Ashlar.Identity.Notifications;

public interface ISecurityNotificationService
{
    Task<SecurityNotificationResult> NotifyAsync(
        SecurityNotification notification,
        CancellationToken cancellationToken = default);
}
