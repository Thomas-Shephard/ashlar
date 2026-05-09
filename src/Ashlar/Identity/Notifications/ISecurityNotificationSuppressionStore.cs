namespace Ashlar.Identity.Notifications;

public interface ISecurityNotificationSuppressionStore
{
    bool ShouldSend(SecurityNotification notification, TimeSpan cooldown, DateTimeOffset now);
}
