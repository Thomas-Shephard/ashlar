namespace Ashlar.Identity.Notifications;

/// <summary>
/// Tracks notification cooldowns to avoid repeatedly emailing the same recipient.
/// </summary>
public interface ISecurityNotificationSuppressionStore
{
    /// <summary>
    /// Records a send attempt and determines whether the notification may be delivered.
    /// </summary>
    /// <param name="notification">Notification whose recipient and type define the suppression key.</param>
    /// <param name="cooldown">Minimum time between duplicate notifications.</param>
    /// <param name="now">Current UTC time used for suppression expiry.</param>
    /// <returns><see langword="true" /> when the notification should be sent; otherwise, <see langword="false" />.</returns>
    bool ShouldSend(SecurityNotification notification, TimeSpan cooldown, DateTimeOffset now);
}
