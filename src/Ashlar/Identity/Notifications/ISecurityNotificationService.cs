namespace Ashlar.Identity.Notifications;

/// <summary>
/// Sends user-facing security notifications.
/// </summary>
public interface ISecurityNotificationService
{
    /// <summary>
    /// Sends or suppresses a security notification.
    /// </summary>
    /// <param name="notification">Notification content and safe metadata to render for the recipient.</param>
    /// <param name="cancellationToken">Token for aborting delivery work.</param>
    /// <returns>Delivery result indicating success, suppression, or failure.</returns>
    Task<SecurityNotificationResult> NotifyAsync(
        SecurityNotification notification,
        CancellationToken cancellationToken = default);
}
