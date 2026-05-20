namespace Ashlar.Identity.Notifications;

/// <summary>
/// Defines the contract for isecurity notification suppression store operations.
/// </summary>
public interface ISecurityNotificationSuppressionStore
{
    /// <summary>
    /// Performs the should send operation and returns the result.
    /// </summary>
    /// <param name="notification">The notification value.</param>
    /// <param name="cooldown">The cooldown value.</param>
    /// <param name="now">The now value.</param>
    /// <returns>The operation result.</returns>
    bool ShouldSend(SecurityNotification notification, TimeSpan cooldown, DateTimeOffset now);
}


