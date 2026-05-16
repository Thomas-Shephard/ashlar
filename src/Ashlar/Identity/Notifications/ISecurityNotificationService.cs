namespace Ashlar.Identity.Notifications;

/// <summary>
/// Defines the contract for isecurity notification service operations.
/// </summary>
public interface ISecurityNotificationService
{
    /// <summary>
    /// Performs the notify <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="notification">The notification value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<SecurityNotificationResult> NotifyAsync(
        SecurityNotification notification,
        CancellationToken cancellationToken = default);
}
