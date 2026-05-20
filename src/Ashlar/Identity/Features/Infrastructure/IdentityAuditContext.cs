using Ashlar.Auditing;
using Ashlar.Identity.Notifications;

namespace Ashlar.Identity.Features.Infrastructure;

/// <summary>
/// Groups audit and notification dependencies.
/// </summary>
/// <param name="timeProvider">The time provider value.</param>
/// <param name="securityEventSink">The security event sink value.</param>
/// <param name="notificationService">The notification service value.</param>
internal sealed class IdentityAuditContext(
    TimeProvider timeProvider,
    ISecurityEventSink securityEventSink,
    ISecurityNotificationService? notificationService = null)
{
    /// <summary>
    /// Gets the configured dependency value.
    /// </summary>
    public TimeProvider TimeProvider { get; } = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    /// <summary>
    /// Gets the configured dependency value.
    /// </summary>
    public ISecurityEventSink SecurityEventSink { get; } = securityEventSink ?? throw new ArgumentNullException(nameof(securityEventSink));
    /// <summary>
    /// Gets or sets the notification service value.
    /// </summary>
    public ISecurityNotificationService? NotificationService { get; } = notificationService;
}



