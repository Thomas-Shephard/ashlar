using Ashlar.Auditing;
using Ashlar.Identity.Notifications;

namespace Ashlar.Identity.Features.Infrastructure;

/// <summary>
/// Groups audit and notification dependencies.
/// </summary>
/// <param name="timeProvider">Clock used for audit and notification timestamps.</param>
/// <param name="securityEventSink">Sink used to record security events.</param>
/// <param name="notificationService">Optional service used to send user security notifications.</param>
internal sealed class IdentityAuditContext(
    TimeProvider timeProvider,
    ISecurityEventSink securityEventSink,
    ISecurityNotificationService? notificationService = null)
{
    /// <summary>
    /// Gets the clock used for audit and notification timestamps.
    /// </summary>
    public TimeProvider TimeProvider { get; } = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    /// <summary>
    /// Gets the sink used to record security events.
    /// </summary>
    public ISecurityEventSink SecurityEventSink { get; } = securityEventSink ?? throw new ArgumentNullException(nameof(securityEventSink));
    /// <summary>
    /// Gets the optional service used to send user security notifications.
    /// </summary>
    public ISecurityNotificationService? NotificationService { get; } = notificationService;
}
