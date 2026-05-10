using Ashlar.Auditing;
using Ashlar.Identity.Notifications;

namespace Ashlar.Identity;

/// <summary>
/// Groups audit and notification dependencies.
/// </summary>
public sealed class IdentityAuditContext(
    TimeProvider timeProvider,
    ISecurityEventSink securityEventSink,
    ISecurityNotificationService? notificationService = null)
{
    public TimeProvider TimeProvider { get; } = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    public ISecurityEventSink SecurityEventSink { get; } = securityEventSink ?? throw new ArgumentNullException(nameof(securityEventSink));
    public ISecurityNotificationService? NotificationService { get; } = notificationService;
}
