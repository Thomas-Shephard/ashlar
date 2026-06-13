namespace Ashlar.Identity.Notifications;

/// <summary>
/// Configures which security notifications are sent and how they are rendered.
/// </summary>
public sealed class SecurityNotificationOptions
{
    /// <summary>
    /// Whether security notifications are sent.
    /// </summary>
    public bool Enabled { get; set; }
    /// <summary>
    /// Notification types sent when security notifications are enabled.
    /// </summary>
    public HashSet<SecurityNotificationType> EnabledTypes { get; } = [];
    /// <summary>
    /// Per-type templates that replace built-in notification content.
    /// </summary>
    public Dictionary<SecurityNotificationType, SecurityNotificationTemplate> TemplateOverrides { get; } = [];
    /// <summary>
    /// Per-type suppression windows used to avoid duplicate notifications.
    /// </summary>
    public Dictionary<SecurityNotificationType, TimeSpan> Cooldowns { get; } = CreateDefaultCooldowns();
    /// <summary>
    /// Whether templates may include client IP addresses. Treat as personal data.
    /// </summary>
    public bool IncludeIpAddress { get; set; } = true;
    /// <summary>
    /// Whether templates may include user-agent text. Treat as user supplied.
    /// </summary>
    public bool IncludeUserAgent { get; set; } = true;

    /// <summary>
    /// The email address to use as the sender. If <see langword="null" />, the default sender configured in <c>IEmailSender</c> will be used.
    /// </summary>
    public string? FromAddress { get; set; }

    /// <summary>
    /// Built-in templates used when no override is configured.
    /// </summary>
    public static Dictionary<SecurityNotificationType, SecurityNotificationTemplate> DefaultTemplates { get; } = new()
    {
        [SecurityNotificationType.SignIn] = new SecurityNotificationTemplate
        {
            Subject = "New sign-in to your account",
            Body = "A new sign-in was detected for your account at {OccurredAt} from IP {IpAddress}."
        },
        [SecurityNotificationType.SessionRevoked] = new SecurityNotificationTemplate
        {
            Subject = "A session was revoked",
            Body = "A session for your account was revoked at {OccurredAt} from IP {IpAddress}."
        },
        [SecurityNotificationType.AllOtherSessionsRevoked] = new SecurityNotificationTemplate
        {
            Subject = "All other sessions were revoked",
            Body = "All other sessions for your account were revoked at {OccurredAt} from IP {IpAddress}."
        },
        [SecurityNotificationType.AllSessionsRevoked] = new SecurityNotificationTemplate
        {
            Subject = "All sessions were revoked",
            Body = "All sessions for your account were revoked at {OccurredAt} from IP {IpAddress}."
        },
        [SecurityNotificationType.TotpEnrolled] = new SecurityNotificationTemplate
        {
            Subject = "MFA has been enabled",
            Body = "Two-factor authentication (TOTP) has been enabled for your account at {OccurredAt} from IP {IpAddress}."
        },
        [SecurityNotificationType.TotpDisabled] = new SecurityNotificationTemplate
        {
            Subject = "MFA has been disabled",
            Body = "Two-factor authentication (TOTP) has been disabled for your account at {OccurredAt} from IP {IpAddress}."
        },
        [SecurityNotificationType.RecoveryCodesGenerated] = new SecurityNotificationTemplate
        {
            Subject = "New recovery codes generated",
            Body = "New recovery codes were generated for your account at {OccurredAt} from IP {IpAddress}."
        },
        [SecurityNotificationType.InvitationAccepted] = new SecurityNotificationTemplate
        {
            Subject = "Invitation accepted",
            Body = "Your invitation has been accepted at {OccurredAt} from IP {IpAddress}."
        },
        [SecurityNotificationType.BootstrapCompleted] = new SecurityNotificationTemplate
        {
            Subject = "System bootstrap completed",
            Body = "The system bootstrap process has been completed at {OccurredAt} from IP {IpAddress}."
        },
        [SecurityNotificationType.EmailChanged] = new SecurityNotificationTemplate
        {
            Subject = "Your email has been changed",
            Body = "The email address for your account has been changed at {OccurredAt} from IP {IpAddress}."
        },
        [SecurityNotificationType.EmailVerificationCompleted] = new SecurityNotificationTemplate
        {
            Subject = "Email verification completed",
            Body = "Your email address has been successfully verified at {OccurredAt} from IP {IpAddress}."
        },
        [SecurityNotificationType.PasswordResetCompleted] = new SecurityNotificationTemplate
        {
            Subject = "Your password has been reset",
            Body = "The password for your account was reset at {OccurredAt} from IP {IpAddress}."
        },
        [SecurityNotificationType.SuspiciousAuthenticationAttempt] = new SecurityNotificationTemplate
        {
            Subject = "Suspicious authentication attempt",
            Body = "Multiple failed authentication verification attempts were detected for your account at {OccurredAt} from IP {IpAddress}."
        }
    };

    private static Dictionary<SecurityNotificationType, TimeSpan> CreateDefaultCooldowns() => new()
    {
        [SecurityNotificationType.SignIn] = TimeSpan.FromMinutes(15),
        [SecurityNotificationType.SessionRevoked] = TimeSpan.FromMinutes(15),
        [SecurityNotificationType.AllOtherSessionsRevoked] = TimeSpan.FromMinutes(15),
        [SecurityNotificationType.AllSessionsRevoked] = TimeSpan.FromMinutes(15),
        [SecurityNotificationType.TotpEnrolled] = TimeSpan.FromMinutes(15),
        [SecurityNotificationType.TotpDisabled] = TimeSpan.FromMinutes(15),
        [SecurityNotificationType.RecoveryCodesGenerated] = TimeSpan.FromMinutes(15),
        [SecurityNotificationType.InvitationAccepted] = TimeSpan.FromMinutes(15),
        [SecurityNotificationType.BootstrapCompleted] = TimeSpan.FromMinutes(15),
        [SecurityNotificationType.EmailChanged] = TimeSpan.FromMinutes(15),
        [SecurityNotificationType.EmailVerificationCompleted] = TimeSpan.FromMinutes(15),
        [SecurityNotificationType.PasswordResetCompleted] = TimeSpan.FromMinutes(15),
        [SecurityNotificationType.SuspiciousAuthenticationAttempt] = TimeSpan.FromHours(1)
    };
}
