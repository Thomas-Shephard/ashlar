namespace Ashlar.Identity.Notifications;

/// <summary>
/// Defines the available security notification type values.
/// </summary>
public enum SecurityNotificationType
{
    /// <summary>
    /// Represents the sign in value.
    /// </summary>
    SignIn,
    /// <summary>
    /// Represents the session revoked value.
    /// </summary>
    SessionRevoked,
    /// <summary>
    /// Represents the all other sessions revoked value.
    /// </summary>
    AllOtherSessionsRevoked,
    /// <summary>
    /// Represents the all sessions revoked value.
    /// </summary>
    AllSessionsRevoked,
    /// <summary>
    /// Represents the totp enrolled value.
    /// </summary>
    TotpEnrolled,
    /// <summary>
    /// Represents the totp disabled value.
    /// </summary>
    TotpDisabled,
    /// <summary>
    /// Represents the recovery codes generated value.
    /// </summary>
    RecoveryCodesGenerated,
    /// <summary>
    /// Represents the invitation accepted value.
    /// </summary>
    InvitationAccepted,
    /// <summary>
    /// Represents the bootstrap completed value.
    /// </summary>
    BootstrapCompleted,
    /// <summary>
    /// Represents the email changed value.
    /// </summary>
    EmailChanged,
    /// <summary>
    /// Represents the email verification completed value.
    /// </summary>
    EmailVerificationCompleted,
    /// <summary>
    /// Represents the suspicious authentication attempt value.
    /// </summary>
    SuspiciousAuthenticationAttempt
}


