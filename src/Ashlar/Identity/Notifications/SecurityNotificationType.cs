namespace Ashlar.Identity.Notifications;

/// <summary>
/// Lists security notification events that may be sent to users.
/// </summary>
public enum SecurityNotificationType
{
    /// <summary>
    /// A successful sign-in occurred.
    /// </summary>
    SignIn,
    /// <summary>
    /// One application session was revoked.
    /// </summary>
    SessionRevoked,
    /// <summary>
    /// All sessions except the current one were revoked.
    /// </summary>
    AllOtherSessionsRevoked,
    /// <summary>
    /// All application sessions for the account were revoked.
    /// </summary>
    AllSessionsRevoked,
    /// <summary>
    /// TOTP MFA was enabled for the account.
    /// </summary>
    TotpEnrolled,
    /// <summary>
    /// TOTP MFA was disabled for the account.
    /// </summary>
    TotpDisabled,
    /// <summary>
    /// A new set of MFA recovery codes was generated.
    /// </summary>
    RecoveryCodesGenerated,
    /// <summary>
    /// An invitation was accepted.
    /// </summary>
    InvitationAccepted,
    /// <summary>
    /// Initial system bootstrap was completed.
    /// </summary>
    BootstrapCompleted,
    /// <summary>
    /// The account email address was changed.
    /// </summary>
    EmailChanged,
    /// <summary>
    /// Email verification completed for the account.
    /// </summary>
    EmailVerificationCompleted,
    /// <summary>
    /// Password reset completed for the account.
    /// </summary>
    PasswordResetCompleted,
    /// <summary>
    /// A suspicious authentication attempt was detected.
    /// </summary>
    SuspiciousAuthenticationAttempt
}
