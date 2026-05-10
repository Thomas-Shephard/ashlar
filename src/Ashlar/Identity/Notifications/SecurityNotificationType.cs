namespace Ashlar.Identity.Notifications;

public enum SecurityNotificationType
{
    SignIn,
    SessionRevoked,
    AllOtherSessionsRevoked,
    AllSessionsRevoked,
    TotpEnrolled,
    TotpDisabled,
    RecoveryCodesGenerated,
    InvitationAccepted,
    BootstrapCompleted,
    EmailChanged,
    EmailVerificationCompleted,
    SuspiciousAuthenticationAttempt
}
