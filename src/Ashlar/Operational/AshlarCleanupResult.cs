namespace Ashlar.Operational;

public sealed record AshlarCleanupResult(
    int ExpiredSessions,
    int RevokedSessions,
    int ExpiredCredentials,
    int RevokedCredentials,
    int ExpiredInvitations,
    int AcceptedInvitations,
    int RevokedInvitations,
    int ExpiredHandshakes,
    int CompletedHandshakes,
    int RevokedHandshakes,
    int ExpiredRateLimits,
    int AuditEvents,
    int SentEmails,
    int FailedEmails,
    int ExpiredAuthorizationGrants = 0,
    int RevokedAuthorizationGrants = 0)
{
    public static AshlarCleanupResult Empty { get; } = new(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

    public int Total =>
        ExpiredSessions
        + RevokedSessions
        + ExpiredCredentials
        + RevokedCredentials
        + ExpiredAuthorizationGrants
        + RevokedAuthorizationGrants
        + ExpiredInvitations
        + AcceptedInvitations
        + RevokedInvitations
        + ExpiredHandshakes
        + CompletedHandshakes
        + RevokedHandshakes
        + ExpiredRateLimits
        + AuditEvents
        + SentEmails
        + FailedEmails;

    public AshlarCleanupResult Add(AshlarCleanupResult other)
    {
        ArgumentNullException.ThrowIfNull(other);

        return new AshlarCleanupResult(
            ExpiredSessions + other.ExpiredSessions,
            RevokedSessions + other.RevokedSessions,
            ExpiredCredentials + other.ExpiredCredentials,
            RevokedCredentials + other.RevokedCredentials,
            ExpiredInvitations + other.ExpiredInvitations,
            AcceptedInvitations + other.AcceptedInvitations,
            RevokedInvitations + other.RevokedInvitations,
            ExpiredHandshakes + other.ExpiredHandshakes,
            CompletedHandshakes + other.CompletedHandshakes,
            RevokedHandshakes + other.RevokedHandshakes,
            ExpiredRateLimits + other.ExpiredRateLimits,
            AuditEvents + other.AuditEvents,
            SentEmails + other.SentEmails,
            FailedEmails + other.FailedEmails,
            ExpiredAuthorizationGrants + other.ExpiredAuthorizationGrants,
            RevokedAuthorizationGrants + other.RevokedAuthorizationGrants);
    }
}
