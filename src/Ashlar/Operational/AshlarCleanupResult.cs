namespace Ashlar.Operational;

/// <summary>
/// Reports how many operational records were removed or discarded by a cleanup run.
/// </summary>
/// <param name="ExpiredSessions">Expired authentication sessions removed.</param>
/// <param name="RevokedSessions">Revoked authentication sessions removed.</param>
/// <param name="ExpiredCredentials">Expired credentials removed.</param>
/// <param name="RevokedCredentials">Revoked credentials removed.</param>
/// <param name="ExpiredInvitations">Expired invitations removed.</param>
/// <param name="AcceptedInvitations">Accepted invitations removed.</param>
/// <param name="RevokedInvitations">Revoked invitations removed.</param>
/// <param name="ExpiredHandshakes">Expired authentication handshakes removed.</param>
/// <param name="CompletedHandshakes">Completed authentication handshakes removed.</param>
/// <param name="RevokedHandshakes">Revoked authentication handshakes removed.</param>
/// <param name="ExpiredRateLimits">Expired rate-limit records removed.</param>
/// <param name="AuditEvents">Retained audit events removed according to policy.</param>
/// <param name="SentEmails">Sent non-sensitive outbox emails removed.</param>
/// <param name="FailedEmails">Failed non-sensitive outbox emails removed.</param>
/// <param name="ExpiredAuthorizationGrants">Expired authorization grants removed.</param>
/// <param name="RevokedAuthorizationGrants">Revoked authorization grants removed.</param>
/// <param name="ExpiredPasskeyChallenges">Expired passkey challenges removed.</param>
/// <param name="ConsumedPasskeyChallenges">Consumed passkey challenges removed.</param>
/// <param name="SentSensitiveEmails">Sent sensitive outbox emails removed.</param>
/// <param name="FailedSensitiveEmails">Failed sensitive outbox emails removed.</param>
/// <param name="SentSecurityEventWebhooks">Sent security-event webhook deliveries removed.</param>
/// <param name="FailedSecurityEventWebhooks">Failed security-event webhook deliveries removed.</param>
/// <param name="DiscardedSecurityEventWebhooks">Discarded security-event webhook deliveries removed.</param>
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
    int RevokedAuthorizationGrants = 0,
    int ExpiredPasskeyChallenges = 0,
    int ConsumedPasskeyChallenges = 0,
    int SentSensitiveEmails = 0,
    int FailedSensitiveEmails = 0,
    int SentSecurityEventWebhooks = 0,
    int FailedSecurityEventWebhooks = 0,
    int DiscardedSecurityEventWebhooks = 0)
{
    /// <summary>
    /// Gets a cleanup result with all counts set to zero.
    /// </summary>
    public static AshlarCleanupResult Empty { get; } = new(
        ExpiredSessions: 0,
        RevokedSessions: 0,
        ExpiredCredentials: 0,
        RevokedCredentials: 0,
        ExpiredInvitations: 0,
        AcceptedInvitations: 0,
        RevokedInvitations: 0,
        ExpiredHandshakes: 0,
        CompletedHandshakes: 0,
        RevokedHandshakes: 0,
        ExpiredRateLimits: 0,
        AuditEvents: 0,
        SentEmails: 0,
        FailedEmails: 0,
        ExpiredAuthorizationGrants: 0,
        RevokedAuthorizationGrants: 0,
        ExpiredPasskeyChallenges: 0,
        ConsumedPasskeyChallenges: 0,
        SentSensitiveEmails: 0,
        FailedSensitiveEmails: 0,
        SentSecurityEventWebhooks: 0,
        FailedSecurityEventWebhooks: 0,
        DiscardedSecurityEventWebhooks: 0);

    /// <summary>
    /// Gets the total number of records affected by cleanup.
    /// </summary>
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
        + FailedEmails
        + SentSensitiveEmails
        + FailedSensitiveEmails
        + ExpiredPasskeyChallenges
        + ConsumedPasskeyChallenges
        + SentSecurityEventWebhooks
        + FailedSecurityEventWebhooks
        + DiscardedSecurityEventWebhooks;

    /// <summary>
    /// Adds another cleanup result to this result.
    /// </summary>
    /// <param name="other">Cleanup result to add.</param>
    /// <returns>A cleanup result whose counts are the sum of both inputs.</returns>
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
            RevokedAuthorizationGrants + other.RevokedAuthorizationGrants,
            ExpiredPasskeyChallenges + other.ExpiredPasskeyChallenges,
            ConsumedPasskeyChallenges + other.ConsumedPasskeyChallenges,
            SentSensitiveEmails + other.SentSensitiveEmails,
            FailedSensitiveEmails + other.FailedSensitiveEmails,
            SentSecurityEventWebhooks + other.SentSecurityEventWebhooks,
            FailedSecurityEventWebhooks + other.FailedSecurityEventWebhooks,
            DiscardedSecurityEventWebhooks + other.DiscardedSecurityEventWebhooks);
    }
}
