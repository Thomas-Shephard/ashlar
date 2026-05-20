namespace Ashlar.Operational;

/// <summary>
/// Represents the ashlar cleanup result data model.
/// </summary>
/// <param name="ExpiredSessions">The expired sessions value.</param>
/// <param name="RevokedSessions">The revoked sessions value.</param>
/// <param name="ExpiredCredentials">The expired credentials value.</param>
/// <param name="RevokedCredentials">The revoked credentials value.</param>
/// <param name="ExpiredInvitations">The expired invitations value.</param>
/// <param name="AcceptedInvitations">The accepted invitations value.</param>
/// <param name="RevokedInvitations">The revoked invitations value.</param>
/// <param name="ExpiredHandshakes">The expired handshakes value.</param>
/// <param name="CompletedHandshakes">The completed handshakes value.</param>
/// <param name="RevokedHandshakes">The revoked handshakes value.</param>
/// <param name="ExpiredRateLimits">The expired rate limits value.</param>
/// <param name="AuditEvents">The audit events value.</param>
/// <param name="SentEmails">The sent emails value.</param>
/// <param name="FailedEmails">The failed emails value.</param>
/// <param name="ExpiredAuthorizationGrants">The expired authorization grants value.</param>
/// <param name="RevokedAuthorizationGrants">The revoked authorization grants value.</param>
/// <param name="ExpiredPasskeyChallenges">The expired passkey challenges value.</param>
/// <param name="ConsumedPasskeyChallenges">The consumed passkey challenges value.</param>
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
    int ConsumedPasskeyChallenges = 0)
{
    /// <summary>
    /// Executes the new operation.
    /// </summary>
    public static AshlarCleanupResult Empty { get; } = new(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

    /// <summary>
    /// Gets or sets the total value.
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
        + ExpiredPasskeyChallenges
        + ConsumedPasskeyChallenges;

    /// <summary>
    /// Performs the add operation and returns the result.
    /// </summary>
    /// <param name="other">The other value.</param>
    /// <returns>The operation result.</returns>
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
            ConsumedPasskeyChallenges + other.ConsumedPasskeyChallenges);
    }
}


