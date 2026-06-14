using Ashlar.Operational;

namespace Ashlar.Tests.Operational;

internal sealed class AshlarCleanupResultTests
{
    [Test]
    public void EmptyHasZeroTotal()
    {
        Assert.That(AshlarCleanupResult.Empty.Total, Is.Zero);
    }

    [Test]
    public void TotalSumsAllCategories()
    {
        var result = new AshlarCleanupResult(
            ExpiredSessions: 1,
            RevokedSessions: 2,
            ExpiredCredentials: 3,
            RevokedCredentials: 4,
            ExpiredInvitations: 5,
            AcceptedInvitations: 6,
            RevokedInvitations: 7,
            ExpiredHandshakes: 8,
            CompletedHandshakes: 9,
            RevokedHandshakes: 10,
            ExpiredRateLimits: 11,
            AuditEvents: 12,
            SentEmails: 13,
            FailedEmails: 14,
            ExpiredAuthorizationGrants: 15,
            RevokedAuthorizationGrants: 16,
            ExpiredPasskeyChallenges: 17,
            ConsumedPasskeyChallenges: 18,
            SentSensitiveEmails: 19,
            FailedSensitiveEmails: 20,
            DiscardedEmails: 21,
            DiscardedSensitiveEmails: 22,
            SentSecurityEventWebhooks: 23,
            FailedSecurityEventWebhooks: 24,
            DiscardedSecurityEventWebhooks: 25,
            ExpiredRememberedMfaDevices: 26,
            RevokedRememberedMfaDevices: 27);

        Assert.That(result.Total, Is.EqualTo(378));
    }

    [Test]
    public void AddSumsCategoryCounts()
    {
        var result = new AshlarCleanupResult(
                ExpiredSessions: 1,
                RevokedSessions: 1,
                ExpiredCredentials: 1,
                RevokedCredentials: 1,
                ExpiredInvitations: 1,
                AcceptedInvitations: 1,
                RevokedInvitations: 1,
                ExpiredHandshakes: 1,
                CompletedHandshakes: 1,
                RevokedHandshakes: 1,
                ExpiredRateLimits: 1,
                AuditEvents: 1,
                SentEmails: 1,
                FailedEmails: 1,
                ExpiredRememberedMfaDevices: 1,
                RevokedRememberedMfaDevices: 1)
            .Add(new AshlarCleanupResult(
                ExpiredSessions: 2,
                RevokedSessions: 2,
                ExpiredCredentials: 2,
                RevokedCredentials: 2,
                ExpiredInvitations: 2,
                AcceptedInvitations: 2,
                RevokedInvitations: 2,
                ExpiredHandshakes: 2,
                CompletedHandshakes: 2,
                RevokedHandshakes: 2,
                ExpiredRateLimits: 2,
                AuditEvents: 2,
                SentEmails: 2,
                FailedEmails: 2,
                ExpiredRememberedMfaDevices: 2,
                RevokedRememberedMfaDevices: 2));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.ExpiredSessions, Is.EqualTo(3));
            Assert.That(result.RevokedSessions, Is.EqualTo(3));
            Assert.That(result.ExpiredRememberedMfaDevices, Is.EqualTo(3));
            Assert.That(result.RevokedRememberedMfaDevices, Is.EqualTo(3));
            Assert.That(result.Total, Is.EqualTo(48));
        }
    }

    [Test]
    public void AddThrowsForNullResult()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => AshlarCleanupResult.Empty.Add(null!));
    }
}
