using Ashlar.Identity.Models;

namespace Ashlar.Tests.Identity;

public sealed class AuthenticationSessionTests
{
    [Test]
    public void IsActiveShouldBeTrueBeforeExpiryAndWithoutRevocation()
    {
        var now = DateTimeOffset.UtcNow;
        var session = CreateSession(now.AddHours(1));

        Assert.That(session.IsActive(now), Is.True);
    }

    [Test]
    public void IsActiveShouldBeFalseAfterExpiry()
    {
        var now = DateTimeOffset.UtcNow;
        var session = CreateSession(now);

        Assert.That(session.IsActive(now), Is.False);
    }

    [Test]
    public void IsActiveShouldBeFalseAfterRevocation()
    {
        var now = DateTimeOffset.UtcNow;
        var session = CreateSession(now.AddHours(1));
        session.RevokedAt = now.AddMinutes(-1);

        Assert.That(session.IsActive(now), Is.False);
    }

    private static AuthenticationSession CreateSession(DateTimeOffset expiresAt)
    {
        return new AuthenticationSession
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            TokenHash = "sha256:test",
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = expiresAt
        };
    }
}
