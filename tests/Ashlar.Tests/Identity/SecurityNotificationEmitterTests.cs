using Ashlar.Identity;
using Ashlar.Identity.Models;
using Ashlar.Identity.Notifications;
using Moq;

namespace Ashlar.Tests.Identity;

internal sealed class SecurityNotificationEmitterTests
{
    [Test]
    public void NotifyAsyncWithUserDoesNothingWhenServiceIsNull()
    {
        var emitter = new SecurityNotificationEmitter(null);
        var user = new User { Id = Guid.NewGuid(), Email = "user@example.com" };

        Assert.DoesNotThrowAsync(() => emitter.NotifyAsync(SecurityNotificationType.SignIn, user, DateTimeOffset.UtcNow));
    }

    [Test]
    public async Task NotifyAsyncWithUserPassesContextAndMetadata()
    {
        var service = new Mock<ISecurityNotificationService>();
        var emitter = new SecurityNotificationEmitter(service.Object);
        var user = new User { Id = Guid.NewGuid(), Email = "user@example.com" };
        var sessionId = Guid.NewGuid();
        var metadata = new Dictionary<string, string> { ["reason"] = "test" };
        var occurredAt = DateTimeOffset.UtcNow;

        await emitter.NotifyAsync(
            SecurityNotificationType.SessionRevoked,
            user,
            occurredAt,
            new AuthenticationContext(IpAddress: "203.0.113.10", UserAgent: "NUnit"),
            sessionId,
            metadata);

        service.Verify(s => s.NotifyAsync(It.Is<SecurityNotification>(n =>
            n.Type == SecurityNotificationType.SessionRevoked &&
            n.RecipientEmail == "user@example.com" &&
            n.OccurredAt == occurredAt &&
            n.IpAddress == "203.0.113.10" &&
            n.UserAgent == "NUnit" &&
            n.SessionId == sessionId &&
            n.Metadata == metadata), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public void NotifyAsyncWithRecipientDoesNothingWhenServiceIsNull()
    {
        var emitter = new SecurityNotificationEmitter(null);

        Assert.DoesNotThrowAsync(() => emitter.NotifyAsync(SecurityNotificationType.EmailChanged, "user@example.com", DateTimeOffset.UtcNow));
    }

    [Test]
    public async Task NotifyAsyncWithRecipientPassesContextAndMetadata()
    {
        var service = new Mock<ISecurityNotificationService>();
        var emitter = new SecurityNotificationEmitter(service.Object);
        var sessionId = Guid.NewGuid();
        var metadata = new Dictionary<string, string> { ["old_email"] = "old@example.com" };
        var occurredAt = DateTimeOffset.UtcNow;

        await emitter.NotifyAsync(
            SecurityNotificationType.EmailChanged,
            "new@example.com",
            occurredAt,
            new AuthenticationContext(IpAddress: "203.0.113.20", UserAgent: "NUnit"),
            sessionId,
            metadata);

        service.Verify(s => s.NotifyAsync(It.Is<SecurityNotification>(n =>
            n.Type == SecurityNotificationType.EmailChanged &&
            n.RecipientEmail == "new@example.com" &&
            n.OccurredAt == occurredAt &&
            n.IpAddress == "203.0.113.20" &&
            n.UserAgent == "NUnit" &&
            n.SessionId == sessionId &&
            n.Metadata == metadata), It.IsAny<CancellationToken>()), Times.Once);
    }
}
