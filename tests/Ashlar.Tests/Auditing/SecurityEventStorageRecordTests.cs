using Ashlar.Auditing;

namespace Ashlar.Tests.Auditing;

internal sealed class SecurityEventStorageRecordTests
{
    [Test]
    public void ToSummaryMapsSafeDisplayFields()
    {
        var eventId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var actorUserId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var occurredAt = DateTimeOffset.UtcNow;
        var record = new SecurityEventStorageRecord(
            eventId,
            "SignInFailed",
            occurredAt,
            userId,
            tenantId,
            actorUserId,
            sessionId,
            ProviderType.Local.Value,
            "local",
            "203.0.113.10",
            "Test Browser",
            "correlation",
            SecurityEventOutcomes.Failure,
            "bad_password",
            """{"safe":"value","empty":""}""");

        var summary = record.ToSummary();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(summary.EventId, Is.EqualTo(eventId));
            Assert.That(summary.EventType, Is.EqualTo("SignInFailed"));
            Assert.That(summary.OccurredAt, Is.EqualTo(occurredAt));
            Assert.That(summary.UserId, Is.EqualTo(userId));
            Assert.That(summary.TenantId, Is.EqualTo(tenantId));
            Assert.That(summary.ActorUserId, Is.EqualTo(actorUserId));
            Assert.That(summary.SessionId, Is.EqualTo(sessionId));
            Assert.That(summary.Provider, Is.EqualTo(new AuthenticationProviderKey(ProviderType.Local, "local")));
            Assert.That(summary.IpAddress, Is.EqualTo("203.0.113.10"));
            Assert.That(summary.UserAgent, Is.EqualTo("Test Browser"));
            Assert.That(summary.CorrelationId, Is.EqualTo("correlation"));
            Assert.That(summary.Outcome, Is.EqualTo(SecurityEventOutcomes.Failure));
            Assert.That(summary.FailureReason, Is.EqualTo("bad_password"));
            Assert.That(summary.Properties, Does.ContainKey("safe").WithValue("value"));
            Assert.That(summary.Properties, Does.ContainKey("empty").WithValue(string.Empty));
        }
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("[]")]
    [TestCase("{}")]
    [TestCase("{")]
    public void ToSummaryReturnsNullPropertiesForUnsafeOrEmptyPayloads(string? propertiesJson)
    {
        var summary = CreateRecord(propertiesJson: propertiesJson).ToSummary();

        Assert.That(summary.Properties, Is.Null);
    }

    [Test]
    public void ToSummaryReturnsOnlyStringProperties()
    {
        var summary = CreateRecord(propertiesJson: """{"safe":"value","number":1}""").ToSummary();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(summary.Properties, Does.ContainKey("safe").WithValue("value"));
            Assert.That(summary.Properties, Does.Not.ContainKey("number"));
        }
    }

    [TestCase(null, "local")]
    [TestCase("", "local")]
    [TestCase("LOCAL", null)]
    [TestCase("LOCAL", "")]
    public void ToSummaryReturnsNullProviderUnlessTypeAndNameArePresent(string? providerType, string? providerName)
    {
        var summary = CreateRecord(providerType: providerType, providerName: providerName).ToSummary();

        Assert.That(summary.Provider, Is.Null);
    }

    [Test]
    public void ToSummaryPreservesStorageFallbackProviderShape()
    {
        var summary = CreateRecord(
            providerType: ProviderType.StorageFallbackValue,
            providerName: string.Empty).ToSummary();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(summary.Provider, Is.EqualTo(default(AuthenticationProviderKey)));
            Assert.That(summary.Provider?.StorageTypeValue, Is.EqualTo(ProviderType.StorageFallbackValue));
        }
    }

    private static SecurityEventStorageRecord CreateRecord(
        string? providerType = null,
        string? providerName = null,
        string? propertiesJson = null)
    {
        return new SecurityEventStorageRecord(
            Guid.NewGuid(),
            "TestEvent",
            DateTimeOffset.UtcNow,
            null,
            null,
            null,
            null,
            providerType,
            providerName,
            null,
            null,
            null,
            null,
            null,
            propertiesJson);
    }
}
