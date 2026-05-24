using System.Text.Json;

namespace Ashlar.ProviderContractTests.Auditing;

internal abstract class SecurityEventPersistenceContractTests : ProviderContractFixture
{
    private static readonly DateTimeOffset OccurredAt = new(2026, 6, 2, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task RecordAsyncPersistsEventWithCoreFieldsAndProperties()
    {
        await using var scope = CreateAsyncScope();
        var sink = GetSecurityEventSink(scope.ServiceProvider);
        var securityEvent = CreateEvent(
            "Security.Core",
            Guid.NewGuid(),
            provider: new AuthenticationProviderKey(ProviderType.Local, "Password"),
            properties: new Dictionary<string, string>
            {
                ["source"] = "contract",
                ["risk"] = "high"
            });

        await sink.RecordAsync(securityEvent);
        await FlushAsync(scope.ServiceProvider);

        var row = (await ReadSecurityEventStorageRecordsAsync()).Single(record => record.Id == securityEvent.Id);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(row.EventType, Is.EqualTo(securityEvent.EventType));
            Assert.That(row.OccurredAt, Is.EqualTo(securityEvent.OccurredAt));
            Assert.That(row.UserId, Is.EqualTo(securityEvent.UserId));
            Assert.That(row.TenantId, Is.EqualTo(securityEvent.TenantId));
            Assert.That(row.ActorUserId, Is.EqualTo(securityEvent.ActorUserId));
            Assert.That(row.SessionId, Is.EqualTo(securityEvent.SessionId));
            Assert.That(row.ProviderType, Is.EqualTo(securityEvent.Provider!.Value.Type.Value));
            Assert.That(row.ProviderName, Is.EqualTo(securityEvent.Provider.Value.Name));
            Assert.That(row.IpAddress, Is.EqualTo(securityEvent.IpAddress));
            Assert.That(row.UserAgent, Is.EqualTo(securityEvent.UserAgent));
            Assert.That(row.CorrelationId, Is.EqualTo(securityEvent.CorrelationId));
            Assert.That(row.Outcome, Is.EqualTo(securityEvent.Outcome));
            Assert.That(row.FailureReason, Is.EqualTo(securityEvent.FailureReason));
            Assert.That(DeserializeProperties(row.PropertiesJson), Is.EquivalentTo(securityEvent.Properties!));
        }
    }

    [Test]
    public async Task RecordAsyncHandlesOptionalNullFields()
    {
        await using var scope = CreateAsyncScope();
        var sink = GetSecurityEventSink(scope.ServiceProvider);
        var securityEvent = new AshlarSecurityEvent
        {
            Id = Guid.NewGuid(),
            EventType = "Security.Nulls",
            OccurredAt = OccurredAt
        };

        await sink.RecordAsync(securityEvent);
        await FlushAsync(scope.ServiceProvider);

        var row = (await ReadSecurityEventStorageRecordsAsync()).Single(record => record.Id == securityEvent.Id);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(row.UserId, Is.Null);
            Assert.That(row.TenantId, Is.Null);
            Assert.That(row.ActorUserId, Is.Null);
            Assert.That(row.SessionId, Is.Null);
            Assert.That(row.ProviderType, Is.Null);
            Assert.That(row.ProviderName, Is.Null);
            Assert.That(row.IpAddress, Is.Null);
            Assert.That(row.UserAgent, Is.Null);
            Assert.That(row.CorrelationId, Is.Null);
            Assert.That(row.Outcome, Is.Null);
            Assert.That(row.FailureReason, Is.Null);
            Assert.That(row.PropertiesJson, Is.Null);
        }
    }

    [Test]
    public async Task RecordAsyncPersistsDefaultProviderShapeWhenSupplied()
    {
        await using var scope = CreateAsyncScope();
        var sink = GetSecurityEventSink(scope.ServiceProvider);
        var securityEvent = new AshlarSecurityEvent
        {
            Id = Guid.NewGuid(),
            EventType = "Security.DefaultProvider",
            OccurredAt = OccurredAt,
            Provider = (AuthenticationProviderKey?)default(AuthenticationProviderKey)
        };

        await sink.RecordAsync(securityEvent);
        await FlushAsync(scope.ServiceProvider);

        var row = (await ReadSecurityEventStorageRecordsAsync()).Single(record => record.Id == securityEvent.Id);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(row.ProviderType, Is.EqualTo("UNKNOWN"));
            Assert.That(row.ProviderName, Is.EqualTo(string.Empty));
        }
    }

    [Test]
    public async Task MultipleEventsAreAppended()
    {
        await using var scope = CreateAsyncScope();
        var sink = GetSecurityEventSink(scope.ServiceProvider);
        var first = CreateEvent("Security.First", Guid.NewGuid());
        var second = CreateEvent("Security.Second", Guid.NewGuid());

        await sink.RecordAsync(first);
        await sink.RecordAsync(second);
        await FlushAsync(scope.ServiceProvider);

        var rows = await ReadSecurityEventStorageRecordsAsync();
        Assert.That(rows.Select(record => record.Id), Is.SupersetOf(new[] { first.Id, second.Id }));
    }

    [Test]
    public async Task CountSecurityEventsForUserUsesInclusiveSinceAndIgnoresOtherUsers()
    {
        await using var scope = CreateAsyncScope();
        var sink = GetSecurityEventSink(scope.ServiceProvider);
        var summary = GetUserSecurityEventSummaryRepository(scope.ServiceProvider);
        var userId = Guid.NewGuid();
        var otherUserId = Guid.NewGuid();
        var since = OccurredAt.AddHours(-1);
        await sink.RecordAsync(CreateEvent("Boundary", userId, occurredAt: since, outcome: "Success"));
        await sink.RecordAsync(CreateEvent("RecentFailure", userId, occurredAt: OccurredAt.AddMinutes(-5), outcome: "Failure"));
        await sink.RecordAsync(CreateEvent("RecentSuccess", userId, occurredAt: OccurredAt.AddMinutes(-1), outcome: "Success"));
        await sink.RecordAsync(CreateEvent("Old", userId, occurredAt: since.AddTicks(-1), outcome: "Success"));
        await sink.RecordAsync(CreateEvent("OtherUser", otherUserId, occurredAt: OccurredAt, outcome: "Success"));
        await sink.RecordAsync(new AshlarSecurityEvent { Id = Guid.NewGuid(), EventType = "NoUser", OccurredAt = OccurredAt });
        await FlushAsync(scope.ServiceProvider);

        var count = await summary.CountSecurityEventsForUserAsync(userId, since);

        Assert.That(count, Is.EqualTo(3));
    }

    private static AshlarSecurityEvent CreateEvent(
        string eventType,
        Guid userId,
        DateTimeOffset? occurredAt = null,
        string? outcome = null,
        AuthenticationProviderKey? provider = null,
        IReadOnlyDictionary<string, string>? properties = null)
    {
        return new AshlarSecurityEvent
        {
            Id = Guid.NewGuid(),
            EventType = eventType,
            OccurredAt = occurredAt ?? OccurredAt,
            UserId = userId,
            TenantId = Guid.NewGuid(),
            ActorUserId = Guid.NewGuid(),
            SessionId = Guid.NewGuid(),
            Provider = provider,
            IpAddress = "203.0.113.10",
            UserAgent = "Ashlar.ProviderContractTests",
            CorrelationId = $"correlation-{Guid.NewGuid():N}",
            Outcome = outcome ?? "Success",
            FailureReason = outcome == "Failure" ? "invalid_credentials" : null,
            Properties = properties
        };
    }

    private static Dictionary<string, string>? DeserializeProperties(string? json)
    {
        return json == null ? null : JsonSerializer.Deserialize<Dictionary<string, string>>(json);
    }

    private static async Task FlushAsync(IServiceProvider serviceProvider)
    {
        if (GetPersistentSecurityEventSink(serviceProvider) is IAsyncDisposable asyncDisposable)
        {
            await asyncDisposable.DisposeAsync();
        }
    }
}
