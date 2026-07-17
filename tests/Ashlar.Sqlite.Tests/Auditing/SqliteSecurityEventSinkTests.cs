using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.DependencyInjection;

namespace Ashlar.Sqlite.Tests.Auditing;

internal sealed class SqliteSecurityEventSinkTests : SqliteTestBase
{
    private ServiceProvider _serviceProvider = null!;

    [SetUp]
    public async Task SetUp()
    {
        var services = new ServiceCollection();
        services.AddAshlarSqlite(GetConnectionString());
        services.AddAshlarSqliteAuditSink();
        _serviceProvider = services.BuildServiceProvider();
        await _serviceProvider.InitializeAshlarSqliteSchemaAsync();
    }

    [TearDown]
    public async Task TearDownAsync()
    {
        await _serviceProvider.DisposeAsync();
    }

    [Test]
    public async Task RecordAsyncInsertsEventAndSerializesPropertiesAsText()
    {
        var provider = new AuthenticationProviderKey(ProviderType.Local, "Password");
        var securityEvent = new AshlarSecurityEvent
        {
            Id = Guid.NewGuid(),
            EventType = "TestEvent",
            OccurredAt = new DateTimeOffset(2026, 5, 17, 12, 0, 0, TimeSpan.Zero),
            UserId = Guid.NewGuid(),
            TenantId = Guid.NewGuid(),
            ActorUserId = Guid.NewGuid(),
            SessionId = Guid.NewGuid(),
            Provider = provider,
            IpAddress = "127.0.0.1",
            UserAgent = "TestAgent",
            CorrelationId = "TestCorrelation",
            Outcome = "Success",
            Properties = new Dictionary<string, string> { ["Key"] = "Value" }
        };

        var sink = CreateSink();
        await sink.RecordAsync(securityEvent);

        var row = await ReadSingleEventAsync();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(row.Id, Is.EqualTo(securityEvent.Id));
            Assert.That(row.EventType, Is.EqualTo("TestEvent"));
            Assert.That(row.OccurredAt, Is.EqualTo(securityEvent.OccurredAt));
            Assert.That(row.UserId, Is.EqualTo(securityEvent.UserId));
            Assert.That(row.TenantId, Is.EqualTo(securityEvent.TenantId));
            Assert.That(row.ActorUserId, Is.EqualTo(securityEvent.ActorUserId));
            Assert.That(row.SessionId, Is.EqualTo(securityEvent.SessionId));
            Assert.That(row.ProviderType, Is.EqualTo(provider.Type.Value));
            Assert.That(row.ProviderName, Is.EqualTo(provider.Name));
            Assert.That(row.IpAddress, Is.EqualTo("127.0.0.1"));
            Assert.That(row.UserAgent, Is.EqualTo("TestAgent"));
            Assert.That(row.CorrelationId, Is.EqualTo("TestCorrelation"));
            Assert.That(row.Outcome, Is.EqualTo("Success"));
            Assert.That(row.FailureReason, Is.Null);
        }

        var properties = JsonSerializer.Deserialize<Dictionary<string, string>>(row.Properties!);
        Assert.That(properties, Is.EquivalentTo(securityEvent.Properties));
    }

    [Test]
    public async Task RecordAsyncHandlesNullOptionalFieldsAndDefaultProviderShape()
    {
        var securityEvent = new AshlarSecurityEvent
        {
            Id = Guid.NewGuid(),
            EventType = "Nulls",
            OccurredAt = DateTimeOffset.UtcNow,
            Provider = (AuthenticationProviderKey?)default(AuthenticationProviderKey)
        };

        var sink = CreateSink();
        await sink.RecordAsync(securityEvent);

        var row = await ReadSingleEventAsync();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(row.UserId, Is.Null);
            Assert.That(row.TenantId, Is.Null);
            Assert.That(row.ProviderType, Is.EqualTo(ProviderType.StorageFallbackValue));
            Assert.That(row.ProviderName, Is.EqualTo(string.Empty));
            Assert.That(row.Outcome, Is.Null);
            Assert.That(row.Properties, Is.Null);
        }
    }

    [Test]
    public async Task CountSecurityEventsForUserAsyncUsesInclusiveSinceAndUserIsolation()
    {
        var userId = Guid.NewGuid();
        var otherUserId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var otherTenantId = Guid.NewGuid();
        var now = new DateTimeOffset(2026, 5, 17, 12, 0, 0, TimeSpan.Zero);
        var since = now.AddHours(-1);
        var sink = CreateSink();

        await sink.RecordAsync(new AshlarSecurityEvent { Id = Guid.NewGuid(), EventType = "Boundary", UserId = userId, TenantId = tenantId, OccurredAt = since });
        await sink.RecordAsync(new AshlarSecurityEvent { Id = Guid.NewGuid(), EventType = "Recent", UserId = userId, TenantId = tenantId, OccurredAt = now.AddMinutes(-5) });
        await sink.RecordAsync(new AshlarSecurityEvent { Id = Guid.NewGuid(), EventType = "Old", UserId = userId, TenantId = tenantId, OccurredAt = since.AddTicks(-1) });
        await sink.RecordAsync(new AshlarSecurityEvent { Id = Guid.NewGuid(), EventType = "OtherUser", UserId = otherUserId, TenantId = tenantId, OccurredAt = now });
        await sink.RecordAsync(new AshlarSecurityEvent { Id = Guid.NewGuid(), EventType = "OtherTenant", UserId = userId, TenantId = otherTenantId, OccurredAt = now });
        await sink.RecordAsync(new AshlarSecurityEvent { Id = Guid.NewGuid(), EventType = "NoUser", TenantId = tenantId, OccurredAt = now });

        var count = await new SqliteUserSecurityEventSummaryRepository(CreateSink())
            .CountSecurityEventsForUserAsync(userId, since);
        var eventTypeCount = await CountEventsByTypeAsync("Recent");
        var tenantCount = await CountEventsByTenantAsync(tenantId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(count, Is.EqualTo(3));
            Assert.That(eventTypeCount, Is.EqualTo(1));
            Assert.That(tenantCount, Is.EqualTo(5));
        }
    }

    [Test]
    public async Task RecordAsyncParticipatesInCommittedTransaction()
    {
        var manager = _serviceProvider.GetRequiredService<AshlarDurableTransactionProvider>();
        var sink = CreateSink();
        await using var transaction = await manager.BeginTransactionAsync();

        await sink.RecordAsync(new AshlarSecurityEvent { Id = Guid.NewGuid(), EventType = "Committed", OccurredAt = DateTimeOffset.UtcNow });
        await transaction.CommitAsync();

        Assert.That(await CountEventsByTypeAsync("Committed"), Is.EqualTo(1));
    }

    [Test]
    public async Task RecordAsyncRollsBackWithActiveTransaction()
    {
        var manager = _serviceProvider.GetRequiredService<AshlarDurableTransactionProvider>();
        var sink = CreateSink();
        await using var transaction = await manager.BeginTransactionAsync();

        await sink.RecordAsync(new AshlarSecurityEvent { Id = Guid.NewGuid(), EventType = "RolledBack", OccurredAt = DateTimeOffset.UtcNow });
        await transaction.RollbackAsync();

        Assert.That(await CountEventsByTypeAsync("RolledBack"), Is.Zero);
    }

    [Test]
    public async Task RecordAsyncThrowsForNullEventAndPersistenceFailureAndAllowsLaterWrites()
    {
        var sink = CreateSink();
        Assert.ThrowsAsync<ArgumentNullException>(async () => await sink.RecordAsync(null!));

        Assert.ThrowsAsync<SqliteException>(async () => await sink.RecordAsync(new AshlarSecurityEvent
        {
            Id = Guid.NewGuid(),
            EventType = null!,
            OccurredAt = DateTimeOffset.UtcNow
        }));
        await sink.RecordAsync(new AshlarSecurityEvent
        {
            Id = Guid.NewGuid(),
            EventType = "ValidEvent",
            OccurredAt = DateTimeOffset.UtcNow
        });

        Assert.That(await CountEventsAsync(), Is.EqualTo(1));
    }

    [Test]
    public void ConstructorThrowsIfConnectionFactoryIsNull()
    {
        Assert.Throws<ArgumentNullException>(() => _ = new SqliteSecurityEventSink(null!));
    }

    [Test]
    public void ConstructorAcceptsNonNullLogger()
    {
        var sink = new SqliteSecurityEventSink(
            _serviceProvider.GetRequiredService<ISqliteConnectionProvider>(),
            NullLogger<SqliteSecurityEventSink>.Instance);

        Assert.That(sink, Is.Not.Null);
    }

    private SqliteSecurityEventSink CreateSink()
    {
        return new SqliteSecurityEventSink(_serviceProvider.GetRequiredService<ISqliteConnectionProvider>());
    }

    private async Task<int> CountEventsAsync()
    {
        await using var connection = await OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM ashlar_security_events;";
        return Convert.ToInt32(await command.ExecuteScalarAsync(), System.Globalization.CultureInfo.InvariantCulture);
    }

    private async Task<int> CountEventsByTypeAsync(string eventType)
    {
        await using var connection = await OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM ashlar_security_events WHERE event_type = $eventType;";
        command.AddParameter("$eventType", eventType);
        return Convert.ToInt32(await command.ExecuteScalarAsync(), System.Globalization.CultureInfo.InvariantCulture);
    }

    private async Task<int> CountEventsByTenantAsync(Guid tenantId)
    {
        await using var connection = await OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM ashlar_security_events WHERE tenant_id = $tenantId;";
        command.AddGuidParameter("$tenantId", tenantId);
        return Convert.ToInt32(await command.ExecuteScalarAsync(), System.Globalization.CultureInfo.InvariantCulture);
    }

    private async Task<EventRow> ReadSingleEventAsync()
    {
        await using var connection = await OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, event_type, occurred_at, user_id, tenant_id, actor_user_id, session_id,
                   provider_type, provider_name, ip_address, user_agent, correlation_id, outcome, failure_reason, properties
            FROM ashlar_security_events;
            """;
        await using var reader = await command.ExecuteReaderAsync();
        Assert.That(await reader.ReadAsync(), Is.True);
        return new EventRow(
            reader.GetGuidFromText("id"),
            reader.GetString(reader.GetOrdinal("event_type")),
            reader.GetDateTimeOffsetFromText("occurred_at"),
            reader.GetNullableGuidFromText("user_id"),
            reader.GetNullableGuidFromText("tenant_id"),
            reader.GetNullableGuidFromText("actor_user_id"),
            reader.GetNullableGuidFromText("session_id"),
            reader.GetNullableString("provider_type"),
            reader.GetNullableString("provider_name"),
            reader.GetNullableString("ip_address"),
            reader.GetNullableString("user_agent"),
            reader.GetNullableString("correlation_id"),
            reader.GetNullableString("outcome"),
            reader.GetNullableString("failure_reason"),
            reader.GetNullableString("properties"));
    }

    private sealed record EventRow(
        Guid Id,
        string EventType,
        DateTimeOffset OccurredAt,
        Guid? UserId,
        Guid? TenantId,
        Guid? ActorUserId,
        Guid? SessionId,
        string? ProviderType,
        string? ProviderName,
        string? IpAddress,
        string? UserAgent,
        string? CorrelationId,
        string? Outcome,
        string? FailureReason,
        string? Properties);
}
