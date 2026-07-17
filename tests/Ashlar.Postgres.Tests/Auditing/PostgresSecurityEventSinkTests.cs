using Microsoft.Extensions.DependencyInjection;
using Dapper;
using Ashlar.Identity.Models.AccountSecurity;
using Npgsql;

namespace Ashlar.Postgres.Tests.Auditing;

internal sealed class PostgresSecurityEventSinkTests : PostgresTestBase
{
    private IServiceProvider? _serviceProvider;

    [OneTimeSetUp]
    public override async Task OneTimeSetUp()
    {
        await base.OneTimeSetUp();

        var services = new ServiceCollection();
        services.AddAshlarPostgres(GetConnectionString());
        services.AddAshlarPostgresAuditSink();
        _serviceProvider = services.BuildServiceProvider();

        await _serviceProvider.InitializeAshlarPostgresSchemaAsync();
    }

    [OneTimeTearDown]
    public override async Task OneTimeTearDown()
    {
        if (_serviceProvider is IAsyncDisposable asyncDisposable)
        {
            await asyncDisposable.DisposeAsync();
        }

        await base.OneTimeTearDown();
    }

    [SetUp]
    public async Task SetUpAsync()
    {
        await using var connection = await GetDataSource().OpenConnectionAsync();
        await connection.ExecuteAsync("TRUNCATE ashlar_security_events");
    }

    [Test]
    public void ConstructorThrowsIfDataSourceIsNull()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new PostgresSecurityEventSink(null!));
    }

    [Test]
    public async Task RecordAsyncInsertsEvent()
    {
        var provider = new AuthenticationProviderKey(ProviderType.Local, "Password");
        var securityEvent = new AshlarSecurityEvent
        {
            Id = Guid.NewGuid(),
            EventType = "TestEvent",
            OccurredAt = DateTimeOffset.UtcNow,
            UserId = Guid.NewGuid(),
            TenantId = Guid.NewGuid(),
            ActorUserId = Guid.NewGuid(),
            SessionId = Guid.NewGuid(),
            Provider = provider,
            IpAddress = "127.0.0.1",
            UserAgent = "TestAgent",
            CorrelationId = "TestCorrelation",
            Outcome = "Success",
            FailureReason = null,
            Properties = new Dictionary<string, string> { { "Key", "Value" } }
        };

        var sink = new PostgresSecurityEventSink(new PostgresTransactionManager(GetDataSource()));
        await sink.RecordAsync(securityEvent);

        await using var connection = await GetDataSource().OpenConnectionAsync();
        var count = await connection.ExecuteScalarAsync<int>("SELECT count(*) FROM ashlar_security_events");
        Assert.That(count, Is.EqualTo(1));

        var row = await connection.QuerySingleAsync<dynamic>("SELECT * FROM ashlar_security_events");
        using (Assert.EnterMultipleScope())
        {
            Assert.That((Guid)row.id, Is.EqualTo(securityEvent.Id));
            Assert.That((string)row.event_type, Is.EqualTo(securityEvent.EventType));
            Assert.That((DateTimeOffset)row.occurred_at, Is.EqualTo(securityEvent.OccurredAt).Within(TimeSpan.FromMilliseconds(100)));
            Assert.That((Guid?)row.user_id, Is.EqualTo(securityEvent.UserId));
            Assert.That((Guid?)row.tenant_id, Is.EqualTo(securityEvent.TenantId));
            Assert.That((Guid?)row.actor_user_id, Is.EqualTo(securityEvent.ActorUserId));
            Assert.That((Guid?)row.session_id, Is.EqualTo(securityEvent.SessionId));
            Assert.That((string)row.provider_type, Is.EqualTo(provider.Type.Value));
            Assert.That((string)row.provider_name, Is.EqualTo(provider.Name));
            Assert.That((string)row.ip_address, Is.EqualTo(securityEvent.IpAddress));
            Assert.That((string)row.user_agent, Is.EqualTo(securityEvent.UserAgent));
            Assert.That((string)row.correlation_id, Is.EqualTo(securityEvent.CorrelationId));
            Assert.That((string)row.outcome, Is.EqualTo(securityEvent.Outcome));
            Assert.That((string)row.failure_reason, Is.Null);
        }

        var propertiesJson = (string)row.properties;
        var properties = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(propertiesJson);
        Assert.That(properties, Is.EquivalentTo(securityEvent.Properties));
    }

    [Test]
    public async Task RecordAsyncHandlesNullOptionalFields()
    {
        var securityEvent = new AshlarSecurityEvent
        {
            Id = Guid.NewGuid(),
            EventType = "TestEvent",
            OccurredAt = DateTimeOffset.UtcNow
        };

        var sink = new PostgresSecurityEventSink(new PostgresTransactionManager(GetDataSource()));
        await sink.RecordAsync(securityEvent);

        await using var connection = await GetDataSource().OpenConnectionAsync();
        var row = await connection.QuerySingleAsync<dynamic>("SELECT * FROM ashlar_security_events");
        using (Assert.EnterMultipleScope())
        {
            Assert.That((Guid)row.id, Is.EqualTo(securityEvent.Id));
            Assert.That((Guid?)row.user_id, Is.Null);
            Assert.That((string)row.provider_type, Is.Null);
            Assert.That((string)row.outcome, Is.Null);
            Assert.That((string)row.properties, Is.Null);
        }
    }

    [Test]
    public async Task RecordAsyncWithUninitializedProviderTypePersistsUnknownProviderType()
    {
        var securityEvent = new AshlarSecurityEvent
        {
            Id = Guid.NewGuid(),
            EventType = "TestEvent",
            OccurredAt = DateTimeOffset.UtcNow,
            Provider = (AuthenticationProviderKey?)default(AuthenticationProviderKey)
        };

        var sink = new PostgresSecurityEventSink(new PostgresTransactionManager(GetDataSource()));
        await sink.RecordAsync(securityEvent);

        await using var connection = await GetDataSource().OpenConnectionAsync();
        var row = await connection.QuerySingleAsync<dynamic>("SELECT provider_type, provider_name FROM ashlar_security_events");
        using (Assert.EnterMultipleScope())
        {
            Assert.That((string)row.provider_type, Is.EqualTo(ProviderType.StorageFallbackValue));
            Assert.That((string)row.provider_name, Is.EqualTo(string.Empty));
        }
    }

    [Test]
    public async Task RecordAsyncThrowsIfEventIsNull()
    {
        var sink = new PostgresSecurityEventSink(new PostgresTransactionManager(GetDataSource()));
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(async () => await sink.RecordAsync(null!));
    }

    [Test]
    public async Task MultipleEventsAreAppended()
    {
        var sink = new PostgresSecurityEventSink(new PostgresTransactionManager(GetDataSource()));
        await sink.RecordAsync(new AshlarSecurityEvent { Id = Guid.NewGuid(), EventType = "E1", OccurredAt = DateTimeOffset.UtcNow, Outcome = "S" });
        await sink.RecordAsync(new AshlarSecurityEvent { Id = Guid.NewGuid(), EventType = "E2", OccurredAt = DateTimeOffset.UtcNow, Outcome = "S" });

        await using var connection = await GetDataSource().OpenConnectionAsync();
        var count = await connection.ExecuteScalarAsync<int>("SELECT count(*) FROM ashlar_security_events");
        Assert.That(count, Is.EqualTo(2));
    }

    [Test]
    public async Task RecordAsyncParticipatesInCommittedTransaction()
    {
        await using var manager = new PostgresTransactionManager(GetDataSource());
        var sink = new PostgresSecurityEventSink(manager);
        await using var transaction = await manager.BeginTransactionAsync();

        await sink.RecordAsync(new AshlarSecurityEvent { Id = Guid.NewGuid(), EventType = "Committed", OccurredAt = DateTimeOffset.UtcNow });
        await transaction.CommitAsync();

        await using var connection = await GetDataSource().OpenConnectionAsync();
        var count = await connection.ExecuteScalarAsync<int>("SELECT count(*) FROM ashlar_security_events WHERE event_type = 'Committed'");
        Assert.That(count, Is.EqualTo(1));
    }

    [Test]
    public async Task RecordAsyncRollsBackWithActiveTransaction()
    {
        await using var manager = new PostgresTransactionManager(GetDataSource());
        var sink = new PostgresSecurityEventSink(manager);
        await using var transaction = await manager.BeginTransactionAsync();

        await sink.RecordAsync(new AshlarSecurityEvent { Id = Guid.NewGuid(), EventType = "RolledBack", OccurredAt = DateTimeOffset.UtcNow });
        await transaction.RollbackAsync();

        await using var connection = await GetDataSource().OpenConnectionAsync();
        var count = await connection.ExecuteScalarAsync<int>("SELECT count(*) FROM ashlar_security_events WHERE event_type = 'RolledBack'");
        Assert.That(count, Is.Zero);
    }

    [Test]
    public async Task CountSecurityEventsForUserAsyncCountsOnlyMatchingRecentUserEvents()
    {
        var userId = Guid.NewGuid();
        var otherUserId = Guid.NewGuid();
        var now = new DateTimeOffset(2026, 5, 17, 12, 0, 0, TimeSpan.Zero);

        var sink = new PostgresSecurityEventSink(new PostgresTransactionManager(GetDataSource()));
        await sink.RecordAsync(new AshlarSecurityEvent { Id = Guid.NewGuid(), EventType = "Recent1", UserId = userId, OccurredAt = now.AddMinutes(-5) });
        await sink.RecordAsync(new AshlarSecurityEvent { Id = Guid.NewGuid(), EventType = "Recent2", UserId = userId, OccurredAt = now.AddMinutes(-1) });
        await sink.RecordAsync(new AshlarSecurityEvent { Id = Guid.NewGuid(), EventType = "Old", UserId = userId, OccurredAt = now.AddDays(-2) });
        await sink.RecordAsync(new AshlarSecurityEvent { Id = Guid.NewGuid(), EventType = "OtherUser", UserId = otherUserId, OccurredAt = now });
        await sink.RecordAsync(new AshlarSecurityEvent { Id = Guid.NewGuid(), EventType = "NoUser", OccurredAt = now });

        var countingSink = new PostgresSecurityEventSink(new PostgresTransactionManager(GetDataSource()));
        var count = await new PostgresUserSecurityEventSummaryRepository(countingSink)
            .CountSecurityEventsForUserAsync(userId, now.AddHours(-1));

        Assert.That(count, Is.EqualTo(2));
    }

    [Test]
    public async Task AddAshlarPostgresDoesNotRegisterAuditSinkByDefault()
    {
        var services = new ServiceCollection();
        services.AddAshlarPostgres(GetConnectionString());
        await using var provider = services.BuildServiceProvider();

        var sink = provider.GetService<ISecurityEventSink>();

        Assert.That(sink, Is.Null);
    }

    [Test]
    public async Task AddAshlarPostgresAuditSinkRegistersPersistentSink()
    {
        var services = new ServiceCollection();
        services.AddAshlarIdentity();
        services.AddAshlarPostgres(GetConnectionString());
        services.AddAshlarPostgresAuditSink();
        await using var provider = services.BuildServiceProvider();

        var sink = provider.GetRequiredService<ISecurityEventSink>();
        var persistentSink = provider.GetRequiredAshlarProviderService<IPersistentSecurityEventSink>();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(sink, Is.TypeOf<SecurityEventFanOutSink>());
            Assert.That(persistentSink, Is.TypeOf<PostgresSecurityEventSink>());
            Assert.That(provider.GetRequiredService<IUserSecurityEventSummaryRepository>(), Is.TypeOf<PostgresUserSecurityEventSummaryRepository>());
        }
    }

    [Test]
    public async Task RecordAsyncThrowsPersistenceFailuresAndAllowsLaterWrites()
    {
        var invalidEvent = new AshlarSecurityEvent
        {
            Id = Guid.NewGuid(),
            // ReSharper disable once NullableWarningSuppressionIsUsed
            EventType = null!, // This will cause a PostgresException due to NOT NULL constraint
            OccurredAt = DateTimeOffset.UtcNow
        };

        var validEvent = new AshlarSecurityEvent
        {
            Id = Guid.NewGuid(),
            EventType = "ValidEvent",
            OccurredAt = DateTimeOffset.UtcNow
        };

        var sink = new PostgresSecurityEventSink(new PostgresTransactionManager(GetDataSource()));
        Assert.ThrowsAsync<PostgresException>(async () => await sink.RecordAsync(invalidEvent));
        await sink.RecordAsync(validEvent);

        await using var connection = await GetDataSource().OpenConnectionAsync();
        var count = await connection.ExecuteScalarAsync<int>("SELECT count(*) FROM ashlar_security_events");

        Assert.That(count, Is.EqualTo(1));
    }
}
