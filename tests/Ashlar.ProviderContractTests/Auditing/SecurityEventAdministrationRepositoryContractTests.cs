namespace Ashlar.ProviderContractTests.Auditing;

internal abstract class SecurityEventAdministrationRepositoryContractTests : ProviderContractFixture
{
    private static readonly DateTimeOffset BaseTime = new(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);

    [Test]
    public async Task SecurityEventAdministrationSearchReturnsNewestFirstWithDeterministicIdTieBreaker()
    {
        await using var scope = CreateAsyncScope();
        var older = await RecordAsync(scope.ServiceProvider, "Older", occurredAt: BaseTime.AddMinutes(-1));
        var lowerTie = await RecordAsync(scope.ServiceProvider, "LowerTie", id: Guid.Parse("00000000-0000-0000-0000-000000000001"), occurredAt: BaseTime);
        var higherTie = await RecordAsync(scope.ServiceProvider, "HigherTie", id: Guid.Parse("ffffffff-ffff-ffff-ffff-ffffffffffff"), occurredAt: BaseTime);
        await FlushAsync(scope.ServiceProvider);

        var result = await GetSecurityEventAdministrationRepository(scope.ServiceProvider).SearchSecurityEventsAsync(new SearchSecurityEventsRequest { IncludeAllTenants = true, Limit = 10 });

        Assert.That(result.Select(static securityEvent => securityEvent.EventId), Is.EqualTo(new[] { higherTie.Id, lowerTie.Id, older.Id }));
    }

    [Test]
    public async Task SecurityEventAdministrationSearchFiltersTenantScopes()
    {
        await using var scope = CreateAsyncScope();
        var tenantId = Guid.NewGuid();
        var tenantEvent = await RecordAsync(scope.ServiceProvider, "Tenant", tenantId: tenantId);
        var globalEvent = await RecordAsync(scope.ServiceProvider, "Global");
        var otherTenantEvent = await RecordAsync(scope.ServiceProvider, "OtherTenant", tenantId: Guid.NewGuid());
        await FlushAsync(scope.ServiceProvider);

        var repository = GetSecurityEventAdministrationRepository(scope.ServiceProvider);
        var scoped = await repository.SearchSecurityEventsAsync(new SearchSecurityEventsRequest { Tenant = new TenantContext(tenantId), Limit = 10 });
        var global = await repository.SearchSecurityEventsAsync(new SearchSecurityEventsRequest { Tenant = TenantContext.Global, Limit = 10 });
        var unscoped = await repository.SearchSecurityEventsAsync(new SearchSecurityEventsRequest { IncludeAllTenants = true, Limit = 10 });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scoped.Select(static securityEvent => securityEvent.EventId), Is.EqualTo(new[] { tenantEvent.Id }));
            Assert.That(global.Select(static securityEvent => securityEvent.EventId), Is.EqualTo(new[] { globalEvent.Id }));
            Assert.That(unscoped.Select(static securityEvent => securityEvent.EventId), Does.Contain(tenantEvent.Id));
            Assert.That(unscoped.Select(static securityEvent => securityEvent.EventId), Does.Contain(globalEvent.Id));
            Assert.That(unscoped.Select(static securityEvent => securityEvent.EventId), Does.Contain(otherTenantEvent.Id));
        }
    }

    [Test]
    public async Task SecurityEventAdministrationSearchRequiresExplicitTenantScopeOrAllTenantsMode()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetSecurityEventAdministrationRepository(scope.ServiceProvider);

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentException>(() => repository.SearchSecurityEventsAsync(new SearchSecurityEventsRequest { Limit = 10 }));
            Assert.ThrowsAsync<ArgumentException>(() => repository.SearchSecurityEventsAsync(new SearchSecurityEventsRequest { Tenant = TenantContext.Global, IncludeAllTenants = true, Limit = 10 }));
        }
    }

    [Test]
    public async Task SecurityEventAdministrationSearchFiltersIdentityFields()
    {
        await using var scope = CreateAsyncScope();
        var userId = Guid.NewGuid();
        var actorUserId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var matching = await RecordAsync(scope.ServiceProvider, "MatchingIdentity", userId: userId, actorUserId: actorUserId, sessionId: sessionId);
        await RecordAsync(scope.ServiceProvider, "WrongUser", userId: Guid.NewGuid(), actorUserId: actorUserId, sessionId: sessionId);
        await RecordAsync(scope.ServiceProvider, "WrongActor", userId: userId, actorUserId: Guid.NewGuid(), sessionId: sessionId);
        await RecordAsync(scope.ServiceProvider, "WrongSession", userId: userId, actorUserId: actorUserId, sessionId: Guid.NewGuid());
        await FlushAsync(scope.ServiceProvider);

        var result = await GetSecurityEventAdministrationRepository(scope.ServiceProvider).SearchSecurityEventsAsync(new SearchSecurityEventsRequest
        {
            IncludeAllTenants = true,
            UserId = userId,
            ActorUserId = actorUserId,
            SessionId = sessionId,
            Limit = 10
        });

        Assert.That(result.Select(static securityEvent => securityEvent.EventId), Is.EqualTo(new[] { matching.Id }));
    }

    [Test]
    public async Task SecurityEventAdministrationSearchFiltersEventTypeOutcomeFailureAndProvider()
    {
        await using var scope = CreateAsyncScope();
        var provider = AuthenticationProviderKey.Local;
        var matching = await RecordAsync(scope.ServiceProvider, "PasswordSignIn", provider: provider, outcome: SecurityEventOutcomes.Failure, failureReason: "bad_password");
        await RecordAsync(scope.ServiceProvider, "TotpSignIn", provider: provider, outcome: SecurityEventOutcomes.Failure, failureReason: "bad_password");
        await RecordAsync(scope.ServiceProvider, "PasswordSignIn", provider: AuthenticationProviderKey.EmailCode, outcome: SecurityEventOutcomes.Failure, failureReason: "bad_password");
        await RecordAsync(scope.ServiceProvider, "PasswordSignIn", provider: provider, outcome: SecurityEventOutcomes.Success, failureReason: "bad_password");
        await RecordAsync(scope.ServiceProvider, "PasswordSignIn", provider: provider, outcome: SecurityEventOutcomes.Failure, failureReason: "other");
        await FlushAsync(scope.ServiceProvider);

        var result = await GetSecurityEventAdministrationRepository(scope.ServiceProvider).SearchSecurityEventsAsync(new SearchSecurityEventsRequest
        {
            IncludeAllTenants = true,
            EventTypes = new HashSet<string>(StringComparer.Ordinal) { "PasswordSignIn", "Unused" },
            Outcome = SecurityEventOutcomes.Failure,
            FailureReason = "bad_password",
            Provider = provider,
            Limit = 10
        });

        Assert.That(result.Select(static securityEvent => securityEvent.EventId), Is.EqualTo(new[] { matching.Id }));
    }

    [Test]
    public async Task SecurityEventAdministrationSearchIgnoresBlankEventTypeFilters()
    {
        await using var scope = CreateAsyncScope();
        var stored = await RecordAsync(scope.ServiceProvider, "AnyEvent");
        await FlushAsync(scope.ServiceProvider);

        var result = await GetSecurityEventAdministrationRepository(scope.ServiceProvider).SearchSecurityEventsAsync(new SearchSecurityEventsRequest
        {
            IncludeAllTenants = true,
            EventTypes = new HashSet<string>(StringComparer.Ordinal) { " ", string.Empty },
            Limit = 10
        });

        Assert.That(result.Select(static securityEvent => securityEvent.EventId), Does.Contain(stored.Id));
    }

    [Test]
    public async Task SecurityEventAdministrationSearchUsesInclusiveOccurredDateRange()
    {
        await using var scope = CreateAsyncScope();
        await RecordAsync(scope.ServiceProvider, "Before", occurredAt: BaseTime.AddMilliseconds(-1));
        var from = await RecordAsync(scope.ServiceProvider, "From", occurredAt: BaseTime);
        var inside = await RecordAsync(scope.ServiceProvider, "Inside", occurredAt: BaseTime.AddMinutes(1));
        var to = await RecordAsync(scope.ServiceProvider, "To", occurredAt: BaseTime.AddMinutes(2));
        await RecordAsync(scope.ServiceProvider, "After", occurredAt: BaseTime.AddMinutes(2).AddMilliseconds(1));
        await FlushAsync(scope.ServiceProvider);

        var result = await GetSecurityEventAdministrationRepository(scope.ServiceProvider).SearchSecurityEventsAsync(new SearchSecurityEventsRequest
        {
            IncludeAllTenants = true,
            OccurredFrom = BaseTime,
            OccurredTo = BaseTime.AddMinutes(2),
            Limit = 10
        });

        Assert.That(result.Select(static securityEvent => securityEvent.EventId), Is.EqualTo(new[] { to.Id, inside.Id, from.Id }));
    }

    [Test]
    public async Task SecurityEventAdministrationSearchSupportsLimitOffsetForHasMore()
    {
        await using var scope = CreateAsyncScope();
        var first = await RecordAsync(scope.ServiceProvider, "First", occurredAt: BaseTime.AddMinutes(3));
        var second = await RecordAsync(scope.ServiceProvider, "Second", occurredAt: BaseTime.AddMinutes(2));
        var third = await RecordAsync(scope.ServiceProvider, "Third", occurredAt: BaseTime.AddMinutes(1));
        await FlushAsync(scope.ServiceProvider);

        var result = await GetSecurityEventAdministrationRepository(scope.ServiceProvider).SearchSecurityEventsAsync(new SearchSecurityEventsRequest { IncludeAllTenants = true, Limit = 2, Offset = 1 });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Select(static securityEvent => securityEvent.EventId), Is.EqualTo(new[] { second.Id, third.Id }));
            Assert.That(result.Select(static securityEvent => securityEvent.EventId), Does.Not.Contain(first.Id));
        }
    }

    [Test]
    public async Task SecurityEventAdministrationGetEventByIdReturnsEventAndMissingReturnsNull()
    {
        await using var scope = CreateAsyncScope();
        var stored = await RecordAsync(scope.ServiceProvider, "Detail", provider: AuthenticationProviderKey.Local, properties: new Dictionary<string, string> { ["reason"] = "diagnostic" });
        await FlushAsync(scope.ServiceProvider);

        var repository = GetSecurityEventAdministrationRepository(scope.ServiceProvider);
        var found = await repository.GetSecurityEventAsync(new SecurityEventAdministrationDetailRequest(stored.Id, IncludeAllTenants: true));
        var missing = await repository.GetSecurityEventAsync(new SecurityEventAdministrationDetailRequest(Guid.NewGuid(), IncludeAllTenants: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(found?.EventId, Is.EqualTo(stored.Id));
            Assert.That(found?.Provider, Is.EqualTo(AuthenticationProviderKey.Local));
            Assert.That(found?.Properties, Does.ContainKey("reason").WithValue("diagnostic"));
            Assert.That(missing, Is.Null);
        }
    }

    [Test]
    public async Task SecurityEventAdministrationGetEventByIdAppliesExplicitTenantScopeWithoutLeakingExistence()
    {
        await using var scope = CreateAsyncScope();
        var tenantId = Guid.NewGuid();
        var otherTenantId = Guid.NewGuid();
        var stored = await RecordAsync(scope.ServiceProvider, "ScopedDetail", tenantId: tenantId);
        var globalStored = await RecordAsync(scope.ServiceProvider, "GlobalDetail");
        await FlushAsync(scope.ServiceProvider);

        var repository = GetSecurityEventAdministrationRepository(scope.ServiceProvider);
        var inScope = await repository.GetSecurityEventAsync(new SecurityEventAdministrationDetailRequest(stored.Id, new TenantContext(tenantId)));
        var outOfScope = await repository.GetSecurityEventAsync(new SecurityEventAdministrationDetailRequest(stored.Id, new TenantContext(otherTenantId)));
        var globalScope = await repository.GetSecurityEventAsync(new SecurityEventAdministrationDetailRequest(stored.Id, TenantContext.Global));
        var globalInScope = await repository.GetSecurityEventAsync(new SecurityEventAdministrationDetailRequest(globalStored.Id, TenantContext.Global));
        var allTenants = await repository.GetSecurityEventAsync(new SecurityEventAdministrationDetailRequest(stored.Id, IncludeAllTenants: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(inScope?.EventId, Is.EqualTo(stored.Id));
            Assert.That(outOfScope, Is.Null);
            Assert.That(globalScope, Is.Null);
            Assert.That(globalInScope?.EventId, Is.EqualTo(globalStored.Id));
            Assert.That(allTenants?.EventId, Is.EqualTo(stored.Id));
        }
    }

    [Test]
    public async Task SecurityEventAdministrationGetEventByIdRequiresExplicitTenantScopeOrAllTenantsMode()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetSecurityEventAdministrationRepository(scope.ServiceProvider);
        var eventId = Guid.NewGuid();

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentException>(() => repository.GetSecurityEventAsync(new SecurityEventAdministrationDetailRequest(eventId)));
            Assert.ThrowsAsync<ArgumentException>(() => repository.GetSecurityEventAsync(new SecurityEventAdministrationDetailRequest(eventId, TenantContext.Global, IncludeAllTenants: true)));
        }
    }

    [Test]
    public async Task SecurityEventAdministrationPropertiesDeserializeSafely()
    {
        await using var scope = CreateAsyncScope();
        var withProperties = await RecordAsync(scope.ServiceProvider, "WithProperties", properties: new Dictionary<string, string> { ["ipRisk"] = "low", ["empty"] = string.Empty });
        var withoutProperties = await RecordAsync(scope.ServiceProvider, "WithoutProperties");
        await FlushAsync(scope.ServiceProvider);

        var repository = GetSecurityEventAdministrationRepository(scope.ServiceProvider);
        var found = await repository.GetSecurityEventAsync(new SecurityEventAdministrationDetailRequest(withProperties.Id, IncludeAllTenants: true));
        var empty = await repository.GetSecurityEventAsync(new SecurityEventAdministrationDetailRequest(withoutProperties.Id, IncludeAllTenants: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(found?.Properties, Does.ContainKey("ipRisk").WithValue("low"));
            Assert.That(found?.Properties, Does.ContainKey("empty").WithValue(string.Empty));
            Assert.That(empty?.Properties, Is.Null);
        }
    }

    private static async Task<AshlarSecurityEvent> RecordAsync(
        IServiceProvider serviceProvider,
        string eventType,
        Guid? id = null,
        DateTimeOffset? occurredAt = null,
        Guid? userId = null,
        Guid? tenantId = null,
        Guid? actorUserId = null,
        Guid? sessionId = null,
        AuthenticationProviderKey? provider = null,
        string? outcome = null,
        string? failureReason = null,
        IReadOnlyDictionary<string, string>? properties = null)
    {
        var securityEvent = new AshlarSecurityEvent
        {
            Id = id ?? Guid.NewGuid(),
            EventType = eventType,
            OccurredAt = occurredAt ?? BaseTime,
            UserId = userId,
            TenantId = tenantId,
            ActorUserId = actorUserId,
            SessionId = sessionId,
            Provider = provider,
            IpAddress = "203.0.113.10",
            UserAgent = "Contract Test",
            CorrelationId = "correlation-" + eventType,
            Outcome = outcome ?? SecurityEventOutcomes.Success,
            FailureReason = failureReason,
            Properties = properties
        };

        await GetSecurityEventSink(serviceProvider).RecordAsync(securityEvent);
        return securityEvent;
    }

    private static async Task FlushAsync(IServiceProvider serviceProvider)
    {
        if (GetPersistentSecurityEventSink(serviceProvider) is IAsyncDisposable asyncDisposable)
        {
            await asyncDisposable.DisposeAsync();
        }
    }
}
