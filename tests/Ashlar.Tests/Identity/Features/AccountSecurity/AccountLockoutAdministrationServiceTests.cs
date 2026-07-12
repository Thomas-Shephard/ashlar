using Ashlar.Identity.Features.AccountLockout;
using Ashlar.Identity.Models.AccountLockout;
using Ashlar.Auditing;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Identity.Features.AccountSecurity;

internal sealed class AccountLockoutAdministrationServiceTests
{
    private static readonly Guid UserId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid TenantId = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly DateTimeOffset Now = new(2026, 6, 1, 10, 0, 0, TimeSpan.Zero);

    private FakeTimeProvider _timeProvider;
    private InMemoryAccountLockoutRepository _repository;
    private RecordingSecurityEventSink _events;
    private DurableSecurityMutationTestComposition _composition;
    private AccountLockoutAdministrationService _service;
    private AccountLockoutAdministrationReader _reader;

    [SetUp]
    public void SetUp()
    {
        _timeProvider = new FakeTimeProvider(Now);
        _repository = new InMemoryAccountLockoutRepository();
        _events = new RecordingSecurityEventSink();
        _composition = new DurableSecurityMutationTestComposition(_events);
        _service = new AccountLockoutAdministrationService(
            _repository,
            new AccountLockoutAdministrationServiceDependencies(_timeProvider, _composition.Events, _composition.Transactions));
        _reader = new AccountLockoutAdministrationReader(_repository, _timeProvider);
    }

    [Test]
    public async Task SearchLockoutsAsyncShouldReturnSafePagedSummaries()
    {
        _repository.Seed(CreateRecord(UserId, TenantId, AuthenticationProviderKey.Local, lockedUntil: Now.AddMinutes(5), version: "secret-version"));
        _repository.Seed(CreateRecord(Guid.NewGuid(), TenantId, new AuthenticationProviderKey(ProviderType.OAuth, "github"), failedAt: Now.AddMinutes(-1), version: "other-version"));

        var result = await _reader.SearchLockoutsAsync(new SearchAccountLockoutsRequest
        {
            Tenant = new TenantContext(TenantId),
            Limit = 1
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.Items, Has.Count.EqualTo(1));
            Assert.That(result.Value?.Limit, Is.EqualTo(1));
            Assert.That(result.Value?.Offset, Is.Zero);
            Assert.That(result.Value?.HasMore, Is.True);
            Assert.That(result.Value?.Items[0].TenantId, Is.EqualTo(TenantId));
            Assert.That(result.Value?.Items[0].IsLockedOut, Is.False);
            Assert.That(result.Value?.Items[0].GetType().GetProperty("Version"), Is.Null);
        }
    }

    [Test]
    public async Task SearchLockoutsAsyncShouldFilterActiveLockoutsAfterRepositoryPaging()
    {
        _repository.Seed(CreateRecord(UserId, TenantId, AuthenticationProviderKey.Local, lockedUntil: Now.AddMinutes(5)));
        var unlockedUserId = Guid.NewGuid();
        _repository.Seed(CreateRecord(unlockedUserId, TenantId, AuthenticationProviderKey.Local, failedAt: Now.AddMinutes(-1)));
        _repository.Seed(CreateRecord(Guid.NewGuid(), null, AuthenticationProviderKey.Local, lockedUntil: Now.AddMinutes(10)));

        var locked = await _reader.SearchLockoutsAsync(new SearchAccountLockoutsRequest
        {
            Tenant = new TenantContext(TenantId),
            LockedOut = true,
            Limit = 10
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(locked.Succeeded, Is.True);
            Assert.That(locked.Value?.Items, Has.Count.EqualTo(1));
            Assert.That(locked.Value?.Items.Single().UserId, Is.EqualTo(UserId));
            Assert.That(locked.Value?.Items.Single().IsLockedOut, Is.True);
        }

        var unlocked = await _reader.SearchLockoutsAsync(new SearchAccountLockoutsRequest
        {
            Tenant = new TenantContext(TenantId),
            LockedOut = false,
            Limit = 10
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(unlocked.Succeeded, Is.True);
            Assert.That(unlocked.Value?.Items, Has.Count.EqualTo(1));
            Assert.That(unlocked.Value?.Items.Single().UserId, Is.EqualTo(unlockedUserId));
            Assert.That(unlocked.Value?.HasMore, Is.False);
        }
    }

    [Test]
    public async Task GetLockoutStatusAsyncShouldReturnCurrentStatusOrUnlockedStatusWhenMissing()
    {
        _repository.Seed(CreateRecord(UserId, TenantId, AuthenticationProviderKey.Local, lockedUntil: Now.AddMinutes(5)));

        var existing = await _reader.GetLockoutStatusAsync(UserId, AuthenticationProviderKey.Local, new AccountLockoutStatusRequest(new TenantContext(TenantId)));
        var result = await _reader.GetLockoutStatusAsync(UserId, AuthenticationProviderKey.Local, new AccountLockoutStatusRequest(new TenantContext(TenantId)));
        await _service.ResetLockoutAsync(UserId, AuthenticationProviderKey.Local, new ResetAccountLockoutRequest(new TenantContext(TenantId), CreateAudit()));
        var missing = await _reader.GetLockoutStatusAsync(UserId, AuthenticationProviderKey.Local, new AccountLockoutStatusRequest(new TenantContext(TenantId)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(existing.Succeeded, Is.True);
            Assert.That(existing.Value?.FailedAttemptCount, Is.EqualTo(3));
            Assert.That(existing.Value?.IsLockedOut, Is.True);
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.UserId, Is.EqualTo(UserId));
            Assert.That(result.Value?.TenantId, Is.EqualTo(TenantId));
            Assert.That(missing.Value?.FailedAttemptCount, Is.Zero);
            Assert.That(missing.Value?.IsLockedOut, Is.False);
        }
    }

    [Test]
    public async Task ResetLockoutAsyncShouldClearOnlyAutomaticLockoutState()
    {
        _repository.Seed(CreateRecord(UserId, TenantId, AuthenticationProviderKey.Local, lockedUntil: Now.AddMinutes(5)));

        var reset = await _service.ResetLockoutAsync(UserId, AuthenticationProviderKey.Local, new ResetAccountLockoutRequest(new TenantContext(TenantId), CreateAudit()));
        var secondReset = await _service.ResetLockoutAsync(UserId, AuthenticationProviderKey.Local, new ResetAccountLockoutRequest(new TenantContext(TenantId), CreateAudit()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(reset.Succeeded, Is.True);
            Assert.That(reset.Value?.Status, Is.EqualTo(AccountLockoutResetStatus.Reset));
            Assert.That(reset.Value?.UserId, Is.EqualTo(UserId));
            Assert.That(reset.Value?.TenantId, Is.EqualTo(TenantId));
            Assert.That(reset.Value?.Provider, Is.EqualTo(AuthenticationProviderKey.Local));
            Assert.That(secondReset.Succeeded, Is.True);
            Assert.That(secondReset.Value?.Status, Is.EqualTo(AccountLockoutResetStatus.NotFound));
            Assert.That(secondReset.Value?.UserId, Is.EqualTo(UserId));
            Assert.That(secondReset.Value?.TenantId, Is.EqualTo(TenantId));
            Assert.That(secondReset.Value?.Provider, Is.EqualTo(AuthenticationProviderKey.Local));
        }
    }

    [Test]
    public async Task ResetLockoutAsyncShouldCommitWhenTransactionProviderIsConfigured()
    {
        var transactionProvider = new RecordingTransactionProvider();
        var composition = DurableSecurityMutationTestComposition.Create(transactionProvider, _events);
        _repository.Seed(CreateRecord(UserId, TenantId, AuthenticationProviderKey.Local, lockedUntil: Now.AddMinutes(5)));
        var service = new AccountLockoutAdministrationService(
            _repository,
            new AccountLockoutAdministrationServiceDependencies(_timeProvider, composition.Events, transactionProvider));

        var result = await service.ResetLockoutAsync(
            UserId,
            AuthenticationProviderKey.Local,
            new ResetAccountLockoutRequest(new TenantContext(TenantId), CreateAudit()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(transactionProvider.Transaction.BeginCount, Is.EqualTo(1));
            Assert.That(transactionProvider.Transaction.CommitCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task ResetLockoutAsyncShouldEmitSafeAuditEventWhenStateIsCleared()
    {
        var actorId = Guid.Parse("33333333-3333-3333-3333-333333333333");
        var audit = new AuditContext(actorId, "203.0.113.10", "admin-agent", "corr-reset");
        var provider = new AuthenticationProviderKey(ProviderType.OAuth, "github");
        _repository.Seed(CreateRecord(UserId, TenantId, provider, lockedUntil: Now.AddMinutes(5), version: "secret-version"));

        var result = await _service.ResetLockoutAsync(
            UserId,
            provider,
            new ResetAccountLockoutRequest(new TenantContext(TenantId), audit, "support reset"));

        var securityEvent = _events.Events.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.Status, Is.EqualTo(AccountLockoutResetStatus.Reset));
            Assert.That(result.Value?.UserId, Is.EqualTo(UserId));
            Assert.That(result.Value?.TenantId, Is.EqualTo(TenantId));
            Assert.That(result.Value?.Provider, Is.EqualTo(provider));
            Assert.That(securityEvent.EventType, Is.EqualTo(AshlarSecurityEventTypes.AccountLockoutReset));
            Assert.That(securityEvent.Outcome, Is.EqualTo(SecurityEventOutcomes.Success));
            Assert.That(securityEvent.UserId, Is.EqualTo(UserId));
            Assert.That(securityEvent.TenantId, Is.EqualTo(TenantId));
            Assert.That(securityEvent.ActorUserId, Is.EqualTo(actorId));
            Assert.That(securityEvent.IpAddress, Is.EqualTo("203.0.113.10"));
            Assert.That(securityEvent.UserAgent, Is.EqualTo("admin-agent"));
            Assert.That(securityEvent.CorrelationId, Is.EqualTo("corr-reset"));
            Assert.That(securityEvent.Provider, Is.EqualTo(provider));
            Assert.That(securityEvent.Properties?["lockout_state_cleared"], Is.EqualTo("true"));
            Assert.That(securityEvent.Properties?["tenant_scope"], Is.EqualTo("tenant"));
            Assert.That(securityEvent.Properties?["tenant_id"], Is.EqualTo(TenantId.ToString()));
            Assert.That(securityEvent.Properties?["reason"], Is.EqualTo("support reset"));
            Assert.That(securityEvent.Properties?.ContainsKey("version"), Is.False);
            Assert.That(securityEvent.Properties?.ContainsKey("password"), Is.False);
        }
    }

    [Test]
    public async Task ResetLockoutAsyncShouldEmitNoOpAuditEventWhenStateIsMissing()
    {
        var result = await _service.ResetLockoutAsync(
            UserId,
            AuthenticationProviderKey.Local,
            new ResetAccountLockoutRequest(new TenantContext(TenantId), CreateAudit()));

        var securityEvent = _events.Events.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.Status, Is.EqualTo(AccountLockoutResetStatus.NotFound));
            Assert.That(result.Value?.UserId, Is.EqualTo(UserId));
            Assert.That(result.Value?.TenantId, Is.EqualTo(TenantId));
            Assert.That(result.Value?.Provider, Is.EqualTo(AuthenticationProviderKey.Local));
            Assert.That(securityEvent.EventType, Is.EqualTo(AshlarSecurityEventTypes.AccountLockoutReset));
            Assert.That(securityEvent.Outcome, Is.EqualTo(SecurityEventOutcomes.Success));
            Assert.That(securityEvent.UserId, Is.EqualTo(UserId));
            Assert.That(securityEvent.TenantId, Is.EqualTo(TenantId));
            Assert.That(securityEvent.Provider, Is.EqualTo(AuthenticationProviderKey.Local));
            Assert.That(securityEvent.ActorUserId, Is.EqualTo(CreateAudit().ActorUserId));
            Assert.That(securityEvent.Properties?["lockout_state_cleared"], Is.EqualTo("false"));
            Assert.That(securityEvent.Properties?.ContainsKey("reason"), Is.False);
        }
    }

    [Test]
    public async Task OperationsShouldValidateInputs()
    {
        var unknownProvider = new AuthenticationProviderKey((ProviderType)ProviderType.StorageFallbackValue, "unknown");
        var invalidSearches = new[]
        {
            new SearchAccountLockoutsRequest { Tenant = TenantContext.Global, Limit = 0 },
            new SearchAccountLockoutsRequest { Tenant = TenantContext.Global, Offset = -1 },
            new SearchAccountLockoutsRequest(),
            new SearchAccountLockoutsRequest { Tenant = TenantContext.Global, IncludeAllTenants = true },
            new SearchAccountLockoutsRequest { Tenant = TenantContext.Global, UserId = Guid.Empty },
            new SearchAccountLockoutsRequest { Tenant = TenantContext.Global, Provider = default(AuthenticationProviderKey) },
            new SearchAccountLockoutsRequest { Tenant = TenantContext.Global, Provider = unknownProvider }
        };

        foreach (var request in invalidSearches)
        {
            var result = await _reader.SearchLockoutsAsync(request);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentNullException>(() => _reader.SearchLockoutsAsync(null!));
            Assert.ThrowsAsync<ArgumentNullException>(() => _reader.GetLockoutStatusAsync(UserId, AuthenticationProviderKey.Local, null!));
            Assert.ThrowsAsync<ArgumentNullException>(() => _service.ResetLockoutAsync(UserId, AuthenticationProviderKey.Local, null!));
            Assert.That((await _reader.GetLockoutStatusAsync(Guid.Empty, AuthenticationProviderKey.Local, new AccountLockoutStatusRequest(TenantContext.Global))).FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That((await _reader.GetLockoutStatusAsync(UserId, default, new AccountLockoutStatusRequest(TenantContext.Global))).FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That((await _reader.GetLockoutStatusAsync(UserId, unknownProvider, new AccountLockoutStatusRequest(TenantContext.Global))).FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That((await _reader.GetLockoutStatusAsync(UserId, AuthenticationProviderKey.Local, new AccountLockoutStatusRequest(null!))).FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That((await _service.ResetLockoutAsync(Guid.Empty, AuthenticationProviderKey.Local, new ResetAccountLockoutRequest(TenantContext.Global, CreateAudit()))).FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That((await _service.ResetLockoutAsync(UserId, default, new ResetAccountLockoutRequest(TenantContext.Global, CreateAudit()))).FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That((await _service.ResetLockoutAsync(UserId, unknownProvider, new ResetAccountLockoutRequest(TenantContext.Global, CreateAudit()))).FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That((await _service.ResetLockoutAsync(UserId, AuthenticationProviderKey.Local, new ResetAccountLockoutRequest(null!, CreateAudit()))).FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.Throws<ArgumentNullException>(() => _ = new ResetAccountLockoutRequest(TenantContext.Global, null!));
            Assert.That((await _service.ResetLockoutAsync(UserId, AuthenticationProviderKey.Local, new ResetAccountLockoutRequest(TenantContext.Global, CreateAudit(), new string('x', 513)))).FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.Throws<ArgumentNullException>(() => _ = new AccountLockoutAdministrationService(null!, null!));
            Assert.Throws<ArgumentNullException>(() => _ = new AccountLockoutAdministrationService(_repository, null!));
            Assert.That(_events.Events, Is.Empty);
        }
    }

    [Test]
    public void ConstructorRequiresDurableAuditComposition()
    {
        var transactions = new RecordingTransactionProvider();
        var composition = DurableSecurityMutationTestComposition.Create(transactions);

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new AccountLockoutAdministrationService(_repository,
                new AccountLockoutAdministrationServiceDependencies(TransactionProvider: transactions)));
            Assert.Throws<ArgumentNullException>(() => _ = new AccountLockoutAdministrationService(_repository,
                new AccountLockoutAdministrationServiceDependencies(SecurityEventSink: composition.Events)));
            Assert.Throws<ArgumentException>(() => _ = new AccountLockoutAdministrationService(_repository,
                new AccountLockoutAdministrationServiceDependencies(SecurityEventSink: new SecurityEventFanOutSink(), TransactionProvider: transactions)));
            Assert.Throws<ArgumentException>(() => _ = new AccountLockoutAdministrationService(_repository,
                new AccountLockoutAdministrationServiceDependencies(SecurityEventSink: new SecurityEventFanOutSink(Mock.Of<IPersistentSecurityEventSink>(), transactionProvider: new RecordingTransactionProvider()), TransactionProvider: transactions)));
            Assert.DoesNotThrow(() => _ = new AccountLockoutAdministrationService(_repository,
                new AccountLockoutAdministrationServiceDependencies(SecurityEventSink: composition.Events, TransactionProvider: transactions)));
        }
    }

    [Test]
    public void ReaderConstructorValidatesRepositoryAndDefaultsClock()
    {
        Assert.Throws<ArgumentNullException>(() => _ = new AccountLockoutAdministrationReader(null!));
        Assert.DoesNotThrow(() => _ = new AccountLockoutAdministrationReader(_repository, null));
    }

    [Test]
    public async Task StatusAndResetShouldUseExplicitGlobalTenantScope()
    {
        _repository.Seed(CreateRecord(UserId, null, AuthenticationProviderKey.Local, lockedUntil: Now.AddMinutes(5)));
        var secondUserId = Guid.NewGuid();
        _repository.Seed(CreateRecord(secondUserId, null, AuthenticationProviderKey.Local, lockedUntil: Now.AddMinutes(5)));

        var status = await _reader.GetLockoutStatusAsync(UserId, AuthenticationProviderKey.Local, new AccountLockoutStatusRequest(TenantContext.Global));
        var secondStatus = await _reader.GetLockoutStatusAsync(secondUserId, AuthenticationProviderKey.Local, new AccountLockoutStatusRequest(TenantContext.Global));
        var reset = await _service.ResetLockoutAsync(UserId, AuthenticationProviderKey.Local, new ResetAccountLockoutRequest(TenantContext.Global, CreateAudit()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(status.Succeeded, Is.True);
            Assert.That(status.Value?.TenantId, Is.Null);
            Assert.That(status.Value?.IsLockedOut, Is.True);
            Assert.That(secondStatus.Succeeded, Is.True);
            Assert.That(secondStatus.Value?.TenantId, Is.Null);
            Assert.That(secondStatus.Value?.IsLockedOut, Is.True);
            Assert.That(reset.Succeeded, Is.True);
            Assert.That(reset.Value?.Status, Is.EqualTo(AccountLockoutResetStatus.Reset));
            Assert.That(reset.Value?.TenantId, Is.Null);
            Assert.That(_events.Events.Single().TenantId, Is.Null);
            Assert.That(_events.Events.Single().Properties?["tenant_scope"], Is.EqualTo("global"));
            Assert.That(_events.Events.Single().Properties?.ContainsKey("tenant_id"), Is.False);
        }
    }

    private static AccountLockoutRecord CreateRecord(
        Guid userId,
        Guid? tenantId,
        AuthenticationProviderKey provider,
        DateTimeOffset? failedAt = null,
        DateTimeOffset? lockedUntil = null,
        string version = "version")
    {
        var lastFailedAt = failedAt ?? Now.AddMinutes(-5);
        return new AccountLockoutRecord(
            userId,
            tenantId,
            provider,
            3,
            lastFailedAt.AddMinutes(-1),
            lastFailedAt,
            lockedUntil,
            version);
    }

    private static AuditContext CreateAudit()
    {
        return new AuditContext(Guid.Parse("33333333-3333-3333-3333-333333333333"), "203.0.113.10", "admin-agent", "corr-reset");
    }

    private sealed class InMemoryAccountLockoutRepository : IAccountLockoutRepository
    {
        private readonly List<AccountLockoutRecord> _records = [];

        public void Seed(AccountLockoutRecord record)
        {
            _records.Add(record);
        }

        public Task<IReadOnlyList<AccountLockoutRecord>> SearchAsync(SearchAccountLockoutsRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            IEnumerable<AccountLockoutRecord> records = _records;
            if (request.Tenant is { } tenant)
            {
                records = records.Where(record => record.TenantId == tenant.TenantId);
            }

            if (request.UserId is { } userId)
            {
                records = records.Where(record => record.UserId == userId);
            }

            if (request.Provider is { } provider)
            {
                records = records.Where(record => record.Provider == provider);
            }

            if (request.LockedOut is { } lockedOut)
            {
                records = records.Where(record => (record.LockedUntil is { } lockedUntil && lockedUntil > now) == lockedOut);
            }

            return Task.FromResult<IReadOnlyList<AccountLockoutRecord>>(records
                .OrderByDescending(record => record.LastFailedAt)
                .Skip(request.Offset)
                .Take(request.Limit)
                .ToList()
                .AsReadOnly());
        }

        public Task<AccountLockoutRecord?> GetAsync(Guid userId, Guid? tenantId, AuthenticationProviderKey provider, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(_records.SingleOrDefault(record => record.UserId == userId && record.TenantId == tenantId && record.Provider == provider));
        }

        public Task<AccountLockoutRecordUpdate> RecordFailureAsync(Guid userId, Guid? tenantId, AuthenticationProviderKey provider, DateTimeOffset failedAt, int failureThreshold, TimeSpan lockoutDuration, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<bool> ResetAsync(Guid userId, Guid? tenantId, AuthenticationProviderKey provider, CancellationToken cancellationToken = default)
        {
            var removed = _records.RemoveAll(record => record.UserId == userId && record.TenantId == tenantId && record.Provider == provider);
            return Task.FromResult(removed > 0);
        }
    }

    private sealed class RecordingSecurityEventSink : ISecurityEventSink
    {
        public List<AshlarSecurityEvent> Events { get; } = [];

        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            Events.Add(securityEvent);
            return Task.CompletedTask;
        }
    }
}
