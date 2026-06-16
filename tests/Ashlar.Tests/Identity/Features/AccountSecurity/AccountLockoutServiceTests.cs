using Ashlar.Auditing;
using Ashlar.Identity.Features.AccountLockout;
using Ashlar.Identity.Models.AccountLockout;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Tests.Identity.Features.AccountSecurity;

internal sealed class AccountLockoutServiceTests
{
    private readonly Guid _userId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private FakeTimeProvider _timeProvider;
    private InMemoryAccountLockoutRepository _repository;
    private RecordingSecurityEventSink _events;
    private AccountLockoutService _service;

    [SetUp]
    public void SetUp()
    {
        _timeProvider = new FakeTimeProvider(new DateTimeOffset(2026, 6, 1, 10, 0, 0, TimeSpan.Zero));
        _repository = new InMemoryAccountLockoutRepository();
        _events = new RecordingSecurityEventSink();
        _service = CreateService();
    }

    [Test]
    public async Task GetStatusAsyncShouldReturnUnlockedStatusWithoutStoredState()
    {
        var user = CreateUser();

        var status = await _service.GetStatusAsync(user, AuthenticationProviderKey.Local);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(status.UserId, Is.EqualTo(_userId));
            Assert.That(status.FailedAttemptCount, Is.Zero);
            Assert.That(status.IsLockedOut, Is.False);
            Assert.That(status.LockedUntil, Is.Null);
        }
    }

    [Test]
    public async Task RecordFailureAsyncShouldIncrementAndLockAtThreshold()
    {
        var user = CreateUser();

        var first = await _service.RecordFailureAsync(user, AuthenticationProviderKey.Local);
        _timeProvider.Advance(TimeSpan.FromMinutes(1));
        var second = await _service.RecordFailureAsync(user, AuthenticationProviderKey.Local);
        var status = await _service.GetStatusAsync(user, AuthenticationProviderKey.Local);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(first.ThresholdReached, Is.False);
            Assert.That(first.LockoutActivated, Is.False);
            Assert.That(second.ThresholdReached, Is.True);
            Assert.That(second.LockoutActivated, Is.True);
            Assert.That(second.Status.LockedUntil, Is.EqualTo(_timeProvider.GetUtcNow().AddMinutes(15)));
            Assert.That(status.IsLockedOut, Is.True);
        }
    }

    [Test]
    public async Task RecordFailureAsyncShouldEmitSafeActivationEventOnlyOnceForActiveLockout()
    {
        var tenantId = Guid.NewGuid();
        var user = CreateUser(tenantId, UserAccountState.Active);
        var audit = new AuditContext(Guid.NewGuid(), "127.0.0.1", "agent", "corr");

        await _service.RecordFailureAsync(user, AuthenticationProviderKey.Local, new AccountLockoutContext(audit, new TenantContext(tenantId)));
        await _service.RecordFailureAsync(user, AuthenticationProviderKey.Local, new AccountLockoutContext(audit, new TenantContext(tenantId)));
        await _service.RecordFailureAsync(user, AuthenticationProviderKey.Local, new AccountLockoutContext(audit, new TenantContext(tenantId)));

        var activation = _events.Events.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(activation.EventType, Is.EqualTo(AshlarSecurityEventTypes.AccountLockoutActivated));
            Assert.That(activation.UserId, Is.EqualTo(_userId));
            Assert.That(activation.TenantId, Is.EqualTo(tenantId));
            Assert.That(activation.Provider, Is.EqualTo(AuthenticationProviderKey.Local));
            Assert.That(activation.FailureReason, Is.EqualTo(SecurityEventFailureReasons.AutomaticAccountLockout));
            Assert.That(activation.IpAddress, Is.EqualTo("127.0.0.1"));
            Assert.That(activation.UserAgent, Is.EqualTo("agent"));
            Assert.That(activation.Properties?["failed_attempt_count"], Is.EqualTo("2"));
            Assert.That(activation.Properties?.ContainsKey("password"), Is.False);
        }
    }

    [Test]
    public async Task RecordFailureAsyncShouldWorkWithoutOptionalDependencies()
    {
        var service = new AccountLockoutService(
            _repository,
            Options.Create(new AccountLockoutOptions { FailureThreshold = 1, LockoutDuration = TimeSpan.FromMinutes(5) }));

        var result = await service.RecordFailureAsync(CreateUser(), AuthenticationProviderKey.Local);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.LockoutActivated, Is.True);
            Assert.That(result.Status.LockedUntil, Is.Not.Null);
        }
    }

    [Test]
    public async Task RecordFailureAsyncShouldEmitActivationEventWithoutAuditContext()
    {
        var service = new AccountLockoutService(
            _repository,
            Options.Create(new AccountLockoutOptions { FailureThreshold = 1, LockoutDuration = TimeSpan.FromMinutes(5) }),
            new AccountLockoutServiceDependencies(_timeProvider, _events));

        await service.RecordFailureAsync(CreateUser(), AuthenticationProviderKey.Local);

        Assert.That(_events.Events.Single().ActorUserId, Is.Null);
    }

    [Test]
    public async Task ConcurrentFailuresShouldEmitSingleActivationEvent()
    {
        var service = new AccountLockoutService(
            _repository,
            Options.Create(new AccountLockoutOptions { FailureThreshold = 3, LockoutDuration = TimeSpan.FromMinutes(15) }),
            new AccountLockoutServiceDependencies(_timeProvider, _events));
        var user = CreateUser();

        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ =>
            service.RecordFailureAsync(user, AuthenticationProviderKey.Local)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(results.Count(result => result.LockoutActivated), Is.EqualTo(1));
            Assert.That(_events.Events, Has.Count.EqualTo(1));
            Assert.That(results.Single(result => result.LockoutActivated).Status.FailedAttemptCount, Is.EqualTo(3));
        }
    }

    [Test]
    public async Task ExistingLockoutStatesShouldNotLookLikeNewActivation()
    {
        var user = CreateUser();
        var now = _timeProvider.GetUtcNow();
        _repository.Seed(new AccountLockoutRecord(
            user.Id,
            null,
            AuthenticationProviderKey.Local,
            1,
            now.AddMinutes(-1),
            now.AddMinutes(-1),
            now.AddMinutes(30),
            "active"));

        var activeResult = await _service.RecordFailureAsync(user, AuthenticationProviderKey.Local);
        _repository.Seed(new AccountLockoutRecord(
            user.Id,
            null,
            AuthenticationProviderKey.Local,
            2,
            now.AddMinutes(-30),
            now.AddMinutes(-20),
            now.AddMinutes(-1),
            "expired"));

        var expiredStatus = await _service.GetStatusAsync(user, AuthenticationProviderKey.Local);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(activeResult.ThresholdReached, Is.True);
            Assert.That(activeResult.LockoutActivated, Is.False);
            Assert.That(expiredStatus.IsLockedOut, Is.False);
            Assert.That(_events.Events, Is.Empty);
        }
    }

    [Test]
    public async Task ActiveLockoutWithMatchingExpiryShouldNotLookLikeNewActivation()
    {
        var user = CreateUser();
        var now = _timeProvider.GetUtcNow();
        _repository.Seed(new AccountLockoutRecord(
            user.Id,
            null,
            AuthenticationProviderKey.Local,
            1,
            now.AddMinutes(-5),
            now.AddMinutes(-5),
            now.AddMinutes(15),
            "active"));

        var result = await _service.RecordFailureAsync(user, AuthenticationProviderKey.Local);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.ThresholdReached, Is.True);
            Assert.That(result.LockoutActivated, Is.False);
            Assert.That(result.Status.LockedUntil, Is.EqualTo(now.AddMinutes(15)));
            Assert.That(_events.Events, Is.Empty);
        }
    }

    [Test]
    public async Task ThresholdCountWithoutExpiryShouldNotLookLikeNewActivation()
    {
        var user = CreateUser();
        var service = new AccountLockoutService(
            new FixedFailureRepository(new AccountLockoutRecord(
                user.Id,
                null,
                AuthenticationProviderKey.Local,
                2,
                _timeProvider.GetUtcNow(),
                _timeProvider.GetUtcNow(),
                null,
                "unlocked")),
            Options.Create(new AccountLockoutOptions { FailureThreshold = 2, LockoutDuration = TimeSpan.FromMinutes(15) }),
            new AccountLockoutServiceDependencies(_timeProvider, _events));

        var result = await service.RecordFailureAsync(user, AuthenticationProviderKey.Local);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.ThresholdReached, Is.True);
            Assert.That(result.LockoutActivated, Is.False);
            Assert.That(result.Status.IsLockedOut, Is.False);
            Assert.That(_events.Events, Is.Empty);
        }
    }

    [Test]
    public async Task ResetAsyncShouldClearFailureStateWithoutChangingManualAccountState()
    {
        var user = CreateUser(accountState: UserAccountState.Locked);
        await _service.RecordFailureAsync(user, AuthenticationProviderKey.Local);

        var reset = await _service.ResetAsync(user, AuthenticationProviderKey.Local);
        var status = await _service.GetStatusAsync(user, AuthenticationProviderKey.Local);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(reset, Is.True);
            Assert.That(status.FailedAttemptCount, Is.Zero);
            Assert.That(user.CanSignIn(), Is.False);
            Assert.That(user.AccountState, Is.EqualTo(UserAccountState.Locked));
        }
    }

    [Test]
    public async Task OperationsShouldValidateResolvedUserAndTenant()
    {
        var tenantUser = CreateUser(Guid.NewGuid());

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentNullException>(() => _service.RecordFailureAsync(null!, AuthenticationProviderKey.Local));
            Assert.ThrowsAsync<ArgumentException>(() => _service.RecordFailureAsync(CreateUser(id: Guid.Empty), AuthenticationProviderKey.Local));
            Assert.ThrowsAsync<ArgumentException>(() => _service.RecordFailureAsync(tenantUser, default));
            Assert.ThrowsAsync<ArgumentException>(() => _service.RecordFailureAsync(tenantUser, new AuthenticationProviderKey((ProviderType)ProviderType.StorageFallbackValue, "unknown")));
            Assert.ThrowsAsync<InvalidOperationException>(() => _service.RecordFailureAsync(tenantUser, AuthenticationProviderKey.Local, new AccountLockoutContext(Tenant: new TenantContext(Guid.NewGuid()))));
            Assert.ThrowsAsync<InvalidOperationException>(() => _service.RecordFailureAsync(tenantUser, AuthenticationProviderKey.Local, new AccountLockoutContext(Tenant: TenantContext.Global)));
            Assert.That(await _service.GetStatusAsync(tenantUser, AuthenticationProviderKey.Local, new AccountLockoutContext(Tenant: new TenantContext(tenantUser.TenantId))), Is.Not.Null);
            Assert.That(await _service.GetStatusAsync(new BasicUser(_userId, "basic@example.com", UserAccountState.Active), AuthenticationProviderKey.Local, new AccountLockoutContext(Tenant: TenantContext.Global)), Is.Not.Null);
        }
    }

    [Test]
    public void ConstructorShouldValidateDependenciesAndOptions()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new AccountLockoutService(null!, Options.Create(new AccountLockoutOptions())));
            Assert.Throws<ArgumentNullException>(() => _ = new AccountLockoutService(_repository, null!));
            Assert.Throws<ArgumentException>(() => _ = new AccountLockoutService(_repository, Options.Create(new AccountLockoutOptions { FailureThreshold = 0 })));
        }
    }

    private AccountLockoutService CreateService()
    {
        return new AccountLockoutService(
            _repository,
            Options.Create(new AccountLockoutOptions { FailureThreshold = 2, LockoutDuration = TimeSpan.FromMinutes(15) }),
            new AccountLockoutServiceDependencies(_timeProvider, _events));
    }

    private User CreateUser(Guid? tenantId = null, UserAccountState accountState = UserAccountState.Active, Guid? id = null)
    {
        return new User { Id = id ?? _userId, Email = "user@example.com", TenantId = tenantId, AccountState = accountState };
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

    private sealed record BasicUser(Guid Id, string Email, UserAccountState AccountState) : IUser
    {
        public string? Name => null;
        public DateTimeOffset? EmailVerifiedAt => null;
    }

    private sealed class FixedFailureRepository(AccountLockoutRecord record) : IAccountLockoutRepository
    {
        public Task<IReadOnlyList<AccountLockoutRecord>> SearchAsync(SearchAccountLockoutsRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IReadOnlyList<AccountLockoutRecord>>([]);
        }

        public Task<AccountLockoutRecord?> GetAsync(Guid userId, Guid? tenantId, AuthenticationProviderKey provider, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<AccountLockoutRecord?>(null);
        }

        public Task<AccountLockoutRecordUpdate> RecordFailureAsync(Guid userId, Guid? tenantId, AuthenticationProviderKey provider, DateTimeOffset failedAt, int failureThreshold, TimeSpan lockoutDuration, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new AccountLockoutRecordUpdate(record, false));
        }

        public Task<bool> ResetAsync(Guid userId, Guid? tenantId, AuthenticationProviderKey provider, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(false);
        }
    }

    private sealed class InMemoryAccountLockoutRepository : IAccountLockoutRepository
    {
        private readonly Dictionary<(Guid UserId, Guid? TenantId, AuthenticationProviderKey Provider), AccountLockoutRecord> _records = [];
        private readonly object _lock = new();

        public void Seed(AccountLockoutRecord record)
        {
            lock (_lock)
            {
                _records[(record.UserId, record.TenantId, record.Provider)] = record;
            }
        }

        public Task<IReadOnlyList<AccountLockoutRecord>> SearchAsync(SearchAccountLockoutsRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            lock (_lock)
            {
                return Task.FromResult<IReadOnlyList<AccountLockoutRecord>>(_records.Values.ToList().AsReadOnly());
            }
        }

        public Task<AccountLockoutRecord?> GetAsync(Guid userId, Guid? tenantId, AuthenticationProviderKey provider, CancellationToken cancellationToken = default)
        {
            lock (_lock)
            {
                return Task.FromResult(_records.GetValueOrDefault((userId, tenantId, provider)));
            }
        }

        public Task<AccountLockoutRecordUpdate> RecordFailureAsync(Guid userId, Guid? tenantId, AuthenticationProviderKey provider, DateTimeOffset failedAt, int failureThreshold, TimeSpan lockoutDuration, CancellationToken cancellationToken = default)
        {
            lock (_lock)
            {
                var key = (userId, tenantId, provider);
                _records.TryGetValue(key, out var current);
                var currentlyLocked = current?.LockedUntil is { } activeUntil && activeUntil > failedAt;
                var count = current?.LockedUntil <= failedAt ? 1 : (current?.FailedAttemptCount ?? 0) + 1;
                var firstFailedAt = current?.LockedUntil <= failedAt || current == null ? failedAt : current.FirstFailedAt;
                var lockedUntil = currentlyLocked
                    ? current!.LockedUntil
                    : count >= failureThreshold
                        ? failedAt.Add(lockoutDuration)
                        : null;
                var record = new AccountLockoutRecord(userId, tenantId, provider, count, firstFailedAt, failedAt, lockedUntil, Guid.NewGuid().ToString("N"));
                _records[key] = record;
                var lockoutActivated = !currentlyLocked && count >= failureThreshold;
                return Task.FromResult(new AccountLockoutRecordUpdate(record, lockoutActivated));
            }
        }

        public Task<bool> ResetAsync(Guid userId, Guid? tenantId, AuthenticationProviderKey provider, CancellationToken cancellationToken = default)
        {
            lock (_lock)
            {
                return Task.FromResult(_records.Remove((userId, tenantId, provider)));
            }
        }
    }
}
