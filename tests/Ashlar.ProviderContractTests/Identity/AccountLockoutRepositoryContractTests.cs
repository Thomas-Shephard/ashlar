namespace Ashlar.ProviderContractTests.Identity;

internal abstract class AccountLockoutRepositoryContractTests : ProviderContractFixture
{
    private static readonly DateTimeOffset FirstFailure = new(2026, 6, 1, 10, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task SearchShouldFilterByTenantUserAndProviderWithPaging()
    {
        await using var scope = CreateAsyncScope();
        var users = GetUserRepository(scope.ServiceProvider);
        var lockouts = GetAccountLockoutRepository(scope.ServiceProvider);
        var tenantId = Guid.NewGuid();
        var tenantUser = await CreateUserAsync(users, tenantId: tenantId);
        var secondTenantUser = await CreateUserAsync(users, tenantId: tenantId);
        var otherTenantUser = await CreateUserAsync(users, tenantId: Guid.NewGuid());
        var globalUser = await CreateUserAsync(users);
        var oauthProvider = new AuthenticationProviderKey(ProviderType.OAuth, "github");

        await lockouts.RecordFailureAsync(tenantUser.Id, tenantUser.TenantId, AuthenticationProviderKey.Local, FirstFailure, 5, TimeSpan.FromMinutes(10));
        await lockouts.RecordFailureAsync(secondTenantUser.Id, secondTenantUser.TenantId, AuthenticationProviderKey.Local, FirstFailure.AddMinutes(1), 5, TimeSpan.FromMinutes(10));
        await lockouts.RecordFailureAsync(tenantUser.Id, tenantUser.TenantId, oauthProvider, FirstFailure.AddMinutes(2), 5, TimeSpan.FromMinutes(10));
        await lockouts.RecordFailureAsync(otherTenantUser.Id, otherTenantUser.TenantId, AuthenticationProviderKey.Local, FirstFailure.AddMinutes(3), 5, TimeSpan.FromMinutes(10));
        await lockouts.RecordFailureAsync(globalUser.Id, globalUser.TenantId, AuthenticationProviderKey.Local, FirstFailure.AddMinutes(4), 5, TimeSpan.FromMinutes(10));

        var tenantLocalPage = await lockouts.SearchAsync(new SearchAccountLockoutsRequest
        {
            Tenant = new TenantContext(tenantId),
            Provider = AuthenticationProviderKey.Local,
            Limit = 1
        }, FirstFailure.AddMinutes(5));
        var tenantLocalSecondPage = await lockouts.SearchAsync(new SearchAccountLockoutsRequest
        {
            Tenant = new TenantContext(tenantId),
            Provider = AuthenticationProviderKey.Local,
            Limit = 1,
            Offset = 1
        }, FirstFailure.AddMinutes(5));
        var userProvider = await lockouts.SearchAsync(new SearchAccountLockoutsRequest
        {
            UserId = tenantUser.Id,
            Tenant = new TenantContext(tenantId),
            Provider = oauthProvider,
            Limit = 10
        }, FirstFailure.AddMinutes(5));
        var global = await lockouts.SearchAsync(new SearchAccountLockoutsRequest
        {
            Tenant = TenantContext.Global,
            Limit = 10
        }, FirstFailure.AddMinutes(5));
        var unfiltered = await lockouts.SearchAsync(new SearchAccountLockoutsRequest
        {
            IncludeAllTenants = true,
            Limit = 10
        }, FirstFailure.AddMinutes(5));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(tenantLocalPage, Has.Count.EqualTo(1));
            Assert.That(tenantLocalPage.Single().UserId, Is.EqualTo(secondTenantUser.Id));
            Assert.That(tenantLocalSecondPage, Has.Count.EqualTo(1));
            Assert.That(tenantLocalSecondPage.Single().UserId, Is.EqualTo(tenantUser.Id));
            Assert.That(userProvider, Has.Count.EqualTo(1));
            Assert.That(userProvider.Single().Provider, Is.EqualTo(oauthProvider));
            Assert.That(global, Has.Count.EqualTo(1));
            Assert.That(global.Single().UserId, Is.EqualTo(globalUser.Id));
            Assert.That(unfiltered, Has.Count.EqualTo(5));
        }
    }

    [Test]
    public async Task SearchShouldApplyLockedOutFilterBeforePaging()
    {
        await using var scope = CreateAsyncScope();
        var users = GetUserRepository(scope.ServiceProvider);
        var lockouts = GetAccountLockoutRepository(scope.ServiceProvider);
        var tenantId = Guid.NewGuid();
        var unlockedUser = await CreateUserAsync(users, tenantId: tenantId);
        var lockedUser = await CreateUserAsync(users, tenantId: tenantId);

        await lockouts.RecordFailureAsync(lockedUser.Id, lockedUser.TenantId, AuthenticationProviderKey.Local, FirstFailure, 1, TimeSpan.FromMinutes(10));
        await lockouts.RecordFailureAsync(unlockedUser.Id, unlockedUser.TenantId, AuthenticationProviderKey.Local, FirstFailure.AddMinutes(1), 5, TimeSpan.FromMinutes(10));

        var locked = await lockouts.SearchAsync(new SearchAccountLockoutsRequest
        {
            Tenant = new TenantContext(tenantId),
            LockedOut = true,
            Limit = 1
        }, FirstFailure.AddMinutes(2));
        var unlocked = await lockouts.SearchAsync(new SearchAccountLockoutsRequest
        {
            Tenant = new TenantContext(tenantId),
            LockedOut = false,
            Limit = 1
        }, FirstFailure.AddMinutes(2));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(locked, Has.Count.EqualTo(1));
            Assert.That(locked.Single().UserId, Is.EqualTo(lockedUser.Id));
            Assert.That(unlocked, Has.Count.EqualTo(1));
            Assert.That(unlocked.Single().UserId, Is.EqualTo(unlockedUser.Id));
        }
    }

    [Test]
    public async Task RecordFailureShouldCreateAndIncrementLockoutState()
    {
        await using var scope = CreateAsyncScope();
        var users = GetUserRepository(scope.ServiceProvider);
        var lockouts = GetAccountLockoutRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(users);

        var first = await lockouts.RecordFailureAsync(user.Id, user.TenantId, AuthenticationProviderKey.Local, FirstFailure, 3, TimeSpan.FromMinutes(10));
        var second = await lockouts.RecordFailureAsync(user.Id, user.TenantId, AuthenticationProviderKey.Local, FirstFailure.AddMinutes(1), 3, TimeSpan.FromMinutes(10));
        var fetched = await lockouts.GetAsync(user.Id, user.TenantId, AuthenticationProviderKey.Local);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(first.Record.FailedAttemptCount, Is.EqualTo(1));
            Assert.That(first.Record.LockedUntil, Is.Null);
            Assert.That(first.LockoutActivated, Is.False);
            Assert.That(second.Record.FailedAttemptCount, Is.EqualTo(2));
            Assert.That(second.Record.FirstFailedAt, Is.EqualTo(FirstFailure));
            Assert.That(second.Record.LastFailedAt, Is.EqualTo(FirstFailure.AddMinutes(1)));
            Assert.That(second.LockoutActivated, Is.False);
            Assert.That(fetched, Is.EqualTo(second.Record));
        }
    }

    [Test]
    public async Task RecordFailureShouldLockWhenThresholdIsReached()
    {
        await using var scope = CreateAsyncScope();
        var users = GetUserRepository(scope.ServiceProvider);
        var lockouts = GetAccountLockoutRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(users);

        await lockouts.RecordFailureAsync(user.Id, user.TenantId, AuthenticationProviderKey.Local, FirstFailure, 2, TimeSpan.FromMinutes(10));
        var locked = await lockouts.RecordFailureAsync(user.Id, user.TenantId, AuthenticationProviderKey.Local, FirstFailure.AddMinutes(1), 2, TimeSpan.FromMinutes(10));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(locked.Record.FailedAttemptCount, Is.EqualTo(2));
            Assert.That(locked.Record.LockedUntil, Is.EqualTo(FirstFailure.AddMinutes(11)));
            Assert.That(locked.LockoutActivated, Is.True);
        }
    }

    [Test]
    public async Task RecordFailureShouldStartNewWindowAfterTemporaryLockoutExpires()
    {
        await using var scope = CreateAsyncScope();
        var users = GetUserRepository(scope.ServiceProvider);
        var lockouts = GetAccountLockoutRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(users);
        await lockouts.RecordFailureAsync(user.Id, user.TenantId, AuthenticationProviderKey.Local, FirstFailure, 1, TimeSpan.FromMinutes(10));

        var next = await lockouts.RecordFailureAsync(user.Id, user.TenantId, AuthenticationProviderKey.Local, FirstFailure.AddMinutes(11), 2, TimeSpan.FromMinutes(10));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(next.Record.FailedAttemptCount, Is.EqualTo(1));
            Assert.That(next.Record.FirstFailedAt, Is.EqualTo(FirstFailure.AddMinutes(11)));
            Assert.That(next.Record.LockedUntil, Is.Null);
            Assert.That(next.LockoutActivated, Is.False);
        }
    }

    [Test]
    public async Task RecordFailureShouldPreserveActiveLockoutExpiry()
    {
        await using var scope = CreateAsyncScope();
        var users = GetUserRepository(scope.ServiceProvider);
        var lockouts = GetAccountLockoutRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(users);

        var locked = await lockouts.RecordFailureAsync(user.Id, user.TenantId, AuthenticationProviderKey.Local, FirstFailure, 1, TimeSpan.FromMinutes(10));
        var later = await lockouts.RecordFailureAsync(user.Id, user.TenantId, AuthenticationProviderKey.Local, FirstFailure.AddMinutes(1), 1, TimeSpan.FromMinutes(10));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(locked.LockoutActivated, Is.True);
            Assert.That(later.Record.FailedAttemptCount, Is.EqualTo(2));
            Assert.That(later.Record.LockedUntil, Is.EqualTo(locked.Record.LockedUntil));
            Assert.That(later.LockoutActivated, Is.False);
        }
    }

    [Test]
    public async Task RecordFailureShouldNotActivateAlreadyLockedRecordWhenPolicyChanges()
    {
        await using var scope = CreateAsyncScope();
        var users = GetUserRepository(scope.ServiceProvider);
        var lockouts = GetAccountLockoutRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(users);

        await lockouts.RecordFailureAsync(user.Id, user.TenantId, AuthenticationProviderKey.Local, FirstFailure, 2, TimeSpan.FromMinutes(10));
        var locked = await lockouts.RecordFailureAsync(user.Id, user.TenantId, AuthenticationProviderKey.Local, FirstFailure.AddMinutes(5), 2, TimeSpan.FromMinutes(10));
        var later = await lockouts.RecordFailureAsync(user.Id, user.TenantId, AuthenticationProviderKey.Local, FirstFailure.AddMinutes(10), 3, TimeSpan.FromMinutes(5));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(locked.LockoutActivated, Is.True);
            Assert.That(later.Record.FailedAttemptCount, Is.EqualTo(3));
            Assert.That(later.Record.LockedUntil, Is.EqualTo(locked.Record.LockedUntil));
            Assert.That(later.LockoutActivated, Is.False);
        }
    }

    [Test]
    public async Task ResetShouldClearStoredState()
    {
        await using var scope = CreateAsyncScope();
        var users = GetUserRepository(scope.ServiceProvider);
        var lockouts = GetAccountLockoutRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(users);
        await lockouts.RecordFailureAsync(user.Id, user.TenantId, AuthenticationProviderKey.Local, FirstFailure, 2, TimeSpan.FromMinutes(10));

        var reset = await lockouts.ResetAsync(user.Id, user.TenantId, AuthenticationProviderKey.Local);
        var secondReset = await lockouts.ResetAsync(user.Id, user.TenantId, AuthenticationProviderKey.Local);
        var fetched = await lockouts.GetAsync(user.Id, user.TenantId, AuthenticationProviderKey.Local);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(reset, Is.True);
            Assert.That(secondReset, Is.False);
            Assert.That(fetched, Is.Null);
        }

        var tenantId = Guid.NewGuid();
        var tenantUser = await CreateUserAsync(users, tenantId: tenantId);
        await lockouts.RecordFailureAsync(tenantUser.Id, tenantUser.TenantId, AuthenticationProviderKey.Local, FirstFailure, 2, TimeSpan.FromMinutes(10));

        Assert.That(await lockouts.ResetAsync(tenantUser.Id, tenantUser.TenantId, AuthenticationProviderKey.Local), Is.True);
    }

    [Test]
    public async Task LockoutStateShouldBeIsolatedByTenantAndProvider()
    {
        await using var scope = CreateAsyncScope();
        var users = GetUserRepository(scope.ServiceProvider);
        var lockouts = GetAccountLockoutRepository(scope.ServiceProvider);
        var tenantId = Guid.NewGuid();
        var tenantUser = await CreateUserAsync(users, tenantId: tenantId);
        var globalUser = await CreateUserAsync(users);
        var oauthProvider = new AuthenticationProviderKey(ProviderType.OAuth, "github");

        await lockouts.RecordFailureAsync(tenantUser.Id, tenantUser.TenantId, AuthenticationProviderKey.Local, FirstFailure, 5, TimeSpan.FromMinutes(10));
        await lockouts.RecordFailureAsync(tenantUser.Id, tenantUser.TenantId, oauthProvider, FirstFailure, 5, TimeSpan.FromMinutes(10));
        await lockouts.RecordFailureAsync(globalUser.Id, globalUser.TenantId, AuthenticationProviderKey.Local, FirstFailure, 5, TimeSpan.FromMinutes(10));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(await lockouts.GetAsync(tenantUser.Id, tenantId, AuthenticationProviderKey.Local), Is.Not.Null);
            Assert.That(await lockouts.GetAsync(tenantUser.Id, null, AuthenticationProviderKey.Local), Is.Null);
            Assert.That(await lockouts.GetAsync(tenantUser.Id, tenantId, oauthProvider), Is.Not.Null);
            Assert.That(await lockouts.GetAsync(globalUser.Id, null, AuthenticationProviderKey.Local), Is.Not.Null);
        }
    }

    [Test]
    public async Task RecordFailureShouldRejectUnknownUsers()
    {
        await using var scope = CreateAsyncScope();
        var lockouts = GetAccountLockoutRepository(scope.ServiceProvider);

        Assert.ThrowsAsync(Is.InstanceOf<Exception>(), async () =>
            await lockouts.RecordFailureAsync(Guid.NewGuid(), null, AuthenticationProviderKey.Local, FirstFailure, 5, TimeSpan.FromMinutes(10)));
    }

    [Test]
    public async Task ConcurrentFailuresShouldNotLoseIncrements()
    {
        await using var scope = CreateAsyncScope();
        var users = GetUserRepository(scope.ServiceProvider);
        var lockouts = GetAccountLockoutRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(users);

        await Task.WhenAll(Enumerable.Range(0, 8).Select(index =>
            lockouts.RecordFailureAsync(user.Id, user.TenantId, AuthenticationProviderKey.Local, FirstFailure.AddSeconds(index), 20, TimeSpan.FromMinutes(10))));

        var fetched = await lockouts.GetAsync(user.Id, user.TenantId, AuthenticationProviderKey.Local);

        Assert.That(fetched?.FailedAttemptCount, Is.EqualTo(8));
    }

    [Test]
    public async Task ConcurrentThresholdCrossingShouldProduceSingleThresholdCountRecord()
    {
        await using var scope = CreateAsyncScope();
        var users = GetUserRepository(scope.ServiceProvider);
        var lockouts = GetAccountLockoutRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(users);

        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(index =>
            lockouts.RecordFailureAsync(user.Id, user.TenantId, AuthenticationProviderKey.Local, FirstFailure.AddSeconds(index), 3, TimeSpan.FromMinutes(10))));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(results.Count(result => result.Record.FailedAttemptCount == 3), Is.EqualTo(1));
            Assert.That(results.Count(result => result.LockoutActivated), Is.EqualTo(1));
            Assert.That(results.Where(result => result.Record.FailedAttemptCount > 3).All(result => result.Record.LockedUntil == results.Single(item => item.Record.FailedAttemptCount == 3).Record.LockedUntil), Is.True);
        }
    }

    [Test]
    public async Task OperationsShouldValidateArguments()
    {
        await using var scope = CreateAsyncScope();
        var lockouts = GetAccountLockoutRepository(scope.ServiceProvider);
        var unknownProvider = new AuthenticationProviderKey((ProviderType)ProviderType.UnknownValue, "unknown");

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentException>(() => lockouts.GetAsync(Guid.Empty, null, AuthenticationProviderKey.Local));
            Assert.ThrowsAsync<ArgumentException>(() => lockouts.GetAsync(Guid.NewGuid(), null, default));
            Assert.ThrowsAsync<ArgumentNullException>(() => lockouts.SearchAsync(null!, FirstFailure));
            Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => lockouts.SearchAsync(new SearchAccountLockoutsRequest { Tenant = TenantContext.Global, Limit = 0 }, FirstFailure));
            Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => lockouts.SearchAsync(new SearchAccountLockoutsRequest { Tenant = TenantContext.Global, Offset = -1 }, FirstFailure));
            Assert.ThrowsAsync<ArgumentException>(() => lockouts.SearchAsync(new SearchAccountLockoutsRequest(), FirstFailure));
            Assert.ThrowsAsync<ArgumentException>(() => lockouts.SearchAsync(new SearchAccountLockoutsRequest { Tenant = TenantContext.Global, IncludeAllTenants = true }, FirstFailure));
            Assert.ThrowsAsync<ArgumentException>(() => lockouts.SearchAsync(new SearchAccountLockoutsRequest { Tenant = TenantContext.Global, UserId = Guid.Empty }, FirstFailure));
            Assert.ThrowsAsync<ArgumentException>(() => lockouts.SearchAsync(new SearchAccountLockoutsRequest { Tenant = TenantContext.Global, Provider = default(AuthenticationProviderKey) }, FirstFailure));
            Assert.ThrowsAsync<ArgumentException>(() => lockouts.SearchAsync(new SearchAccountLockoutsRequest { Tenant = TenantContext.Global, Provider = unknownProvider }, FirstFailure));
            Assert.ThrowsAsync<ArgumentException>(() => lockouts.ResetAsync(Guid.Empty, null, AuthenticationProviderKey.Local));
            Assert.ThrowsAsync<ArgumentException>(() => lockouts.ResetAsync(Guid.NewGuid(), null, default));
            Assert.ThrowsAsync<ArgumentException>(() => lockouts.RecordFailureAsync(Guid.Empty, null, AuthenticationProviderKey.Local, FirstFailure, 5, TimeSpan.FromMinutes(10)));
            Assert.ThrowsAsync<ArgumentException>(() => lockouts.RecordFailureAsync(Guid.NewGuid(), null, default, FirstFailure, 5, TimeSpan.FromMinutes(10)));
            Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => lockouts.RecordFailureAsync(Guid.NewGuid(), null, AuthenticationProviderKey.Local, FirstFailure, 0, TimeSpan.FromMinutes(10)));
            Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => lockouts.RecordFailureAsync(Guid.NewGuid(), null, AuthenticationProviderKey.Local, FirstFailure, 5, TimeSpan.Zero));
        }
    }
}
