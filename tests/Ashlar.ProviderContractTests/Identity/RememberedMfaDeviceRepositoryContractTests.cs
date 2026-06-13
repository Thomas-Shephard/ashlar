namespace Ashlar.ProviderContractTests.Identity;

internal abstract class RememberedMfaDeviceRepositoryContractTests : ProviderContractFixture
{
    private static readonly DateTimeOffset CreatedAt = new(2026, 6, 2, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task CreateAndFetchBySelectorAndIdMapsFields()
    {
        await using var scope = CreateAsyncScope();
        var user = await CreateUserAsync(GetUserRepository(scope.ServiceProvider), tenantId: Guid.NewGuid());
        var repository = GetRememberedMfaDeviceRepository(scope.ServiceProvider);
        var device = CreateDevice(user.Id, user.TenantId);
        device.LastUsedAt = CreatedAt.AddMinutes(2);
        device.RevokedAt = CreatedAt.AddMinutes(3);
        device.RevocationReason = "manual";

        await repository.CreateAsync(device);

        var bySelector = await repository.GetByTokenSelectorAsync(device.TokenSelector);
        var byId = await repository.GetAsync(device.Id);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(bySelector, Is.Not.Null);
            Assert.That(bySelector!.Id, Is.EqualTo(device.Id));
            Assert.That(bySelector.UserId, Is.EqualTo(device.UserId));
            Assert.That(bySelector.TenantId, Is.EqualTo(device.TenantId));
            Assert.That(bySelector.TokenSelector, Is.EqualTo(device.TokenSelector));
            Assert.That(bySelector.TokenHash, Is.EqualTo(device.TokenHash));
            Assert.That(bySelector.DisplayName, Is.EqualTo(device.DisplayName));
            Assert.That(bySelector.CreatedAt, Is.EqualTo(device.CreatedAt));
            Assert.That(bySelector.LastUsedAt, Is.EqualTo(device.LastUsedAt));
            Assert.That(bySelector.ExpiresAt, Is.EqualTo(device.ExpiresAt));
            Assert.That(bySelector.RevokedAt, Is.EqualTo(device.RevokedAt));
            Assert.That(bySelector.RevocationReason, Is.EqualTo(device.RevocationReason));
            Assert.That(byId!.Id, Is.EqualTo(device.Id));
        }
    }

    [Test]
    public async Task MissingLookupsReturnNull()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetRememberedMfaDeviceRepository(scope.ServiceProvider);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(await repository.GetByTokenSelectorAsync("missing"), Is.Null);
            Assert.That(await repository.GetAsync(Guid.NewGuid()), Is.Null);
        }
    }

    [Test]
    public async Task SelectorUniquenessAndTenantInvariantAreEnforced()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetRememberedMfaDeviceRepository(scope.ServiceProvider);
        var tenantId = Guid.NewGuid();
        var tenantUser = await CreateUserAsync(userRepository, tenantId: tenantId);
        var globalUser = await CreateUserAsync(userRepository);
        var first = CreateDevice(tenantUser.Id, tenantId);
        var duplicate = CreateDevice(tenantUser.Id, tenantId, selector: first.TokenSelector);

        await repository.CreateAsync(first);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(async () => await repository.CreateAsync(duplicate), Throws.Exception);
            Assert.That(async () => await repository.CreateAsync(CreateDevice(tenantUser.Id, null)), Throws.Exception);
            Assert.That(async () => await repository.CreateAsync(CreateDevice(globalUser.Id, Guid.NewGuid())), Throws.Exception);
        }
    }

    [Test]
    public async Task CreateRejectsInvalidDeviceShape()
    {
        await using var scope = CreateAsyncScope();
        var user = await CreateUserAsync(GetUserRepository(scope.ServiceProvider));
        var repository = GetRememberedMfaDeviceRepository(scope.ServiceProvider);
        var emptyId = CreateDevice(user.Id) with { Id = Guid.Empty };
        var emptyUser = CreateDevice(user.Id) with { UserId = Guid.Empty };
        var emptySelector = CreateDevice(user.Id) with { TokenSelector = " " };
        var emptyHash = CreateDevice(user.Id) with { TokenHash = " " };
        var invalidExpiry = CreateDevice(user.Id, expiresAt: CreatedAt.AddTicks(-1));
        var revocationReasonWithoutRevocation = CreateDevice(user.Id);
        revocationReasonWithoutRevocation.RevocationReason = "reason";

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentException>(() => repository.CreateAsync(emptyId));
            Assert.ThrowsAsync<ArgumentException>(() => repository.CreateAsync(emptyUser));
            Assert.ThrowsAsync<ArgumentException>(() => repository.CreateAsync(emptySelector));
            Assert.ThrowsAsync<ArgumentException>(() => repository.CreateAsync(emptyHash));
            Assert.That(async () => await repository.CreateAsync(invalidExpiry), Throws.Exception);
            Assert.That(async () => await repository.CreateAsync(revocationReasonWithoutRevocation), Throws.Exception);
        }
    }

    [Test]
    public async Task ActiveFilteringLastUsedAndRevocationBehaveSafely()
    {
        await using var scope = CreateAsyncScope();
        var user = await CreateUserAsync(GetUserRepository(scope.ServiceProvider));
        var other = await CreateUserAsync(GetUserRepository(scope.ServiceProvider));
        var repository = GetRememberedMfaDeviceRepository(scope.ServiceProvider);
        var active = CreateDevice(user.Id);
        var revoked = CreateDevice(user.Id);
        var expired = CreateDevice(user.Id, expiresAt: CreatedAt.AddMinutes(30));
        var otherDevice = CreateDevice(other.Id);
        await repository.CreateAsync(active);
        await repository.CreateAsync(revoked);
        await repository.CreateAsync(expired);
        await repository.CreateAsync(otherDevice);

        var lastUsed = CreatedAt.AddHours(1);
        var updated = await repository.UpdateLastUsedAsync(active.Id, lastUsed);
        var expiredUpdate = await repository.UpdateLastUsedAsync(expired.Id, lastUsed);
        var revokedResult = await repository.RevokeAsync(revoked.Id, user.Id, lastUsed, "single", TenantContext.Global);
        var wrongOwner = await repository.RevokeAsync(otherDevice.Id, user.Id, lastUsed, "wrong", TenantContext.Global);
        var activeOnly = await repository.ListForUserAsync(user.Id, TenantContext.Global, activeOnly: true, lastUsed);
        var all = await repository.ListForUserAsync(user.Id, TenantContext.Global, activeOnly: false, lastUsed);
        var activeCount = await repository.CountForUserAsync(user.Id, TenantContext.Global, activeOnly: true, lastUsed);
        var allCount = await repository.CountForUserAsync(user.Id, TenantContext.Global, activeOnly: false, lastUsed);
        var fetchedActive = await repository.GetAsync(active.Id);
        var fetchedRevoked = await repository.GetAsync(revoked.Id);
        var unrestrictedCountBeforeRevokeAll = await repository.CountForUserAsync(user.Id, tenant: null, activeOnly: false, lastUsed);
        var unrestrictedCount = await repository.RevokeAllForUserAsync(user.Id, lastUsed.AddMinutes(1), "unrestricted", tenant: null);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(updated, Is.True);
            Assert.That(expiredUpdate, Is.False);
            Assert.That(revokedResult, Is.True);
            Assert.That(wrongOwner, Is.False);
            Assert.That(activeOnly.Select(d => d.Id), Is.EquivalentTo(new[] { active.Id }));
            Assert.That(all.Select(d => d.Id), Is.EquivalentTo(new[] { active.Id, revoked.Id, expired.Id }));
            Assert.That(activeCount, Is.EqualTo(1));
            Assert.That(allCount, Is.EqualTo(3));
            Assert.That(fetchedActive!.LastUsedAt, Is.EqualTo(lastUsed));
            Assert.That(fetchedRevoked!.RevokedAt, Is.EqualTo(lastUsed));
            Assert.That(unrestrictedCountBeforeRevokeAll, Is.EqualTo(3));
            Assert.That(unrestrictedCount, Is.EqualTo(2));
        }
    }

    [Test]
    public async Task LastUsedUpdateIsMonotonicAndRejectedAfterRevocation()
    {
        await using var scope = CreateAsyncScope();
        var user = await CreateUserAsync(GetUserRepository(scope.ServiceProvider));
        var repository = GetRememberedMfaDeviceRepository(scope.ServiceProvider);
        var device = CreateDevice(user.Id);
        await repository.CreateAsync(device);

        var newer = CreatedAt.AddHours(2);
        var older = CreatedAt.AddHours(1);
        var firstUpdate = await repository.UpdateLastUsedAsync(device.Id, newer);
        var staleUpdate = await repository.UpdateLastUsedAsync(device.Id, older);
        var revoke = await repository.RevokeAsync(device.Id, user.Id, newer.AddMinutes(1), "manual", TenantContext.Global);
        var updateAfterRevoke = await repository.UpdateLastUsedAsync(device.Id, newer.AddMinutes(2));
        var fetched = await repository.GetAsync(device.Id);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(firstUpdate, Is.True);
            Assert.That(staleUpdate, Is.True);
            Assert.That(revoke, Is.True);
            Assert.That(updateAfterRevoke, Is.False);
            Assert.That(fetched!.LastUsedAt, Is.EqualTo(newer));
            Assert.That(fetched.RevokedAt, Is.EqualTo(newer.AddMinutes(1)));
        }
    }

    [Test]
    public async Task SingleRevocationIsIdempotentAndRemovesDeviceFromActiveListings()
    {
        await using var scope = CreateAsyncScope();
        var user = await CreateUserAsync(GetUserRepository(scope.ServiceProvider));
        var repository = GetRememberedMfaDeviceRepository(scope.ServiceProvider);
        var device = CreateDevice(user.Id);
        await repository.CreateAsync(device);

        var revokedAt = CreatedAt.AddHours(1);
        var first = await repository.RevokeAsync(device.Id, user.Id, revokedAt, "first", TenantContext.Global);
        var second = await repository.RevokeAsync(device.Id, user.Id, revokedAt.AddMinutes(1), "second", TenantContext.Global);
        var active = await repository.ListForUserAsync(user.Id, TenantContext.Global, activeOnly: true, revokedAt);
        var activeCount = await repository.CountForUserAsync(user.Id, TenantContext.Global, activeOnly: true, revokedAt);
        var all = await repository.ListForUserAsync(user.Id, TenantContext.Global, activeOnly: false, revokedAt);
        var fetched = await repository.GetAsync(device.Id);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(first, Is.True);
            Assert.That(second, Is.False);
            Assert.That(active, Is.Empty);
            Assert.That(activeCount, Is.Zero);
            Assert.That(all.Select(d => d.Id), Is.EquivalentTo(new[] { device.Id }));
            Assert.That(fetched!.RevokedAt, Is.EqualTo(revokedAt));
            Assert.That(fetched.RevocationReason, Is.EqualTo("first"));
        }
    }

    [Test]
    public async Task TenantScopedOperationsDoNotCrossGlobalScope()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetRememberedMfaDeviceRepository(scope.ServiceProvider);
        var tenantId = Guid.NewGuid();
        var tenant = new TenantContext(tenantId);
        var globalUser = await CreateUserAsync(userRepository);
        var tenantUser = await CreateUserAsync(userRepository, tenantId: tenantId);
        var globalDevice = CreateDevice(globalUser.Id);
        var tenantDevice = CreateDevice(tenantUser.Id, tenantId);
        await repository.CreateAsync(globalDevice);
        await repository.CreateAsync(tenantDevice);

        var now = CreatedAt.AddHours(1);
        var globalList = await repository.ListForUserAsync(globalUser.Id, TenantContext.Global, activeOnly: false, now);
        var tenantAsGlobal = await repository.ListForUserAsync(tenantUser.Id, TenantContext.Global, activeOnly: false, now);
        var globalAsTenant = await repository.ListForUserAsync(globalUser.Id, tenant, activeOnly: false, now);
        var tenantList = await repository.ListForUserAsync(tenantUser.Id, tenant, activeOnly: false, now);
        var globalCount = await repository.CountForUserAsync(globalUser.Id, TenantContext.Global, activeOnly: false, now);
        var tenantAsGlobalCount = await repository.CountForUserAsync(tenantUser.Id, TenantContext.Global, activeOnly: false, now);
        var globalAsTenantCount = await repository.CountForUserAsync(globalUser.Id, tenant, activeOnly: false, now);
        var tenantCount = await repository.CountForUserAsync(tenantUser.Id, tenant, activeOnly: false, now);
        var wrongTenantRevoke = await repository.RevokeAsync(tenantDevice.Id, tenantUser.Id, now, "wrong", TenantContext.Global);
        var globalRevoke = await repository.RevokeAsync(globalDevice.Id, globalUser.Id, now, "global", TenantContext.Global);
        var tenantRevoke = await repository.RevokeAsync(tenantDevice.Id, tenantUser.Id, now, "tenant", tenant);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(globalList.Select(d => d.Id), Is.EquivalentTo(new[] { globalDevice.Id }));
            Assert.That(tenantAsGlobal, Is.Empty);
            Assert.That(globalAsTenant, Is.Empty);
            Assert.That(tenantList.Select(d => d.Id), Is.EquivalentTo(new[] { tenantDevice.Id }));
            Assert.That(globalCount, Is.EqualTo(1));
            Assert.That(tenantAsGlobalCount, Is.Zero);
            Assert.That(globalAsTenantCount, Is.Zero);
            Assert.That(tenantCount, Is.EqualTo(1));
            Assert.That(wrongTenantRevoke, Is.False);
            Assert.That(globalRevoke, Is.True);
            Assert.That(tenantRevoke, Is.True);
        }
    }

    [Test]
    public async Task RevokeAllHonorsTenantScopeAndPreservesFirstRevocation()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetRememberedMfaDeviceRepository(scope.ServiceProvider);
        var tenantId = Guid.NewGuid();
        var tenantUser = await CreateUserAsync(userRepository, tenantId: tenantId);
        var device1 = CreateDevice(tenantUser.Id, tenantId);
        var device2 = CreateDevice(tenantUser.Id, tenantId);
        await repository.CreateAsync(device1);
        await repository.CreateAsync(device2);

        var first = CreatedAt.AddHours(1);
        var second = CreatedAt.AddHours(2);
        var one = await repository.RevokeAsync(device1.Id, tenantUser.Id, first, "first", new TenantContext(tenantId));
        var wrongTenant = await repository.RevokeAllForUserAsync(tenantUser.Id, second, "wrong", TenantContext.Global);
        var count = await repository.RevokeAllForUserAsync(tenantUser.Id, second, "bulk", new TenantContext(tenantId));
        var fetched1 = await repository.GetAsync(device1.Id);
        var fetched2 = await repository.GetAsync(device2.Id);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(one, Is.True);
            Assert.That(wrongTenant, Is.Zero);
            Assert.That(count, Is.EqualTo(1));
            Assert.That(fetched1!.RevokedAt, Is.EqualTo(first));
            Assert.That(fetched1.RevocationReason, Is.EqualTo("first"));
            Assert.That(fetched2!.RevokedAt, Is.EqualTo(second));
            Assert.That(fetched2.RevocationReason, Is.EqualTo("bulk"));
        }
    }

    [Test]
    public async Task WritesRollBackWhenProviderSupportsTransactions()
    {
        Guid id;
        await using (var scope = CreateAsyncScope())
        {
            var transactionProvider = GetTransactionProvider(scope.ServiceProvider);
            if (transactionProvider == null)
            {
                Assert.Ignore("Provider does not register IAshlarTransactionProvider.");
            }

            var user = await CreateUserAsync(GetUserRepository(scope.ServiceProvider));
            var repository = GetRememberedMfaDeviceRepository(scope.ServiceProvider);
            var device = CreateDevice(user.Id);
            id = device.Id;
            await using var transaction = await transactionProvider.BeginTransactionAsync();
            await repository.CreateAsync(device);
            await transaction.RollbackAsync();
        }

        await using var verificationScope = CreateAsyncScope();
        Assert.That(await GetRememberedMfaDeviceRepository(verificationScope.ServiceProvider).GetAsync(id), Is.Null);
    }

    private static RememberedMfaDevice CreateDevice(Guid userId, Guid? tenantId = null, string? selector = null, DateTimeOffset? expiresAt = null)
    {
        return new RememberedMfaDevice
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            TenantId = tenantId,
            TokenSelector = selector ?? $"selector-{Guid.NewGuid():N}",
            TokenHash = $"hash-{Guid.NewGuid():N}",
            DisplayName = "Test device",
            CreatedAt = CreatedAt,
            ExpiresAt = expiresAt ?? CreatedAt.AddDays(1)
        };
    }
}
