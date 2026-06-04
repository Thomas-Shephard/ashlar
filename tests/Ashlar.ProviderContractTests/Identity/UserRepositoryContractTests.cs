namespace Ashlar.ProviderContractTests.Identity;

internal abstract class UserRepositoryContractTests : ProviderContractFixture
{
    [Test]
    public async Task CreateAndFetchUserById()
    {
        await using var scope = CreateAsyncScope();
        var users = GetUserRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(users, "fetch-by-id@example.com");

        var fetched = await users.GetUserByIdAsync(user.Id);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched, Is.Not.Null);
            Assert.That(fetched!.Id, Is.EqualTo(user.Id));
            Assert.That(fetched.Email, Is.EqualTo(user.Email));
        }
    }

    [Test]
    public async Task EmailLookupIsCaseInsensitiveAndTenantIsolated()
    {
        await using var scope = CreateAsyncScope();
        var users = GetUserRepository(scope.ServiceProvider);
        var tenant1 = Guid.NewGuid();
        var tenant2 = Guid.NewGuid();
        const string email = "MixedCase@example.com";
        var noTenant = await CreateUserAsync(users, email, AccountState: UserAccountState.Disabled);
        var user1 = await CreateUserAsync(users, email, tenant1);
        var user2 = await CreateUserAsync(users, email, tenant2);

        var fetchedNoTenant = await users.GetUserByEmailAsync("mixedcase@example.com");
        var fetchedTenant1 = await users.GetUserByEmailAsync("mixedcase@example.com", tenant1);
        var fetchedTenant2 = await users.GetUserByEmailAsync("mixedcase@example.com", tenant2);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetchedNoTenant?.Id, Is.EqualTo(noTenant.Id));
            Assert.That(fetchedTenant1?.Id, Is.EqualTo(user1.Id));
            Assert.That(fetchedTenant2?.Id, Is.EqualTo(user2.Id));
        }
    }

    [Test]
    public async Task MissingLookupsReturnNull()
    {
        await using var scope = CreateAsyncScope();
        var users = GetUserRepository(scope.ServiceProvider);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(await users.GetUserByIdAsync(Guid.NewGuid()), Is.Null);
            Assert.That(await users.GetUserByEmailAsync("missing@example.com"), Is.Null);
            Assert.That(await users.GetUserByProviderKeyAsync(ProviderType.OAuth, "github", "missing"), Is.Null);
        }
    }

    [Test]
    public async Task UpdateUserChangesMutableFields()
    {
        await using var scope = CreateAsyncScope();
        var users = GetUserRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(users, "update-user@example.com");

        await users.UpdateUserAsync(user with { Name = "Updated Name", AccountState = UserAccountState.Disabled, EmailVerifiedAt = DateTimeOffset.UtcNow });
        var fetched = await users.GetUserByIdAsync(user.Id);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched?.Name, Is.EqualTo("Updated Name"));
            Assert.That(fetched?.AccountState, Is.EqualTo(UserAccountState.Disabled));
            Assert.That(fetched?.EmailVerifiedAt, Is.Not.Null);
        }
    }

    [TestCase(UserAccountState.Active)]
    [TestCase(UserAccountState.Disabled)]
    [TestCase(UserAccountState.Locked)]
    [TestCase(UserAccountState.Suspended)]
    public async Task CreateAndFetchUserRoundTripsAccountState(UserAccountState accountState)
    {
        await using var scope = CreateAsyncScope();
        var users = GetUserRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(users, $"{accountState.ToStorageValue()}@example.com", AccountState: accountState);

        var fetched = await users.GetUserByIdAsync(user.Id);

        Assert.That(fetched?.AccountState, Is.EqualTo(accountState));
    }

    [Test]
    public async Task DuplicateNormalizedEmailUniquenessIsEnforcedPerTenant()
    {
        await using var scope = CreateAsyncScope();
        var users = GetUserRepository(scope.ServiceProvider);
        var tenantId = Guid.NewGuid();

        await CreateUserAsync(users, "dupe@example.com");
        await CreateUserAsync(users, "dupe@example.com", tenantId);

        Assert.That(async () => await CreateUserAsync(users, "DUPE@example.com"), Throws.Exception);
        Assert.That(async () => await CreateUserAsync(users, "DUPE@example.com", tenantId), Throws.Exception);
    }

    [Test]
    public async Task ProviderKeyLookupReturnsLinkedUser()
    {
        await using var scope = CreateAsyncScope();
        var users = GetUserRepository(scope.ServiceProvider);
        var credentials = GetCredentialRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(users);
        var credential = CreateCredential(user.Id, ProviderType.OAuth, "github", "gh-1");

        await credentials.CreateCredentialAsync(credential);

        var fetchedUser = await users.GetUserByProviderKeyAsync(ProviderType.OAuth, "github", "gh-1");

        Assert.That(fetchedUser?.Id, Is.EqualTo(user.Id));
    }

    [Test]
    public async Task UserWritesRollBackWhenProviderSupportsTransactions()
    {
        Guid userId;
        await using (var scope = CreateAsyncScope())
        {
            var transactionProvider = GetTransactionProvider(scope.ServiceProvider);
            if (transactionProvider == null)
            {
                Assert.Ignore("Provider does not register IAshlarTransactionProvider.");
            }

            var users = GetUserRepository(scope.ServiceProvider);
            userId = Guid.NewGuid();

            await using var transaction = await transactionProvider.BeginTransactionAsync();
            await users.CreateUserAsync(new AshlarUser { Id = userId, Email = "rollback@example.com", AccountState = UserAccountState.Active });
            await transaction.RollbackAsync();
        }

        await using var verificationScope = CreateAsyncScope();
        var verificationUsers = GetUserRepository(verificationScope.ServiceProvider);
        Assert.That(await verificationUsers.GetUserByIdAsync(userId), Is.Null);
    }
}
