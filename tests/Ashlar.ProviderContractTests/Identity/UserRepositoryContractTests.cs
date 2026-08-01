namespace Ashlar.ProviderContractTests.Identity;

/// <summary>Tests user persistence, normalized lookup, tenant isolation, credentials, and rollback.</summary>
public abstract class UserRepositoryContractTests : ProviderContractFixture
{
    private const string PasswordResetProviderName = "password-reset";

    /// <summary>Verifies that a created user can be recovered by its assigned ID.</summary>
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
            Assert.That(fetched.DisplayEmail, Is.EqualTo(user.DisplayEmail));
        }
    }

    /// <summary>Verifies that normalized email lookup remains case-insensitive without crossing tenants.</summary>
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
            Assert.That(fetchedNoTenant?.DisplayEmail, Is.EqualTo(email));
            Assert.That(fetchedTenant1?.Id, Is.EqualTo(user1.Id));
            Assert.That(fetchedTenant1?.DisplayEmail, Is.EqualTo(email));
            Assert.That(fetchedTenant2?.Id, Is.EqualTo(user2.Id));
            Assert.That(fetchedTenant2?.DisplayEmail, Is.EqualTo(email));
        }
    }

    /// <summary>Verifies that writes preserve display email while lookup uses its normalized form.</summary>
    [Test]
    public async Task CreateAndUpdatePreserveDisplayEmailWhileLookupUsesNormalizedEmail()
    {
        await using var scope = CreateAsyncScope();
        var users = GetUserRepository(scope.ServiceProvider);
        var tenantId = Guid.NewGuid();
        var user = await CreateUserAsync(users, "Display.User@Example.COM", tenantId);

        var fetchedByLowercase = await users.GetUserByEmailAsync("display.user@example.com", tenantId);
        await users.UpdateUserAsync(user with { DisplayEmail = "Updated.User@Example.COM" });
        var updatedByUppercase = await users.GetUserByEmailAsync("UPDATED.USER@EXAMPLE.COM", tenantId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetchedByLowercase?.DisplayEmail, Is.EqualTo("Display.User@Example.COM"));
            Assert.That(updatedByUppercase?.Id, Is.EqualTo(user.Id));
            Assert.That(updatedByUppercase?.DisplayEmail, Is.EqualTo("Updated.User@Example.COM"));
        }
    }

    /// <summary>Leaves unknown identifiers, emails, and provider keys distinguishable from stored users.</summary>
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

    /// <summary>Verifies that user updates persist all mutable profile fields.</summary>
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

    /// <summary>Verifies that user lookup preserves active and verification state.</summary>
    /// <param name="accountState">Account state that must survive persistence.</param>
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

    /// <summary>Rejects duplicate normalized email addresses within a tenant while allowing other tenants.</summary>
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

    /// <summary>Verifies that an external provider key resolves its owning user.</summary>
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

    /// <summary>Refuses to resolve a user through a credential after that credential is revoked.</summary>
    [Test]
    public async Task ProviderKeyLookupIgnoresRevokedCredential()
    {
        await using var scope = CreateAsyncScope();
        var users = GetUserRepository(scope.ServiceProvider);
        var credentials = GetCredentialRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(users);
        var credential = CreateCredential(user.Id, ProviderType.Internal, PasswordResetProviderName, "reset-token-hash");

        await credentials.CreateCredentialAsync(credential);
        var linkedUser = await users.GetUserByProviderKeyAsync(ProviderType.Internal, PasswordResetProviderName, credential.ProviderKey);
        await credentials.RevokeCredentialsAsync(user.Id, ProviderType.Internal, PasswordResetProviderName);
        var revokedUser = await users.GetUserByProviderKeyAsync(ProviderType.Internal, PasswordResetProviderName, credential.ProviderKey);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(linkedUser?.Id, Is.EqualTo(user.Id));
            Assert.That(revokedUser, Is.Null);
        }
    }

    /// <summary>Refuses to resolve a user through a one-time credential after it is consumed.</summary>
    [Test]
    public async Task ProviderKeyLookupIgnoresConsumedCredential()
    {
        await using var scope = CreateAsyncScope();
        var users = GetUserRepository(scope.ServiceProvider);
        var credentials = GetCredentialRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(users);
        var credential = CreateCredential(user.Id, ProviderType.Internal, PasswordResetProviderName, "reset-token-hash");

        await credentials.CreateCredentialAsync(credential);
        var linkedUser = await users.GetUserByProviderKeyAsync(ProviderType.Internal, PasswordResetProviderName, credential.ProviderKey);
        await credentials.ConsumeCredentialAsync(credential.Id, credential.Version);
        var consumedUser = await users.GetUserByProviderKeyAsync(ProviderType.Internal, PasswordResetProviderName, credential.ProviderKey);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(linkedUser?.Id, Is.EqualTo(user.Id));
            Assert.That(consumedUser, Is.Null);
        }
    }

    /// <summary>Leaves no persisted user after its surrounding transaction is rolled back.</summary>
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
            await users.CreateUserAsync(new AshlarUser { Id = userId, DisplayEmail = "rollback@example.com", AccountState = UserAccountState.Active });
            await transaction.RollbackAsync();
        }

        await using var verificationScope = CreateAsyncScope();
        var verificationUsers = GetUserRepository(verificationScope.ServiceProvider);
        Assert.That(await verificationUsers.GetUserByIdAsync(userId), Is.Null);
    }
}
