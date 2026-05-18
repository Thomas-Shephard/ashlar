using Ashlar.Identity.Models;

namespace Ashlar.ProviderContractTests.Identity;

internal abstract class IdentityRepositoryContractTests : ProviderContractFixture
{
    [Test]
    public async Task CreateAndFetchUserById()
    {
        await using var scope = CreateAsyncScope();
        var repo = GetIdentityRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(repo, "fetch-by-id@example.com");

        var fetched = await repo.GetUserByIdAsync(user.Id);

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
        var repo = GetIdentityRepository(scope.ServiceProvider);
        var tenant1 = Guid.NewGuid();
        var tenant2 = Guid.NewGuid();
        const string email = "MixedCase@example.com";
        var noTenant = await CreateUserAsync(repo, email, isActive: false);
        var user1 = await CreateUserAsync(repo, email, tenant1);
        var user2 = await CreateUserAsync(repo, email, tenant2);

        var fetchedNoTenant = await repo.GetUserByEmailAsync("mixedcase@example.com");
        var fetchedTenant1 = await repo.GetUserByEmailAsync("mixedcase@example.com", tenant1);
        var fetchedTenant2 = await repo.GetUserByEmailAsync("mixedcase@example.com", tenant2);

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
        var repo = GetIdentityRepository(scope.ServiceProvider);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(await repo.GetUserByIdAsync(Guid.NewGuid()), Is.Null);
            Assert.That(await repo.GetUserByEmailAsync("missing@example.com"), Is.Null);
            Assert.That(await repo.GetUserByProviderKeyAsync(ProviderType.OAuth, "github", "missing"), Is.Null);
        }
    }

    [Test]
    public async Task UpdateUserChangesMutableFields()
    {
        await using var scope = CreateAsyncScope();
        var repo = GetIdentityRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(repo, "update-user@example.com");

        await repo.UpdateUserAsync(user with { Name = "Updated Name", IsActive = false, EmailVerifiedAt = DateTimeOffset.UtcNow });
        var fetched = await repo.GetUserByIdAsync(user.Id);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched?.Name, Is.EqualTo("Updated Name"));
            Assert.That(fetched?.IsActive, Is.False);
            Assert.That(fetched?.EmailVerifiedAt, Is.Not.Null);
        }
    }

    [Test]
    public async Task DuplicateNormalizedEmailUniquenessIsEnforcedPerTenant()
    {
        await using var scope = CreateAsyncScope();
        var repo = GetIdentityRepository(scope.ServiceProvider);
        var tenantId = Guid.NewGuid();

        await CreateUserAsync(repo, "dupe@example.com");
        await CreateUserAsync(repo, "dupe@example.com", tenantId);

        Assert.That(async () => await CreateUserAsync(repo, "DUPE@example.com"), Throws.Exception);
        Assert.That(async () => await CreateUserAsync(repo, "DUPE@example.com", tenantId), Throws.Exception);
    }

    [Test]
    public async Task CredentialCreateReadAndProviderKeyLookupWork()
    {
        await using var scope = CreateAsyncScope();
        var repo = GetIdentityRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(repo);
        var otherUser = await CreateUserAsync(repo);
        var credential = CreateCredential(user.Id, ProviderType.OAuth, "github", "gh-1");

        await repo.CreateCredentialAsync(credential);

        var fetched = await repo.GetCredentialForUserAsync(user.Id, ProviderType.OAuth, "github", "gh-1");
        var wrongUserCredential = await repo.GetCredentialForUserAsync(otherUser.Id, ProviderType.OAuth, "github", "gh-1");
        var fetchedUser = await repo.GetUserByProviderKeyAsync(ProviderType.OAuth, "github", "gh-1");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched?.Id, Is.EqualTo(credential.Id));
            Assert.That(wrongUserCredential, Is.Null);
            Assert.That(fetchedUser?.Id, Is.EqualTo(user.Id));
        }
    }

    [Test]
    public async Task CreateOrReplaceCredentialUpdatesExistingIdentityWithoutMovingUsers()
    {
        await using var scope = CreateAsyncScope();
        var repo = GetIdentityRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(repo);
        var otherUser = await CreateUserAsync(repo);
        var original = CreateCredential(user.Id, ProviderType.EmailCode, ProviderType.EmailCode.Value, "shared-key");
        original.CredentialValue = "first";
        original.LastUsedAt = new DateTimeOffset(2026, 5, 1, 10, 0, 0, TimeSpan.Zero);
        var replacement = CreateCredential(user.Id, ProviderType.EmailCode, ProviderType.EmailCode.Value, "shared-key");
        replacement.CredentialValue = "second";
        replacement.Metadata = "{}";

        await repo.CreateOrReplaceCredentialAsync(original);
        await repo.CreateOrReplaceCredentialAsync(replacement);

        var fetched = await repo.GetCredentialForUserAsync(user.Id, ProviderType.EmailCode, ProviderType.EmailCode.Value, "shared-key");
        var moved = CreateCredential(otherUser.Id, ProviderType.EmailCode, ProviderType.EmailCode.Value, "shared-key");
        Assert.ThrowsAsync<InvalidOperationException>(async () => await repo.CreateOrReplaceCredentialAsync(moved));
        var otherFetched = await repo.GetCredentialForUserAsync(otherUser.Id, ProviderType.EmailCode, ProviderType.EmailCode.Value, "shared-key");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched?.Id, Is.EqualTo(original.Id));
            Assert.That(fetched?.CredentialValue, Is.EqualTo("second"));
            Assert.That(fetched?.Metadata, Is.EqualTo("{}"));
            Assert.That(fetched?.LastUsedAt, Is.EqualTo(original.LastUsedAt));
            Assert.That(otherFetched, Is.Null);
        }
    }

    [Test]
    public async Task VersionedCredentialUpdateSucceedsOnceAndFailsWithStaleVersion()
    {
        await using var scope = CreateAsyncScope();
        var repo = GetIdentityRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(repo);
        var credential = CreateCredential(user.Id, ProviderType.Local, ProviderType.Local.Value);
        credential.CredentialValue = "first";
        await repo.CreateCredentialAsync(credential);

        var fetched = await repo.GetCredentialForUserAsync(user.Id, ProviderType.Local, ProviderType.Local.Value, credential.ProviderKey);
        Assert.That(fetched, Is.Not.Null);
        var expectedVersion = fetched!.Version;
        fetched.CredentialValue = "updated";

        var updated = await repo.UpdateCredentialAsync(fetched, expectedVersion);
        var staleUpdate = await repo.UpdateCredentialAsync(fetched, expectedVersion);
        var updatedFetched = await repo.GetCredentialForUserAsync(user.Id, ProviderType.Local, ProviderType.Local.Value, credential.ProviderKey);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(updated, Is.True);
            Assert.That(staleUpdate, Is.False);
            Assert.That(updatedFetched?.CredentialValue, Is.EqualTo("updated"));
        }
    }

    [Test]
    public async Task CredentialConsumeSucceedsOnceAndPreventsReplay()
    {
        await using var scope = CreateAsyncScope();
        var repo = GetIdentityRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(repo);
        var credential = CreateCredential(user.Id, ProviderType.Local, "otp");
        await repo.CreateCredentialAsync(credential);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(await repo.ConsumeCredentialAsync(credential.Id, credential.Version), Is.True);
            Assert.That(await repo.ConsumeCredentialAsync(credential.Id, credential.Version), Is.False);
            Assert.That(await repo.GetCredentialForUserAsync(user.Id, ProviderType.Local, "otp", credential.ProviderKey), Is.Null);
        }
    }

    [Test]
    public async Task RevokeCredentialsAffectsMatchingActiveCredentialsOnly()
    {
        await using var scope = CreateAsyncScope();
        var repo = GetIdentityRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(repo);
        var otherUser = await CreateUserAsync(repo);
        var matching1 = CreateCredential(user.Id, ProviderType.MagicLink, ProviderType.MagicLink.Value);
        var matching2 = CreateCredential(user.Id, ProviderType.MagicLink, ProviderType.MagicLink.Value);
        var otherProvider = CreateCredential(user.Id, ProviderType.EmailCode, ProviderType.EmailCode.Value);
        var otherUserCredential = CreateCredential(otherUser.Id, ProviderType.MagicLink, ProviderType.MagicLink.Value);
        await repo.CreateCredentialAsync(matching1);
        await repo.CreateCredentialAsync(matching2);
        await repo.CreateCredentialAsync(otherProvider);
        await repo.CreateCredentialAsync(otherUserCredential);

        var revoked = await repo.RevokeCredentialsAsync(user.Id, ProviderType.MagicLink, ProviderType.MagicLink.Value);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revoked, Is.EqualTo(2));
            Assert.That(await repo.GetCredentialForUserAsync(user.Id, ProviderType.MagicLink, ProviderType.MagicLink.Value, matching1.ProviderKey), Is.Null);
            Assert.That(await repo.GetCredentialForUserAsync(user.Id, ProviderType.MagicLink, ProviderType.MagicLink.Value, matching2.ProviderKey), Is.Null);
            Assert.That(await repo.GetCredentialForUserAsync(user.Id, ProviderType.EmailCode, ProviderType.EmailCode.Value, otherProvider.ProviderKey), Is.Not.Null);
            Assert.That(await repo.GetCredentialForUserAsync(otherUser.Id, ProviderType.MagicLink, ProviderType.MagicLink.Value, otherUserCredential.ProviderKey), Is.Not.Null);
        }
    }

    [Test]
    public async Task CredentialListingOmitsSecretCredentialValues()
    {
        await using var scope = CreateAsyncScope();
        var repo = GetIdentityRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(repo);
        var activeCredential = CreateCredential(user.Id, ProviderType.Local, ProviderType.Local.Value);
        activeCredential.CredentialValue = "secret";
        var revokedCredential = CreateCredential(user.Id, ProviderType.MagicLink, ProviderType.MagicLink.Value);
        await repo.CreateCredentialAsync(activeCredential);
        await repo.CreateCredentialAsync(revokedCredential);
        await repo.RevokeCredentialsAsync(user.Id, ProviderType.MagicLink, ProviderType.MagicLink.Value);

        var active = await repo.ListCredentialsForUserAsync(user.Id);
        var all = await repo.ListCredentialsForUserAsync(user.Id, activeOnly: false);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(active, Has.Count.EqualTo(1));
            Assert.That(active[0].Id, Is.EqualTo(activeCredential.Id));
            Assert.That(active[0].CredentialValue, Is.Null);
            Assert.That(all, Has.Count.EqualTo(2));
        }
    }

    [Test]
    public async Task UserAndCredentialWritesRollBackWhenProviderSupportsTransactions()
    {
        Guid userId;
        await using (var scope = CreateAsyncScope())
        {
            var transactionProvider = GetTransactionProvider(scope.ServiceProvider);
            if (transactionProvider == null)
            {
                Assert.Ignore("Provider does not register IAshlarTransactionProvider.");
            }

            var repo = GetIdentityRepository(scope.ServiceProvider);
            userId = Guid.NewGuid();

            await using var transaction = await transactionProvider.BeginTransactionAsync();
            await repo.CreateUserAsync(new AshlarUser { Id = userId, Email = "rollback@example.com", IsActive = true });
            await repo.CreateCredentialAsync(CreateCredential(userId, ProviderType.Local, ProviderType.Local.Value));
            await transaction.RollbackAsync();
        }

        await using var verificationScope = CreateAsyncScope();
        var verificationRepo = GetIdentityRepository(verificationScope.ServiceProvider);
        Assert.That(await verificationRepo.GetUserByIdAsync(userId), Is.Null);
    }
}
