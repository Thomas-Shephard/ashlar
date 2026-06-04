namespace Ashlar.ProviderContractTests.Identity;

internal abstract class CredentialRepositoryContractTests : ProviderContractFixture
{
    [Test]
    public async Task CredentialCreateReadAndProviderKeyOwnershipWork()
    {
        await using var scope = CreateAsyncScope();
        var users = GetUserRepository(scope.ServiceProvider);
        var credentials = GetCredentialRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(users);
        var otherUser = await CreateUserAsync(users);
        var credential = CreateCredential(user.Id, ProviderType.OAuth, "github", "gh-1");

        await credentials.CreateCredentialAsync(credential);

        var fetched = await credentials.GetCredentialForUserAsync(user.Id, ProviderType.OAuth, "github", "gh-1");
        var wrongUserCredential = await credentials.GetCredentialForUserAsync(otherUser.Id, ProviderType.OAuth, "github", "gh-1");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched?.Id, Is.EqualTo(credential.Id));
            Assert.That(wrongUserCredential, Is.Null);
        }
    }

    [Test]
    public async Task CreateOrReplaceCredentialUpdatesExistingIdentityWithoutMovingUsers()
    {
        await using var scope = CreateAsyncScope();
        var users = GetUserRepository(scope.ServiceProvider);
        var credentials = GetCredentialRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(users);
        var otherUser = await CreateUserAsync(users);
        var original = CreateCredential(user.Id, ProviderType.EmailCode, ProviderType.EmailCode.Value, "shared-key");
        original.CredentialValue = "first";
        original.LastUsedAt = new DateTimeOffset(2026, 5, 1, 10, 0, 0, TimeSpan.Zero);
        var replacement = CreateCredential(user.Id, ProviderType.EmailCode, ProviderType.EmailCode.Value, "shared-key");
        replacement.CredentialValue = "second";
        replacement.Metadata = "{}";

        await credentials.CreateOrReplaceCredentialAsync(original);
        await credentials.CreateOrReplaceCredentialAsync(replacement);

        var fetched = await credentials.GetCredentialForUserAsync(user.Id, ProviderType.EmailCode, ProviderType.EmailCode.Value, "shared-key");
        var moved = CreateCredential(otherUser.Id, ProviderType.EmailCode, ProviderType.EmailCode.Value, "shared-key");
        Assert.ThrowsAsync<CredentialProviderKeyConflictException>(async () => await credentials.CreateOrReplaceCredentialAsync(moved));
        var otherFetched = await credentials.GetCredentialForUserAsync(otherUser.Id, ProviderType.EmailCode, ProviderType.EmailCode.Value, "shared-key");

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
        var users = GetUserRepository(scope.ServiceProvider);
        var credentials = GetCredentialRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(users);
        var credential = CreateCredential(user.Id, ProviderType.Local, ProviderType.Local.Value);
        credential.CredentialValue = "first";
        await credentials.CreateCredentialAsync(credential);

        var fetched = await credentials.GetCredentialForUserAsync(user.Id, ProviderType.Local, ProviderType.Local.Value, credential.ProviderKey);
        Assert.That(fetched, Is.Not.Null);
        var expectedVersion = fetched!.Version;
        fetched.CredentialValue = "updated";

        var updated = await credentials.UpdateCredentialAsync(fetched, expectedVersion);
        var staleUpdate = await credentials.UpdateCredentialAsync(fetched, expectedVersion);
        var updatedFetched = await credentials.GetCredentialForUserAsync(user.Id, ProviderType.Local, ProviderType.Local.Value, credential.ProviderKey);

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
        var users = GetUserRepository(scope.ServiceProvider);
        var credentials = GetCredentialRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(users);
        var credential = CreateCredential(user.Id, ProviderType.Local, "otp");
        await credentials.CreateCredentialAsync(credential);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(await credentials.ConsumeCredentialAsync(credential.Id, credential.Version), Is.True);
            Assert.That(await credentials.ConsumeCredentialAsync(credential.Id, credential.Version), Is.False);
            Assert.That(await credentials.GetCredentialForUserAsync(user.Id, ProviderType.Local, "otp", credential.ProviderKey), Is.Null);
        }
    }

    [Test]
    public async Task RevokeCredentialsAffectsMatchingActiveCredentialsOnly()
    {
        await using var scope = CreateAsyncScope();
        var users = GetUserRepository(scope.ServiceProvider);
        var credentials = GetCredentialRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(users);
        var otherUser = await CreateUserAsync(users);
        var matching1 = CreateCredential(user.Id, ProviderType.MagicLink, ProviderType.MagicLink.Value);
        var matching2 = CreateCredential(user.Id, ProviderType.MagicLink, ProviderType.MagicLink.Value);
        var otherProvider = CreateCredential(user.Id, ProviderType.EmailCode, ProviderType.EmailCode.Value);
        var otherUserCredential = CreateCredential(otherUser.Id, ProviderType.MagicLink, ProviderType.MagicLink.Value);
        await credentials.CreateCredentialAsync(matching1);
        await credentials.CreateCredentialAsync(matching2);
        await credentials.CreateCredentialAsync(otherProvider);
        await credentials.CreateCredentialAsync(otherUserCredential);

        var revoked = await credentials.RevokeCredentialsAsync(user.Id, ProviderType.MagicLink, ProviderType.MagicLink.Value);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revoked, Is.EqualTo(2));
            Assert.That(await credentials.GetCredentialForUserAsync(user.Id, ProviderType.MagicLink, ProviderType.MagicLink.Value, matching1.ProviderKey), Is.Null);
            Assert.That(await credentials.GetCredentialForUserAsync(user.Id, ProviderType.MagicLink, ProviderType.MagicLink.Value, matching2.ProviderKey), Is.Null);
            Assert.That(await credentials.GetCredentialForUserAsync(user.Id, ProviderType.EmailCode, ProviderType.EmailCode.Value, otherProvider.ProviderKey), Is.Not.Null);
            Assert.That(await credentials.GetCredentialForUserAsync(otherUser.Id, ProviderType.MagicLink, ProviderType.MagicLink.Value, otherUserCredential.ProviderKey), Is.Not.Null);
        }
    }

    [Test]
    public async Task CredentialListingOmitsSecretCredentialValues()
    {
        await using var scope = CreateAsyncScope();
        var users = GetUserRepository(scope.ServiceProvider);
        var credentials = GetCredentialRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(users);
        var activeCredential = CreateCredential(user.Id, ProviderType.Local, ProviderType.Local.Value);
        activeCredential.CredentialValue = "secret";
        var revokedCredential = CreateCredential(user.Id, ProviderType.MagicLink, ProviderType.MagicLink.Value);
        await credentials.CreateCredentialAsync(activeCredential);
        await credentials.CreateCredentialAsync(revokedCredential);
        await credentials.RevokeCredentialsAsync(user.Id, ProviderType.MagicLink, ProviderType.MagicLink.Value);

        var active = await credentials.ListCredentialsForUserAsync(user.Id);
        var all = await credentials.ListCredentialsForUserAsync(user.Id, activeOnly: false);

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

            userId = Guid.NewGuid();

            await using var transaction = await transactionProvider.BeginTransactionAsync();
            var users = GetUserRepository(scope.ServiceProvider);
            var credentials = GetCredentialRepository(scope.ServiceProvider);
            await users.CreateUserAsync(new AshlarUser { Id = userId, Email = "rollback@example.com", AccountState = UserAccountState.Active });
            await credentials.CreateCredentialAsync(CreateCredential(userId, ProviderType.Local, ProviderType.Local.Value));
            await transaction.RollbackAsync();
        }

        await using var verificationScope = CreateAsyncScope();
        var verificationUsers = GetUserRepository(verificationScope.ServiceProvider);
        var verificationCredentials = GetCredentialRepository(verificationScope.ServiceProvider);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(await verificationUsers.GetUserByIdAsync(userId), Is.Null);
            Assert.That(await verificationCredentials.ListCredentialsForUserAsync(userId, activeOnly: false), Is.Empty);
        }
    }
}
