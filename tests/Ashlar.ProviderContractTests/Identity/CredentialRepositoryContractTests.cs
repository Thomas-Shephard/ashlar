namespace Ashlar.ProviderContractTests.Identity;

internal abstract class CredentialRepositoryContractTests : ProviderContractFixture
{
    private const string PasswordResetProviderName = "password-reset";
    private const string PasswordResetPurpose = "password-reset";

    [Test]
    public async Task UserMutationLockRequiresTransactionAndExistingUser()
    {
        await using var scope = CreateAsyncScope();
        var users = GetUserRepository(scope.ServiceProvider);
        var credentials = GetCredentialRepository(scope.ServiceProvider);
        var transactions = GetTransactionProvider(scope.ServiceProvider)!;
        var user = await CreateUserAsync(users);

        Assert.ThrowsAsync<InvalidOperationException>(async () => await credentials.AcquireUserMutationLockAsync(user.Id));

        await using var transaction = await transactions.BeginTransactionAsync();
        Assert.DoesNotThrowAsync(async () => await credentials.AcquireUserMutationLockAsync(user.Id));
        Assert.ThrowsAsync<InvalidOperationException>(async () => await credentials.AcquireUserMutationLockAsync(Guid.NewGuid()));
    }

    [Test]
    public async Task UserMutationLockSerializesConcurrentCredentialDecisions()
    {
        await using var firstScope = CreateAsyncScope();
        var users = GetUserRepository(firstScope.ServiceProvider);
        var user = await CreateUserAsync(users);
        await using var firstTransaction = await GetTransactionProvider(firstScope.ServiceProvider)!.BeginTransactionAsync();
        await GetCredentialRepository(firstScope.ServiceProvider).AcquireUserMutationLockAsync(user.Id);

        var secondLock = Task.Run(async () =>
        {
            await using var secondScope = CreateAsyncScope();
            await using var secondTransaction = await GetTransactionProvider(secondScope.ServiceProvider)!.BeginTransactionAsync();
            await GetCredentialRepository(secondScope.ServiceProvider).AcquireUserMutationLockAsync(user.Id);
            await secondTransaction.CommitAsync();
        });

        Assert.ThrowsAsync<TimeoutException>(async () => await secondLock.WaitAsync(TimeSpan.FromMilliseconds(100)));
        await firstTransaction.CommitAsync();
        await secondLock.WaitAsync(TimeSpan.FromSeconds(5));
    }

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
    public async Task PasswordResetInternalCredentialPersistsLifecycleMetadataAndRevocationIsProviderScoped()
    {
        await using var scope = CreateAsyncScope();
        var users = GetUserRepository(scope.ServiceProvider);
        var credentials = GetCredentialRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(users);
        var localPassword = CreateCredential(user.Id, ProviderType.Local, ProviderType.Local.Value, user.Id.ToString("D"));
        var expiresAt = TruncateToMicroseconds(DateTimeOffset.UtcNow.AddHours(2));
        var resetCredential = CreateCredential(user.Id, ProviderType.Internal, PasswordResetProviderName, "reset-token-hash");
        resetCredential.Purpose = PasswordResetPurpose;
        resetCredential.ExpiresAt = expiresAt;
        await credentials.CreateCredentialAsync(localPassword);
        await credentials.CreateOrReplaceCredentialAsync(resetCredential);

        var fetched = await credentials.GetCredentialForUserAsync(user.Id, ProviderType.Internal, PasswordResetProviderName, resetCredential.ProviderKey);
        var revoked = await credentials.RevokeCredentialsAsync(user.Id, ProviderType.Internal, PasswordResetProviderName);
        var replayFetch = await credentials.GetCredentialForUserAsync(user.Id, ProviderType.Internal, PasswordResetProviderName, resetCredential.ProviderKey);
        var passwordFetch = await credentials.GetCredentialForUserAsync(user.Id, ProviderType.Local, ProviderType.Local.Value, localPassword.ProviderKey);
        var all = await credentials.ListCredentialsForUserAsync(user.Id, activeOnly: false);
        var listedReset = all.Single(credential => credential.Id == resetCredential.Id);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched, Is.Not.Null);
            Assert.That(fetched?.Purpose, Is.EqualTo(PasswordResetPurpose));
            Assert.That(fetched?.Status, Is.EqualTo(CredentialStatus.Active));
            Assert.That(fetched?.ExpiresAt, Is.EqualTo(expiresAt));
            Assert.That(fetched?.CredentialValue, Is.Null);
            Assert.That(revoked, Is.EqualTo(1));
            Assert.That(replayFetch, Is.Null);
            Assert.That(passwordFetch, Is.Not.Null);
            Assert.That(listedReset.Status, Is.EqualTo(CredentialStatus.Revoked));
            Assert.That(listedReset.Purpose, Is.EqualTo(PasswordResetPurpose));
            Assert.That(listedReset.ExpiresAt, Is.EqualTo(expiresAt));
            Assert.That(listedReset.RevokedAt, Is.Not.Null);
            Assert.That(listedReset.CredentialValue, Is.Null);
        }
    }

    [Test]
    public async Task CreateOrReplaceCredentialReactivatesRevokedLocalPasswordCredential()
    {
        await using var scope = CreateAsyncScope();
        var users = GetUserRepository(scope.ServiceProvider);
        var credentials = GetCredentialRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(users);
        var providerKey = user.Id.ToString("D");
        var original = CreateCredential(user.Id, ProviderType.Local, ProviderType.Local.Value, providerKey);
        original.CredentialValue = "old-password-hash";
        var replacement = CreateCredential(user.Id, ProviderType.Local, ProviderType.Local.Value, providerKey);
        replacement.CredentialValue = "new-password-hash";

        await credentials.CreateCredentialAsync(original);
        await credentials.RevokeCredentialsAsync(user.Id, ProviderType.Local, ProviderType.Local.Value);
        await credentials.CreateOrReplaceCredentialAsync(replacement);

        var fetched = await credentials.GetCredentialForUserAsync(user.Id, ProviderType.Local, ProviderType.Local.Value, providerKey);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched, Is.Not.Null);
            Assert.That(fetched?.Id, Is.EqualTo(original.Id));
            Assert.That(fetched?.Status, Is.EqualTo(CredentialStatus.Active));
            Assert.That(fetched?.RevokedAt, Is.Null);
            Assert.That(fetched?.CredentialValue, Is.EqualTo("new-password-hash"));
        }
    }

    [Test]
    public async Task CredentialListingSeparatesActiveRevokedAndExpiredLifecycleStates()
    {
        await using var scope = CreateAsyncScope();
        var users = GetUserRepository(scope.ServiceProvider);
        var credentials = GetCredentialRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(users);
        var now = TruncateToMicroseconds(DateTimeOffset.UtcNow);
        var active = CreateCredential(user.Id, ProviderType.Local, ProviderType.Local.Value);
        active.ExpiresAt = now.AddHours(1);
        var expired = CreateCredential(user.Id, ProviderType.MagicLink, ProviderType.MagicLink.Value);
        expired.ExpiresAt = now.AddMilliseconds(-1);
        var revoked = CreateCredential(user.Id, ProviderType.EmailCode, ProviderType.EmailCode.Value);
        revoked.Status = CredentialStatus.Revoked;
        revoked.RevokedAt = now.AddMinutes(-5);
        await credentials.CreateCredentialAsync(active);
        await credentials.CreateCredentialAsync(expired);
        await credentials.CreateCredentialAsync(revoked);

        var activeOnly = await credentials.ListCredentialsForUserAsync(user.Id);
        var all = await credentials.ListCredentialsForUserAsync(user.Id, activeOnly: false);
        var expiredFetch = await credentials.GetCredentialForUserAsync(user.Id, ProviderType.MagicLink, ProviderType.MagicLink.Value, expired.ProviderKey);
        var revokedFetch = await credentials.GetCredentialForUserAsync(user.Id, ProviderType.EmailCode, ProviderType.EmailCode.Value, revoked.ProviderKey);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(activeOnly.Select(static credential => credential.Id), Is.EquivalentTo(new[] { active.Id, expired.Id }));
            Assert.That(all.Select(static credential => credential.Id), Is.EquivalentTo(new[] { active.Id, expired.Id, revoked.Id }));
            Assert.That(expiredFetch?.Id, Is.EqualTo(expired.Id));
            Assert.That(expiredFetch?.ExpiresAt, Is.EqualTo(expired.ExpiresAt));
            Assert.That(revokedFetch, Is.Null);
        }
    }

    [Test]
    public async Task CreateCredentialPathsRequireExistingUser()
    {
        await using var scope = CreateAsyncScope();
        var credentials = GetCredentialRepository(scope.ServiceProvider);
        var credential = CreateCredential(Guid.NewGuid(), ProviderType.Local, ProviderType.Local.Value);
        var replacement = CreateCredential(Guid.NewGuid(), ProviderType.Internal, PasswordResetProviderName, "reset-token-hash");

        Assert.CatchAsync(async () => await credentials.CreateCredentialAsync(credential));
        Assert.CatchAsync(async () => await credentials.CreateOrReplaceCredentialAsync(replacement));
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
    public async Task CredentialListingReturnsCompleteInventory()
    {
        await using var scope = CreateAsyncScope();
        var users = GetUserRepository(scope.ServiceProvider);
        var credentials = GetCredentialRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(users);
        for (var i = 0; i < 101; i++)
        {
            await credentials.CreateCredentialAsync(CreateCredential(user.Id, ProviderType.Mfa, "factor", i.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        }

        Assert.That(await credentials.ListCredentialsForUserAsync(user.Id), Has.Count.EqualTo(101));
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
            await users.CreateUserAsync(new AshlarUser { Id = userId, DisplayEmail = "rollback@example.com", AccountState = UserAccountState.Active });
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

    private static DateTimeOffset TruncateToMicroseconds(DateTimeOffset value)
    {
        return new DateTimeOffset(value.Ticks - value.Ticks % 10, value.Offset);
    }
}
