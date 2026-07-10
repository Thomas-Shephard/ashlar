using Ashlar.Sqlite.Models;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;

namespace Ashlar.Sqlite.Tests.Identity;

internal sealed class SqliteUserAndCredentialRepositoryTests : SqliteTestBase
{
    private ServiceProvider _serviceProvider = null!;

    [SetUp]
    public async Task SetUp()
    {
        var services = new ServiceCollection();
        services.AddAshlarSqlite(GetConnectionString());
        _serviceProvider = services.BuildServiceProvider();
        await _serviceProvider.InitializeAshlarSqliteSchemaAsync();
    }

    [TearDown]
    public async Task TearDownAsync()
    {
        await _serviceProvider.DisposeAsync();
    }

    [Test]
    public void ConstructorThrowsOnNullConnectionProvider()
    {
        Assert.Throws<ArgumentNullException>(() => _ = new SqliteUserRepository(null!));
        Assert.Throws<ArgumentNullException>(() => _ = new SqliteCredentialRepository(null!));
    }

    [Test]
    public async Task UserCreateFetchEmailLookupAndTenantIsolationShouldWork()
    {
        await using var scope = _serviceProvider.CreateAsyncScope();
        var repo = GetRepository(scope.ServiceProvider);
        var tenant1 = Guid.NewGuid();
        var tenant2 = Guid.NewGuid();
        var email = "MixedCase@Example.Com";
        var noTenant = new AshlarUser { Id = Guid.NewGuid(), DisplayEmail = email, Name = "No Tenant", AccountState = UserAccountState.Disabled };
        var user1 = new AshlarUser { Id = Guid.NewGuid(), DisplayEmail = email, Name = "Tenant 1", AccountState = UserAccountState.Active, TenantId = tenant1 };
        var user2 = new AshlarUser { Id = Guid.NewGuid(), DisplayEmail = email, Name = "Tenant 2", AccountState = UserAccountState.Active, TenantId = tenant2 };

        await repo.CreateUserAsync(noTenant);
        await repo.CreateUserAsync(user1);
        await repo.CreateUserAsync(user2);

        var fetchedById = await repo.GetUserByIdAsync(user1.Id);
        var fetchedNoTenant = await repo.GetUserByEmailAsync("mixedcase@example.com");
        var fetchedTenant1 = await repo.GetUserByEmailAsync("mixedcase@example.com", tenant1);
        var fetchedTenant2 = await repo.GetUserByEmailAsync("mixedcase@example.com", tenant2);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetchedById?.Id, Is.EqualTo(user1.Id));
            Assert.That(fetchedNoTenant?.Id, Is.EqualTo(noTenant.Id));
            Assert.That(fetchedNoTenant?.AccountState, Is.EqualTo(UserAccountState.Disabled));
            Assert.That(fetchedTenant1?.Id, Is.EqualTo(user1.Id));
            Assert.That(fetchedTenant2?.Id, Is.EqualTo(user2.Id));
        }
    }

    [Test]
    public async Task MissingLookupsReturnNull()
    {
        await using var scope = _serviceProvider.CreateAsyncScope();
        var repo = GetRepository(scope.ServiceProvider);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(await repo.GetUserByEmailAsync("missing@example.com"), Is.Null);
            Assert.That(await repo.GetUserByProviderKeyAsync(ProviderType.OAuth, "github", "missing"), Is.Null);
        }
    }

    [Test]
    public async Task UpdateUserHandlesAuditNonAuditInvalidAndMissingUsers()
    {
        await using var scope = _serviceProvider.CreateAsyncScope();
        var repo = GetRepository(scope.ServiceProvider);
        var auditUser = new AshlarSqliteUser
        {
            Id = Guid.NewGuid(),
            DisplayEmail = "audit@example.com",
            Name = "Original",
            AccountState = UserAccountState.Active,
            CreatedAt = new DateTimeOffset(2026, 5, 1, 0, 0, 0, TimeSpan.Zero)
        };
        await repo.CreateUserAsync(auditUser);

        auditUser.Name = "Updated";
        await repo.UpdateUserAsync(auditUser);
        var fetchedAudit = await repo.GetUserByIdAsync(auditUser.Id);

        var nonAuditUser = new AshlarUser { Id = Guid.NewGuid(), DisplayEmail = "non-audit@example.com", Name = "Original", AccountState = UserAccountState.Active };
        await repo.CreateUserAsync(nonAuditUser);
        await repo.UpdateUserAsync(nonAuditUser with { Name = "Updated" });
        var fetchedNonAudit = await repo.GetUserByIdAsync(nonAuditUser.Id);

        var minimalUser = new MinimalUser
        {
            Id = Guid.NewGuid(),
            DisplayEmail = "minimal@example.com",
            Name = "Original",
            AccountState = UserAccountState.Active
        };
        await repo.CreateUserAsync(minimalUser);
        await repo.UpdateUserAsync(new MinimalUser
        {
            Id = minimalUser.Id,
            DisplayEmail = minimalUser.DisplayEmail,
            Name = "Updated",
            AccountState = UserAccountState.Active
        });
        var fetchedMinimal = await repo.GetUserByIdAsync(minimalUser.Id);

        var missingAuditUser = new AshlarSqliteUser
        {
            Id = Guid.NewGuid(),
            DisplayEmail = "missing-update@example.com",
            AccountState = UserAccountState.Active,
            CreatedAt = DateTimeOffset.UtcNow
        };
        await repo.UpdateUserAsync(missingAuditUser);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetchedAudit?.Name, Is.EqualTo("Updated"));
            Assert.That(auditUser.UpdatedAt, Is.Not.Null);
            Assert.That(fetchedNonAudit?.Name, Is.EqualTo("Updated"));
            Assert.That(fetchedMinimal?.Name, Is.EqualTo("Updated"));
            Assert.That(missingAuditUser.UpdatedAt, Is.Null);
            Assert.ThrowsAsync<ArgumentNullException>(async () => await repo.UpdateUserAsync(null!));
            Assert.ThrowsAsync<ArgumentException>(async () => await repo.UpdateUserAsync(new AshlarUser { Id = Guid.NewGuid(), DisplayEmail = "", AccountState = UserAccountState.Active }));
        }
    }

    [Test]
    public async Task DuplicateEmailUniquenessSeparatesNullTenantAndTenantScopedUsers()
    {
        await using var scope = _serviceProvider.CreateAsyncScope();
        var repo = GetRepository(scope.ServiceProvider);
        var tenantId = Guid.NewGuid();

        await repo.CreateUserAsync(new AshlarUser { Id = Guid.NewGuid(), DisplayEmail = "dupe@example.com", AccountState = UserAccountState.Active });
        await repo.CreateUserAsync(new AshlarUser { Id = Guid.NewGuid(), DisplayEmail = "dupe@example.com", AccountState = UserAccountState.Active, TenantId = tenantId });

        Assert.ThrowsAsync<SqliteException>(async () =>
            await repo.CreateUserAsync(new AshlarUser { Id = Guid.NewGuid(), DisplayEmail = "DUPE@example.com", AccountState = UserAccountState.Active }));
        Assert.ThrowsAsync<SqliteException>(async () =>
            await repo.CreateUserAsync(new AshlarUser { Id = Guid.NewGuid(), DisplayEmail = "DUPE@example.com", AccountState = UserAccountState.Active, TenantId = tenantId }));
    }

    [Test]
    public async Task ProviderKeyLookupAndCredentialReadShouldWork()
    {
        await using var scope = _serviceProvider.CreateAsyncScope();
        var repo = GetRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(repo);
        var credential = CreateCredential(user.Id, ProviderType.OAuth, "github", "gh-1");
        credential.CredentialValue = "secret";
        credential.ExpiresAt = DateTimeOffset.UtcNow.AddHours(1);

        await repo.CreateCredentialAsync(credential);

        var fetchedUser = await repo.GetUserByProviderKeyAsync(ProviderType.OAuth, "github", "gh-1");
        var fetchedCredential = await repo.GetCredentialForUserAsync(user.Id, ProviderType.OAuth, "github", "gh-1");
        var wrongUserCredential = await repo.GetCredentialForUserAsync(Guid.NewGuid(), ProviderType.OAuth, "github", "gh-1");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetchedUser?.Id, Is.EqualTo(user.Id));
            Assert.That(fetchedCredential?.Id, Is.EqualTo(credential.Id));
            Assert.That(fetchedCredential?.CredentialValue, Is.EqualTo("secret"));
            Assert.That(wrongUserCredential, Is.Null);
        }
    }

    [Test]
    public async Task CredentialUniquenessCreateOrReplaceUpdateConsumeRevokeAndSecretOmissionShouldWork()
    {
        await using var scope = _serviceProvider.CreateAsyncScope();
        var repo = GetRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(repo);
        var otherUser = await CreateUserAsync(repo);
        var original = CreateCredential(user.Id, ProviderType.EmailCode, ProviderType.EmailCode.Value, "shared-key");
        original.CredentialValue = "first";
        original.LastUsedAt = DateTimeOffset.UtcNow.AddMinutes(-5);
        var replacement = CreateCredential(user.Id, ProviderType.EmailCode, ProviderType.EmailCode.Value, "shared-key");
        replacement.CredentialValue = "second";
        replacement.Metadata = "{}";
        replacement.ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5);

        await repo.CreateOrReplaceCredentialAsync(original);
        await repo.CreateOrReplaceCredentialAsync(replacement);
        var fetched = await repo.GetCredentialForUserAsync(user.Id, ProviderType.EmailCode, ProviderType.EmailCode.Value, "shared-key");
        Assert.That(fetched, Is.Not.Null);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched.Id, Is.EqualTo(original.Id));
            Assert.That(fetched.CredentialValue, Is.EqualTo("second"));
            Assert.That(fetched.Metadata, Is.EqualTo("{}"));
            Assert.That(fetched.LastUsedAt, Is.EqualTo(original.LastUsedAt));
        }

        var moved = CreateCredential(otherUser.Id, ProviderType.EmailCode, ProviderType.EmailCode.Value, "shared-key");
        Assert.ThrowsAsync<CredentialProviderKeyConflictException>(async () => await repo.CreateOrReplaceCredentialAsync(moved));
        Assert.ThrowsAsync<SqliteException>(async () => await repo.CreateCredentialAsync(CreateCredential(user.Id, ProviderType.EmailCode, ProviderType.EmailCode.Value, "shared-key")));

        var staleVersion = fetched.Version;
        fetched.CredentialValue = "updated";
        Assert.That(await repo.UpdateCredentialAsync(fetched, staleVersion), Is.True);
        Assert.That(await repo.UpdateCredentialAsync(fetched, staleVersion), Is.False);

        var listed = await repo.ListCredentialsForUserAsync(user.Id);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(listed, Has.Count.EqualTo(1));
            Assert.That(listed[0].CredentialValue, Is.Null);
        }

        Assert.That(await repo.ConsumeCredentialAsync(fetched.Id, fetched.Version), Is.True);
        Assert.That(await repo.ConsumeCredentialAsync(fetched.Id, fetched.Version), Is.False);

        var revoke1 = CreateCredential(user.Id, ProviderType.MagicLink, ProviderType.MagicLink.Value);
        var revoke2 = CreateCredential(user.Id, ProviderType.MagicLink, ProviderType.MagicLink.Value);
        var expired = CreateCredential(user.Id, ProviderType.Local, ProviderType.Local.Value);
        expired.ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1);
        await repo.CreateCredentialAsync(revoke1);
        await repo.CreateCredentialAsync(revoke2);
        await repo.CreateCredentialAsync(expired);

        using (Assert.EnterMultipleScope())
        {
            Assert.That((await repo.GetCredentialForUserAsync(user.Id, ProviderType.Local, ProviderType.Local.Value, expired.ProviderKey))?.IsAvailable(DateTimeOffset.UtcNow), Is.False);
            Assert.That(await repo.RevokeCredentialsAsync(user.Id, ProviderType.MagicLink, ProviderType.MagicLink.Value), Is.EqualTo(2));
            Assert.That(await repo.GetCredentialForUserAsync(user.Id, ProviderType.MagicLink, ProviderType.MagicLink.Value, revoke1.ProviderKey), Is.Null);
            Assert.That(await repo.ListCredentialsForUserAsync(user.Id, activeOnly: false), Has.Count.EqualTo(3));
        }
    }

    [Test]
    public async Task UserAndCredentialWritesRollBackWithTransaction()
    {
        Guid userId;
        await using (var scope = _serviceProvider.CreateAsyncScope())
        {
            var repo = GetRepository(scope.ServiceProvider);
            var transactions = scope.ServiceProvider.GetRequiredService<IAshlarTransactionProvider>();
            userId = Guid.NewGuid();

            await using var transaction = await transactions.BeginTransactionAsync();
            await repo.CreateUserAsync(new AshlarUser { Id = userId, DisplayEmail = "rolled-back@example.com", AccountState = UserAccountState.Active });
            await repo.CreateCredentialAsync(CreateCredential(userId, ProviderType.Local, ProviderType.Local.Value));
            await transaction.RollbackAsync();
        }

        await using var verificationScope = _serviceProvider.CreateAsyncScope();
        var verificationRepo = GetRepository(verificationScope.ServiceProvider);
        Assert.That(await verificationRepo.GetUserByIdAsync(userId), Is.Null);
    }

    private static RepositoryFacade GetRepository(IServiceProvider serviceProvider)
    {
        return new RepositoryFacade(
            serviceProvider.GetRequiredService<IUserRepository>(),
            serviceProvider.GetRequiredService<ICredentialRepository>());
    }

    private static async Task<AshlarUser> CreateUserAsync(RepositoryFacade repo)
    {
        var user = new AshlarUser
        {
            Id = Guid.NewGuid(),
            DisplayEmail = $"{Guid.NewGuid():N}@example.com",
            AccountState = UserAccountState.Active
        };

        await repo.CreateUserAsync(user);
        return user;
    }

    private static UserCredential CreateCredential(Guid userId, ProviderType providerType, string providerName, string? providerKey = null)
    {
        return new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = providerType,
            ProviderName = providerName,
            ProviderKey = providerKey ?? $"{providerName}-{Guid.NewGuid():N}",
            Version = Guid.NewGuid().ToString("N"),
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active
        };
    }

    private sealed class RepositoryFacade(IUserRepository users, ICredentialRepository credentials) : IUserRepository, ICredentialRepository
    {
        public Task AcquireUserMutationLockAsync(Guid userId, CancellationToken cancellationToken = default) => credentials.AcquireUserMutationLockAsync(userId, cancellationToken);
        public Task<IUser?> GetUserByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default) => users.GetUserByEmailAsync(email, tenantId, cancellationToken);
        public Task<IUser?> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken = default) => users.GetUserByIdAsync(userId, cancellationToken);
        public Task<IUser?> GetUserByProviderKeyAsync(ProviderType type, string providerName, string providerKey, CancellationToken cancellationToken = default) => users.GetUserByProviderKeyAsync(type, providerName, providerKey, cancellationToken);
        public Task CreateUserAsync(IUser user, CancellationToken cancellationToken = default) => users.CreateUserAsync(user, cancellationToken);
        public Task UpdateUserAsync(IUser user, CancellationToken cancellationToken = default) => users.UpdateUserAsync(user, cancellationToken);
        public Task<UserCredential?> GetCredentialForUserAsync(Guid userId, ProviderType type, string providerName, string? providerKey = null, CancellationToken cancellationToken = default) => credentials.GetCredentialForUserAsync(userId, type, providerName, providerKey, cancellationToken);
        public Task<IReadOnlyList<UserCredential>> ListCredentialsForUserAsync(Guid userId, bool activeOnly = true, CancellationToken cancellationToken = default) => credentials.ListCredentialsForUserAsync(userId, activeOnly, cancellationToken);
        public Task CreateCredentialAsync(UserCredential credential, CancellationToken cancellationToken = default) => credentials.CreateCredentialAsync(credential, cancellationToken);
        public Task CreateOrReplaceCredentialAsync(UserCredential credential, CancellationToken cancellationToken = default) => credentials.CreateOrReplaceCredentialAsync(credential, cancellationToken);
        public Task<bool> UpdateCredentialAsync(UserCredential credential, string expectedVersion, CancellationToken cancellationToken = default) => credentials.UpdateCredentialAsync(credential, expectedVersion, cancellationToken);
        public Task<bool> ConsumeCredentialAsync(Guid credentialId, string expectedVersion, CancellationToken cancellationToken = default) => credentials.ConsumeCredentialAsync(credentialId, expectedVersion, cancellationToken);
        public Task<int> RevokeCredentialsAsync(Guid userId, ProviderType type, string providerName, CancellationToken cancellationToken = default) => credentials.RevokeCredentialsAsync(userId, type, providerName, cancellationToken);
    }

    private sealed class MinimalUser : IUser
    {
        public Guid Id { get; init; }
        public required string DisplayEmail { get; init; }
        public string? Name { get; init; }
        public UserAccountState AccountState { get; init; } = UserAccountState.Active;
        public DateTimeOffset? EmailVerifiedAt { get; init; }
    }
}
