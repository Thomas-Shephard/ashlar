using Ashlar.Sqlite.Models;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Sqlite.Tests.Identity;

internal sealed class SqliteIdentityRepositoryTests : SqliteTestBase
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
        Assert.Throws<ArgumentNullException>(() => _ = new SqliteIdentityRepository(null!));
    }

    [Test]
    public void ConstructorAcceptsExplicitTimeProvider()
    {
        var provider = _serviceProvider.GetRequiredService<ISqliteConnectionProvider>();

        using (Assert.EnterMultipleScope())
        {
            Assert.DoesNotThrow(() => _ = new SqliteIdentityRepository(provider, new FakeTimeProvider()));
            Assert.DoesNotThrow(() => _ = new SqliteIdentityRepository(provider, null));
        }
    }

    [Test]
    public async Task UserCreateFetchEmailLookupAndTenantIsolationShouldWork()
    {
        await using var scope = _serviceProvider.CreateAsyncScope();
        var repo = scope.ServiceProvider.GetRequiredService<IIdentityRepository>();
        var tenant1 = Guid.NewGuid();
        var tenant2 = Guid.NewGuid();
        var email = "MixedCase@Example.Com";
        var noTenant = new AshlarUser { Id = Guid.NewGuid(), Email = email, Name = "No Tenant", IsActive = false };
        var user1 = new AshlarUser { Id = Guid.NewGuid(), Email = email, Name = "Tenant 1", IsActive = true, TenantId = tenant1 };
        var user2 = new AshlarUser { Id = Guid.NewGuid(), Email = email, Name = "Tenant 2", IsActive = true, TenantId = tenant2 };

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
            Assert.That(fetchedNoTenant?.IsActive, Is.False);
            Assert.That(fetchedTenant1?.Id, Is.EqualTo(user1.Id));
            Assert.That(fetchedTenant2?.Id, Is.EqualTo(user2.Id));
        }
    }

    [Test]
    public async Task MissingLookupsReturnNull()
    {
        await using var scope = _serviceProvider.CreateAsyncScope();
        var repo = scope.ServiceProvider.GetRequiredService<IIdentityRepository>();

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
        var repo = scope.ServiceProvider.GetRequiredService<IIdentityRepository>();
        var auditUser = new AshlarSqliteUser
        {
            Id = Guid.NewGuid(),
            Email = "audit@example.com",
            Name = "Original",
            IsActive = true,
            CreatedAt = new DateTimeOffset(2026, 5, 1, 0, 0, 0, TimeSpan.Zero)
        };
        await repo.CreateUserAsync(auditUser);

        auditUser.Name = "Updated";
        await repo.UpdateUserAsync(auditUser);
        var fetchedAudit = await repo.GetUserByIdAsync(auditUser.Id);

        var nonAuditUser = new AshlarUser { Id = Guid.NewGuid(), Email = "non-audit@example.com", Name = "Original", IsActive = true };
        await repo.CreateUserAsync(nonAuditUser);
        await repo.UpdateUserAsync(nonAuditUser with { Name = "Updated" });
        var fetchedNonAudit = await repo.GetUserByIdAsync(nonAuditUser.Id);

        var minimalUser = new MinimalUser
        {
            Id = Guid.NewGuid(),
            Email = "minimal@example.com",
            Name = "Original",
            IsActive = true
        };
        await repo.CreateUserAsync(minimalUser);
        await repo.UpdateUserAsync(new MinimalUser
        {
            Id = minimalUser.Id,
            Email = minimalUser.Email,
            Name = "Updated",
            IsActive = true
        });
        var fetchedMinimal = await repo.GetUserByIdAsync(minimalUser.Id);

        var missingAuditUser = new AshlarSqliteUser
        {
            Id = Guid.NewGuid(),
            Email = "missing-update@example.com",
            IsActive = true,
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
            Assert.ThrowsAsync<ArgumentException>(async () => await repo.UpdateUserAsync(new AshlarUser { Id = Guid.NewGuid(), Email = "", IsActive = true }));
        }
    }

    [Test]
    public async Task DuplicateEmailUniquenessSeparatesNullTenantAndTenantScopedUsers()
    {
        await using var scope = _serviceProvider.CreateAsyncScope();
        var repo = scope.ServiceProvider.GetRequiredService<IIdentityRepository>();
        var tenantId = Guid.NewGuid();

        await repo.CreateUserAsync(new AshlarUser { Id = Guid.NewGuid(), Email = "dupe@example.com", IsActive = true });
        await repo.CreateUserAsync(new AshlarUser { Id = Guid.NewGuid(), Email = "dupe@example.com", IsActive = true, TenantId = tenantId });

        Assert.ThrowsAsync<SqliteException>(async () =>
            await repo.CreateUserAsync(new AshlarUser { Id = Guid.NewGuid(), Email = "DUPE@example.com", IsActive = true }));
        Assert.ThrowsAsync<SqliteException>(async () =>
            await repo.CreateUserAsync(new AshlarUser { Id = Guid.NewGuid(), Email = "DUPE@example.com", IsActive = true, TenantId = tenantId }));
    }

    [Test]
    public async Task ProviderKeyLookupAndCredentialReadShouldWork()
    {
        await using var scope = _serviceProvider.CreateAsyncScope();
        var repo = scope.ServiceProvider.GetRequiredService<IIdentityRepository>();
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
        var repo = scope.ServiceProvider.GetRequiredService<IIdentityRepository>();
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
        Assert.ThrowsAsync<InvalidOperationException>(async () => await repo.CreateOrReplaceCredentialAsync(moved));
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
            var repo = scope.ServiceProvider.GetRequiredService<IIdentityRepository>();
            var transactions = scope.ServiceProvider.GetRequiredService<IAshlarTransactionProvider>();
            userId = Guid.NewGuid();

            await using var transaction = await transactions.BeginTransactionAsync();
            await repo.CreateUserAsync(new AshlarUser { Id = userId, Email = "rolled-back@example.com", IsActive = true });
            await repo.CreateCredentialAsync(CreateCredential(userId, ProviderType.Local, ProviderType.Local.Value));
            await transaction.RollbackAsync();
        }

        await using var verificationScope = _serviceProvider.CreateAsyncScope();
        var verificationRepo = verificationScope.ServiceProvider.GetRequiredService<IIdentityRepository>();
        Assert.That(await verificationRepo.GetUserByIdAsync(userId), Is.Null);
    }

    private static async Task<AshlarUser> CreateUserAsync(IIdentityRepository repo)
    {
        var user = new AshlarUser
        {
            Id = Guid.NewGuid(),
            Email = $"{Guid.NewGuid():N}@example.com",
            IsActive = true
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

    private sealed class MinimalUser : IUser
    {
        public Guid Id { get; init; }
        public required string Email { get; init; }
        public string? Name { get; init; }
        public bool IsActive { get; init; }
        public DateTimeOffset? EmailVerifiedAt { get; init; }
    }
}
