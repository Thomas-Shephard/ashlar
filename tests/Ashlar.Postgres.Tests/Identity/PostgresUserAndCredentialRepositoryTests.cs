using Ashlar.Postgres.Models;
using Dapper;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Ashlar.Postgres.Tests.Identity;

internal sealed class PostgresUserAndCredentialRepositoryTests : PostgresTestBase
{
    private IServiceProvider? _serviceProvider;

    public override async Task OneTimeSetUp()
    {
        await base.OneTimeSetUp();

        var services = new ServiceCollection();
        services.AddAshlarPostgres(GetConnectionString());
        services.AddPostgresProviderContractTestServices();
        _serviceProvider = services.BuildServiceProvider();

        await _serviceProvider.InitializeAshlarPostgresSchemaAsync();
    }

    [OneTimeTearDown]
    public async Task OneTimeTearDownAsync()
    {
        if (_serviceProvider is IAsyncDisposable asyncDisposable)
        {
            await asyncDisposable.DisposeAsync();
        }
        else if (_serviceProvider is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }

    private RepositoryFacade GetRepository()
    {
        return new RepositoryFacade(
            _serviceProvider!.GetRequiredService<IUserRepository>(),
            _serviceProvider!.GetRequiredService<ICredentialRepository>());
    }

    [Test]
    public void ConstructorNullDataSourceShouldThrow()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new PostgresUserRepository(null!));
        Assert.Throws<ArgumentNullException>(() => _ = new PostgresCredentialRepository(null!));
    }

    [Test]
    public void ConstructorWithCustomTimeProviderShouldSucceed()
    {
        var connectionProvider = new PostgresTransactionManager(GetDataSource());

        Assert.DoesNotThrow(() => _ = new PostgresCredentialRepository(connectionProvider, TimeProvider.System));
    }

    [Test]
    public void ConstructorWithoutCustomTimeProviderShouldSucceed()
    {
        var connectionProvider = new PostgresTransactionManager(GetDataSource());

        Assert.DoesNotThrow(() => _ = new PostgresCredentialRepository(connectionProvider));
    }

    [Test]
    public void AuthenticationContextPropertiesShouldWork()
    {
        var tenantId = Guid.NewGuid();
        var items = new Dictionary<string, string> { ["provider"] = "local" };
        var context = new AuthenticationContext(
            "test@example.com",
            tenantId,
            "127.0.0.1",
            "test-agent",
            "correlation-id",
            "/return",
            items);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(context.Email, Is.EqualTo("test@example.com"));
            Assert.That(context.TenantId, Is.EqualTo(tenantId));
            Assert.That(context.IpAddress, Is.EqualTo("127.0.0.1"));
            Assert.That(context.UserAgent, Is.EqualTo("test-agent"));
            Assert.That(context.CorrelationId, Is.EqualTo("correlation-id"));
            Assert.That(context.ReturnUrl, Is.EqualTo("/return"));
            Assert.That(context.Items, Is.EqualTo(items));
        }
    }

    [Test]
    public async Task CreateAndFetchUserShouldSucceed()
    {
        var repo = GetRepository();
        var user = new AshlarPostgresUser
        {
            Id = Guid.NewGuid(),
            DisplayEmail = "test@example.com",
            Name = "Test User",
            AccountState = UserAccountState.Active,
            CreatedAt = DateTimeOffset.UtcNow
        };

        await repo.CreateUserAsync(user);

        var fetchedById = await repo.GetUserByIdAsync(user.Id);
        var fetchedByEmail = await repo.GetUserByEmailAsync(user.DisplayEmail);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetchedById, Is.Not.Null);
            Assert.That(fetchedByEmail, Is.Not.Null);
        }

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetchedById.DisplayEmail, Is.EqualTo(user.DisplayEmail));
            Assert.That(fetchedByEmail.Id, Is.EqualTo(user.Id));
        }
    }

    [Test]
    public async Task CreateUserWithExistingCreatedAtShouldPreserveValue()
    {
        var repo = GetRepository();
        var specificTime = new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var user = new AshlarPostgresUser
        {
            Id = Guid.NewGuid(),
            DisplayEmail = "preserved@example.com",
            CreatedAt = specificTime
        };

        await repo.CreateUserAsync(user);
        var fetched = (AshlarPostgresUser?)await repo.GetUserByIdAsync(user.Id);

        Assert.That(fetched, Is.Not.Null);
        Assert.That(fetched.CreatedAt, Is.EqualTo(specificTime));
    }

    [Test]
    public async Task GetUserByEmailShouldBeCaseInsensitive()
    {
        var repo = GetRepository();
        var user = new AshlarPostgresUser
        {
            Id = Guid.NewGuid(),
            DisplayEmail = "MixedCase@Example.Com",
            AccountState = UserAccountState.Active,
            CreatedAt = DateTimeOffset.UtcNow
        };

        await repo.CreateUserAsync(user);

        var fetched = await repo.GetUserByEmailAsync("mixedcase@example.com");

        Assert.That(fetched, Is.Not.Null);
        Assert.That(fetched.Id, Is.EqualTo(user.Id));
    }

    [Test]
    public async Task TenantAwareLookupShouldSucceed()
    {
        var repo = GetRepository();
        var tenant1 = Guid.NewGuid();
        var tenant2 = Guid.NewGuid();
        var email = "tenant@example.com";

        var user1 = new AshlarPostgresUser
        {
            Id = Guid.NewGuid(),
            DisplayEmail = email,
            TenantId = tenant1,
            CreatedAt = DateTimeOffset.UtcNow
        };

        var user2 = new AshlarPostgresUser
        {
            Id = Guid.NewGuid(),
            DisplayEmail = email,
            TenantId = tenant2,
            CreatedAt = DateTimeOffset.UtcNow
        };

        await repo.CreateUserAsync(user1);
        await repo.CreateUserAsync(user2);

        var fetched1 = await repo.GetUserByEmailAsync(email, tenant1);
        var fetched2 = await repo.GetUserByEmailAsync(email, tenant2);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched1, Is.Not.Null);
            Assert.That(fetched2, Is.Not.Null);
        }

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched1.Id, Is.EqualTo(user1.Id));
            Assert.That(fetched2.Id, Is.EqualTo(user2.Id));
        }
    }

    [Test]
    public async Task CreateAndFetchCredentialShouldSucceed()
    {
        var repo = GetRepository();
        var user = await CreateTestUser(repo);

        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Local,
            ProviderName = "LOCAL",
            ProviderKey = user.Id.ToString("D"),
            Version = Guid.NewGuid().ToString(),
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active
        };

        await repo.CreateCredentialAsync(credential);

        var fetched = await repo.GetCredentialForUserAsync(user.Id, ProviderType.Local, "LOCAL", user.Id.ToString("D"));
        var fetchedWithNullKey = await repo.GetCredentialForUserAsync(user.Id, ProviderType.Local, "LOCAL");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched, Is.Not.Null);
            Assert.That(fetchedWithNullKey, Is.Not.Null);
        }

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched.Id, Is.EqualTo(credential.Id));
            Assert.That(fetchedWithNullKey.Id, Is.EqualTo(credential.Id));
            Assert.That(fetched.ProviderType, Is.EqualTo(credential.ProviderType));
        }
    }

    [Test]
    public async Task GetCredentialForUserShouldNotReturnCredentialOfAnotherUser()
    {
        var repo = GetRepository();
        var user1 = await CreateTestUser(repo);
        var user2 = await CreateTestUser(repo);

        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user1.Id,
            ProviderType = ProviderType.Local,
            ProviderName = "LOCAL",
            ProviderKey = user1.Id.ToString("D"),
            Version = Guid.NewGuid().ToString(),
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active
        };

        await repo.CreateCredentialAsync(credential);

        var fetched = await repo.GetCredentialForUserAsync(user2.Id, ProviderType.Local, "LOCAL", user1.Id.ToString("D"));

        Assert.That(fetched, Is.Null);
    }

    [Test]
    public async Task GetUserByProviderKeyShouldSucceed()
    {
        var repo = GetRepository();
        var user = await CreateTestUser(repo);

        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.OAuth,
            ProviderName = "google",
            ProviderKey = "google-id-123",
            Version = Guid.NewGuid().ToString(),
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active
        };

        await repo.CreateCredentialAsync(credential);

        var fetchedUser = await repo.GetUserByProviderKeyAsync(ProviderType.OAuth, "google", "google-id-123");

        Assert.That(fetchedUser, Is.Not.Null);
        Assert.That(fetchedUser.Id, Is.EqualTo(user.Id));
    }

    [Test]
    public async Task UpdateCredentialAtomicShouldSucceedWithCorrectVersion()
    {
        var repo = GetRepository();
        var user = await CreateTestUser(repo);
        var version = Guid.NewGuid().ToString();
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Local,
            ProviderName = "LOCAL",
            ProviderKey = user.Id.ToString("D"),
            Version = version,
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active
        };

        await repo.CreateCredentialAsync(credential);

        credential.CredentialValue = "new-hash";
        var result = await repo.UpdateCredentialAsync(credential, version);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(result, Is.True);
            Assert.That(credential.Version, Is.Not.EqualTo(version));
        }

        var fetched = await repo.GetCredentialForUserAsync(user.Id, ProviderType.Local, "LOCAL", user.Id.ToString("D"));
        Assert.That(fetched, Is.Not.Null);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched.CredentialValue, Is.EqualTo("new-hash"));
            Assert.That(fetched.Version, Is.EqualTo(credential.Version));
        }
    }

    [Test]
    public async Task UpdateCredentialAtomicShouldFailWithStaleVersion()
    {
        var repo = GetRepository();
        var user = await CreateTestUser(repo);
        var version = Guid.NewGuid().ToString();
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Local,
            ProviderName = "LOCAL",
            ProviderKey = user.Id.ToString("D"),
            Version = version,
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active
        };

        await repo.CreateCredentialAsync(credential);

        var result = await repo.UpdateCredentialAsync(credential, "stale-version");

        Assert.That(result, Is.False);
    }

    [Test]
    public async Task ConsumeCredentialAtomicShouldSucceedAndRemoveRow()
    {
        var repo = GetRepository();
        var user = await CreateTestUser(repo);
        var version = Guid.NewGuid().ToString();
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Local,
            ProviderName = "otp",
            ProviderKey = "123456",
            Version = version,
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active
        };

        await repo.CreateCredentialAsync(credential);

        var result = await repo.ConsumeCredentialAsync(credential.Id, version);

        Assert.That(result, Is.True);

        var fetched = await repo.GetCredentialForUserAsync(user.Id, ProviderType.Local, "otp", "123456");
        Assert.That(fetched, Is.Null);
    }

    [Test]
    public async Task RevokeCredentialsShouldUpdateMatchingActiveCredentialsOnly()
    {
        var repo = GetRepository();
        var user = await CreateTestUser(repo);
        var otherUser = await CreateTestUser(repo);
        var matchingCredential1 = CreateCredential(user.Id, ProviderType.MagicLink, ProviderType.MagicLink.Value);
        var matchingCredential2 = CreateCredential(user.Id, ProviderType.MagicLink, ProviderType.MagicLink.Value);
        var otherProviderCredential = CreateCredential(user.Id, ProviderType.EmailCode, ProviderType.EmailCode.Value);
        var otherUserCredential = CreateCredential(otherUser.Id, ProviderType.MagicLink, ProviderType.MagicLink.Value);

        await repo.CreateCredentialAsync(matchingCredential1);
        await repo.CreateCredentialAsync(matchingCredential2);
        await repo.CreateCredentialAsync(otherProviderCredential);
        await repo.CreateCredentialAsync(otherUserCredential);

        await repo.RevokeCredentialsAsync(user.Id, ProviderType.MagicLink, ProviderType.MagicLink.Value);

        var fetchedMatching1 = await repo.GetCredentialForUserAsync(user.Id, ProviderType.MagicLink, ProviderType.MagicLink.Value, matchingCredential1.ProviderKey);
        var fetchedMatching2 = await repo.GetCredentialForUserAsync(user.Id, ProviderType.MagicLink, ProviderType.MagicLink.Value, matchingCredential2.ProviderKey);
        var fetchedOtherProvider = await repo.GetCredentialForUserAsync(user.Id, ProviderType.EmailCode, ProviderType.EmailCode.Value, otherProviderCredential.ProviderKey);
        var fetchedOtherUser = await repo.GetCredentialForUserAsync(otherUser.Id, ProviderType.MagicLink, ProviderType.MagicLink.Value, otherUserCredential.ProviderKey);
        const string sql = """
            SELECT id AS Id, version AS Version, revoked_at AS RevokedAt, status AS Status
            FROM ashlar_credentials
            WHERE id = ANY(@Ids)
            """;
        var ids = new[] { matchingCredential1.Id, matchingCredential2.Id, otherProviderCredential.Id, otherUserCredential.Id };
        await using var connection = await GetDataSource().OpenConnectionAsync();
        var rows = (await connection.QueryAsync<CredentialRevocationRow>(sql, new { Ids = ids })).ToDictionary(row => row.Id);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetchedMatching1, Is.Null);
            Assert.That(fetchedMatching2, Is.Null);
            Assert.That(fetchedOtherProvider, Is.Not.Null);
            Assert.That(fetchedOtherUser, Is.Not.Null);

            Assert.That(rows[matchingCredential1.Id].Status, Is.EqualTo((int)CredentialStatus.Revoked));
            Assert.That(rows[matchingCredential1.Id].RevokedAt, Is.Not.Null);
            Assert.That(rows[matchingCredential1.Id].Version, Is.Not.EqualTo(matchingCredential1.Version));
            Assert.That(rows[matchingCredential2.Id].Status, Is.EqualTo((int)CredentialStatus.Revoked));
            Assert.That(rows[matchingCredential2.Id].RevokedAt, Is.Not.Null);
            Assert.That(rows[matchingCredential2.Id].Version, Is.Not.EqualTo(matchingCredential2.Version));

            Assert.That(rows[otherProviderCredential.Id].Status, Is.EqualTo((int)CredentialStatus.Active));
            Assert.That(rows[otherProviderCredential.Id].RevokedAt, Is.Null);
            Assert.That(rows[otherProviderCredential.Id].Version, Is.EqualTo(otherProviderCredential.Version));
            Assert.That(rows[otherUserCredential.Id].Status, Is.EqualTo((int)CredentialStatus.Active));
            Assert.That(rows[otherUserCredential.Id].RevokedAt, Is.Null);
            Assert.That(rows[otherUserCredential.Id].Version, Is.EqualTo(otherUserCredential.Version));
        }
    }

    [Test]
    public async Task ListCredentialsForUserShouldReturnActiveCredentialSummariesWithoutValues()
    {
        var repo = GetRepository();
        var user = await CreateTestUser(repo);
        var activeCredential = CreateCredential(user.Id, ProviderType.Local, ProviderType.Local.Value);
        activeCredential.CredentialValue = "secret-value";
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
    public void RevokeCredentialsInvalidProviderNameShouldThrow()
    {
        var repo = GetRepository();

        Assert.ThrowsAsync<ArgumentException>(async () => await repo.RevokeCredentialsAsync(Guid.NewGuid(), ProviderType.MagicLink, " "));
    }

    [Test]
    public async Task DuplicateCredentialIdentityShouldFail()
    {
        var repo = GetRepository();
        var user1 = await CreateTestUser(repo);
        var user2 = await CreateTestUser(repo);

        var credential1 = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user1.Id,
            ProviderType = ProviderType.OAuth,
            ProviderName = "github",
            ProviderKey = "gh-user-1",
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active
        };

        await repo.CreateCredentialAsync(credential1);

        var credential2 = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user2.Id,
            ProviderType = ProviderType.OAuth,
            ProviderName = "github",
            ProviderKey = "gh-user-1",
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active
        };

        Assert.ThrowsAsync<PostgresException>(async () => await repo.CreateCredentialAsync(credential2));
    }

    [Test]
    public async Task CreateOrReplaceCredentialShouldUpsertByProviderIdentity()
    {
        var repo = GetRepository();
        var user = await CreateTestUser(repo);
        var providerKey = user.Id.ToString("D");
        var lastUsedAt = new DateTimeOffset(2026, 5, 3, 12, 0, 0, TimeSpan.Zero);
        var originalCreatedAt = new DateTimeOffset(2026, 5, 3, 11, 0, 0, TimeSpan.Zero);
        var replacementCreatedAt = new DateTimeOffset(2026, 5, 3, 12, 30, 0, TimeSpan.Zero);
        var original = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.EmailCode,
            ProviderName = ProviderType.EmailCode.Value,
            ProviderKey = providerKey,
            Version = "v1",
            CredentialValue = "first",
            LastUsedAt = lastUsedAt,
            CreatedAt = originalCreatedAt,
            Status = CredentialStatus.Active,
            Purpose = "email-sign-in"
        };
        var originalLastUsedAt = original.LastUsedAt;

        var replacement = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.EmailCode,
            ProviderName = ProviderType.EmailCode.Value,
            ProviderKey = providerKey,
            Version = "v2",
            CredentialValue = "second",
            Metadata = "{}",
            LastUsedAt = null,
            CreatedAt = replacementCreatedAt,
            UpdatedAt = null,
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10),
            RevokedAt = null,
            Status = CredentialStatus.Active,
            Purpose = "email-sign-in"
        };

        await repo.CreateOrReplaceCredentialAsync(original);
        await repo.CreateOrReplaceCredentialAsync(replacement);

        var fetched = await repo.GetCredentialForUserAsync(user.Id, ProviderType.EmailCode, ProviderType.EmailCode.Value, providerKey);

        Assert.That(fetched, Is.Not.Null);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched.Id, Is.EqualTo(original.Id));
            Assert.That(fetched.Version, Is.EqualTo("v2"));
            Assert.That(fetched.CredentialValue, Is.EqualTo("second"));
            Assert.That(fetched.Metadata, Is.EqualTo("{}"));
            Assert.That(fetched.CreatedAt, Is.EqualTo(originalCreatedAt));
            Assert.That(fetched.LastUsedAt, Is.EqualTo(originalLastUsedAt));
            Assert.That(fetched.UpdatedAt, Is.Not.Null);
            Assert.That(fetched.Purpose, Is.EqualTo("email-sign-in"));
        }
    }

    [Test]
    public async Task CreateOrReplaceCredentialShouldNotMoveProviderKeyToAnotherUserOnConflict()
    {
        var repo = GetRepository();
        var user1 = await CreateTestUser(repo);
        var user2 = await CreateTestUser(repo);
        var providerKey = $"shared-{Guid.NewGuid():N}";
        var original = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user1.Id,
            ProviderType = ProviderType.EmailCode,
            ProviderName = ProviderType.EmailCode.Value,
            ProviderKey = providerKey,
            Version = "v1",
            CredentialValue = "first",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            Purpose = "email-sign-in"
        };

        var replacement = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user2.Id,
            ProviderType = ProviderType.EmailCode,
            ProviderName = ProviderType.EmailCode.Value,
            ProviderKey = providerKey,
            Version = "v2",
            CredentialValue = "second",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            Purpose = "email-sign-in"
        };

        await repo.CreateOrReplaceCredentialAsync(original);

        var exception = Assert.ThrowsAsync<CredentialProviderKeyConflictException>(async () => await repo.CreateOrReplaceCredentialAsync(replacement));

        var oldUserCredential = await repo.GetCredentialForUserAsync(user1.Id, ProviderType.EmailCode, ProviderType.EmailCode.Value, providerKey);
        var newUserCredential = await repo.GetCredentialForUserAsync(user2.Id, ProviderType.EmailCode, ProviderType.EmailCode.Value, providerKey);

        Assert.That(exception?.Message, Does.Contain("already linked"));
        using (Assert.EnterMultipleScope())
        {
            Assert.That(oldUserCredential, Is.Not.Null);
            Assert.That(newUserCredential, Is.Null);
        }

        using (Assert.EnterMultipleScope())
        {
            Assert.That(oldUserCredential.Id, Is.EqualTo(original.Id));
            Assert.That(oldUserCredential.UserId, Is.EqualTo(user1.Id));
            Assert.That(oldUserCredential.CredentialValue, Is.EqualTo("first"));
        }
    }

    [Test]
    public void CreateOrReplaceCredentialNullShouldThrow()
    {
        var repo = GetRepository();

        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(async () => await repo.CreateOrReplaceCredentialAsync(null!));
    }

    [Test]
    public async Task UpdateUserShouldSucceed()
    {
        var repo = GetRepository();
        var user = await CreateTestUser(repo);

        var updatedUser = new AshlarPostgresUser
        {
            Id = user.Id,
            DisplayEmail = user.DisplayEmail,
            Name = "Updated Name",
            AccountState = user.AccountState,
            TenantId = user.TenantId,
            CreatedAt = user.CreatedAt
        };

        await repo.UpdateUserAsync(updatedUser);

        var fetched = await repo.GetUserByIdAsync(user.Id);
        Assert.That(fetched, Is.Not.Null);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched.Name, Is.EqualTo("Updated Name"));
            Assert.That(updatedUser.UpdatedAt, Is.Not.Null);
        }
    }

    [Test]
    public void UpdateUserNullOrInvalidShouldThrow()
    {
        var repo = GetRepository();

        using (Assert.EnterMultipleScope())
        {
            // ReSharper disable once NullableWarningSuppressionIsUsed
            Assert.ThrowsAsync<ArgumentNullException>(async () => await repo.UpdateUserAsync(null!));
            Assert.ThrowsAsync<ArgumentException>(async () => await repo.UpdateUserAsync(new AshlarPostgresUser { Id = Guid.NewGuid(), DisplayEmail = "", CreatedAt = default }));
        }
    }

    [Test]
    public async Task UpdateUserNonExistentShouldReturnGracefully()
    {
        var repo = GetRepository();

        var user = new AshlarPostgresUser
        {
            Id = Guid.NewGuid(),
            DisplayEmail = "nonexistent@example.com",
            CreatedAt = DateTimeOffset.UtcNow
        };

        // Should not throw, and should not update UpdatedAt since rowsAffected == 0
        await repo.UpdateUserAsync(user);
        Assert.That(user.UpdatedAt, Is.Null);
    }

    [Test]
    public async Task UpdateUserNonAuditUserShouldStillSucceed()
    {
        var repo = GetRepository();

        var user = new MinimalUser
        {
            Id = Guid.NewGuid(),
            DisplayEmail = "minimal@example.com",
            AccountState = UserAccountState.Active,
            Name = "Original"
        };

        await repo.CreateUserAsync(user);

        var updatedUser = new MinimalUser
        {
            Id = user.Id,
            DisplayEmail = user.DisplayEmail,
            AccountState = user.AccountState,
            Name = "Updated"
        };

        await repo.UpdateUserAsync(updatedUser);

        var fetched = await repo.GetUserByIdAsync(user.Id);

        Assert.That(fetched, Is.Not.Null);
        Assert.That(fetched.Name, Is.EqualTo("Updated"));
    }

    private static async Task<AshlarPostgresUser> CreateTestUser(RepositoryFacade repo)
    {
        var user = new AshlarPostgresUser
        {
            Id = Guid.NewGuid(),
            DisplayEmail = $"{Guid.NewGuid()}@example.com",
            AccountState = UserAccountState.Active,
            CreatedAt = DateTimeOffset.UtcNow
        };
        await repo.CreateUserAsync(user);
        return user;
    }

    private static UserCredential CreateCredential(Guid userId, ProviderType providerType, string providerName)
    {
        return new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = providerType,
            ProviderName = providerName,
            ProviderKey = $"{providerName}-{Guid.NewGuid():N}",
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

    private sealed class CredentialRevocationRow
    {
        public Guid Id { get; init; }
        public string Version { get; init; } = "";
        public DateTime? RevokedAt { get; init; }
        public int Status { get; init; }
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
