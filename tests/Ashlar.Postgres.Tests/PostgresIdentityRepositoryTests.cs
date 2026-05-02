using Ashlar.Identity.Models;
using Ashlar.Postgres.Models;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Ashlar.Postgres.Tests;

public sealed class PostgresIdentityRepositoryTests
{
    private readonly PostgreSqlContainer _postgresContainer = new PostgreSqlBuilder()
        .WithImage("postgres:15-alpine")
        .Build();

    private IServiceProvider _serviceProvider;
    private NpgsqlDataSource _dataSource;

    [OneTimeSetUp]
    public async Task OneTimeSetUp()
    {
        await _postgresContainer.StartAsync();

        var services = new ServiceCollection();
        services.AddAshlarPostgres(_postgresContainer.GetConnectionString());
        _serviceProvider = services.BuildServiceProvider();
        _dataSource = _serviceProvider.GetRequiredService<NpgsqlDataSource>();

        await _serviceProvider.InitializeAshlarPostgresSchemaAsync();
    }

    [OneTimeTearDown]
    public async Task OneTimeTearDown()
    {
        await _dataSource.DisposeAsync();

        if (_serviceProvider is IAsyncDisposable asyncDisposable)
        {
            await asyncDisposable.DisposeAsync();
        }
        else if (_serviceProvider is IDisposable disposable)
        {
            disposable.Dispose();
        }

        await _postgresContainer.DisposeAsync();
    }

    private PostgresIdentityRepository GetRepository() => (PostgresIdentityRepository)_serviceProvider.GetRequiredService<Identity.Abstractions.IIdentityRepository>();

    [Test]
    public async Task CreateAndFetchUserShouldSucceed()
    {
        var repo = GetRepository();
        var user = new AshlarPostgresUser
        {
            Id = Guid.NewGuid(),
            Email = "test@example.com",
            Name = "Test User",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };

        await repo.CreateUserAsync(user);

        var fetchedById = await repo.GetUserByIdAsync(user.Id);
        var fetchedByEmail = await repo.GetUserByEmailAsync(user.Email);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetchedById, Is.Not.Null);
            Assert.That(fetchedByEmail, Is.Not.Null);
        }

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetchedById.Email, Is.EqualTo(user.Email));
            Assert.That(fetchedByEmail.Id, Is.EqualTo(user.Id));
        }
    }

    [Test]
    public async Task GetUserByEmailShouldBeCaseInsensitive()
    {
        var repo = GetRepository();
        var user = new AshlarPostgresUser
        {
            Id = Guid.NewGuid(),
            Email = "MixedCase@Example.Com",
            IsActive = true,
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
            Email = email,
            TenantId = tenant1,
            CreatedAt = DateTimeOffset.UtcNow
        };

        var user2 = new AshlarPostgresUser
        {
            Id = Guid.NewGuid(),
            Email = email,
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

    private static async Task<AshlarPostgresUser> CreateTestUser(PostgresIdentityRepository repo)
    {
        var user = new AshlarPostgresUser
        {
            Id = Guid.NewGuid(),
            Email = $"{Guid.NewGuid()}@example.com",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };
        await repo.CreateUserAsync(user);
        return user;
    }
}
