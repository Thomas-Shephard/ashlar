using Ashlar.Postgres.Models;
using Microsoft.Extensions.DependencyInjection;
using Dapper;

namespace Ashlar.Postgres.Tests.Identity;

internal sealed class PostgresAuthenticationHandshakeRepositoryTests : PostgresTestBase
{
    private IServiceProvider _serviceProvider;

    public override async Task OneTimeSetUp()
    {
        await base.OneTimeSetUp();

        var services = new ServiceCollection();
        services.AddAshlarPostgres(GetConnectionString());
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

    [Test]
    public async Task CreateAndFetchHandshakeShouldMapAllFields()
    {
        var userRepository = GetUserRepository();
        var repository = GetRepository();
        var user = await CreateTestUser(userRepository);

        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            user.Id,
            "hashed:raw-token",
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddMinutes(15),
            false,
            false,
            new HashSet<string> { "totp", "email" },
            new HashSet<string> { "totp" },
            new Dictionary<string, string> { ["foo"] = "bar" }
        );

        await repository.CreateAsync(handshake);

        var fetched = await repository.FindByTokenHashAsync(handshake.TokenHash);

        Assert.That(fetched, Is.Not.Null);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched.Id, Is.EqualTo(handshake.Id));
            Assert.That(fetched.UserId, Is.EqualTo(handshake.UserId));
            Assert.That(fetched.TokenHash, Is.EqualTo(handshake.TokenHash));
            Assert.That(fetched.CreatedAt, Is.EqualTo(handshake.CreatedAt).Within(TimeSpan.FromSeconds(1)));
            Assert.That(fetched.ExpiresAt, Is.EqualTo(handshake.ExpiresAt).Within(TimeSpan.FromSeconds(1)));
            Assert.That(fetched.IsRevoked, Is.EqualTo(handshake.IsRevoked));
            Assert.That(fetched.IsCompleted, Is.EqualTo(handshake.IsCompleted));
            Assert.That(fetched.RequiredFactors, Is.EquivalentTo(handshake.RequiredFactors));
            Assert.That(fetched.VerifiedFactors, Is.EquivalentTo(handshake.VerifiedFactors));
            if (handshake.Metadata != null)
            {
                Assert.That(fetched.Metadata, Is.EquivalentTo(handshake.Metadata));
            }
            else
            {
                Assert.That(fetched.Metadata, Is.Null);
            }
        }
    }

    [Test]
    public async Task UpdateHandshakeShouldUpdateTargetFields()
    {
        var userRepository = GetUserRepository();
        var repository = GetRepository();
        var user = await CreateTestUser(userRepository);

        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            user.Id,
            "hashed:update",
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddMinutes(15),
            false,
            false,
            new HashSet<string> { "totp" },
            new HashSet<string>()
        );

        await repository.CreateAsync(handshake);

        var updatedHandshake = handshake with
        {
            IsRevoked = true,
            IsCompleted = true,
            RevokedAt = DateTimeOffset.UtcNow,
            CompletedAt = DateTimeOffset.UtcNow,
            VerifiedFactors = new HashSet<string> { "totp" },
            Metadata = new Dictionary<string, string> { ["updated"] = "true" }
        };

        var updateApplied = await repository.UpdateAsync(updatedHandshake);

        var fetched = await repository.FindByTokenHashAsync(handshake.TokenHash);

        Assert.That(fetched, Is.Not.Null);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(updateApplied, Is.True);
            Assert.That(fetched.IsRevoked, Is.True);
            Assert.That(fetched.IsCompleted, Is.True);
            Assert.That(fetched.RevokedAt, Is.Not.Null);
            Assert.That(fetched.CompletedAt, Is.Not.Null);
            Assert.That(fetched.VerifiedFactors, Is.EquivalentTo(updatedHandshake.VerifiedFactors));
            if (updatedHandshake.Metadata != null)
            {
                Assert.That(fetched.Metadata, Is.EquivalentTo(updatedHandshake.Metadata));
            }
            else
            {
                Assert.That(fetched.Metadata, Is.Null);
            }
        }
    }

    [Test]
    public async Task FindByTokenHashShouldReturnNullWhenNotFound()
    {
        var repository = GetRepository();
        var fetched = await repository.FindByTokenHashAsync("non-existent");
        Assert.That(fetched, Is.Null);
    }

    [Test]
    public async Task FindByTokenHashForUpdateShouldReturnHandshake()
    {
        var userRepository = GetUserRepository();
        var repository = GetRepository();
        var user = await CreateTestUser(userRepository);

        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            user.Id,
            "hashed:for-update",
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddMinutes(15),
            false,
            false,
            new HashSet<string> { "totp" },
            new HashSet<string>());

        await repository.CreateAsync(handshake);

        var fetched = await repository.FindByTokenHashAsync(handshake.TokenHash, forUpdate: true);

        Assert.That(fetched?.Id, Is.EqualTo(handshake.Id));
    }

    [Test]
    public void ConstructorNullConnectionProviderShouldThrow()
    {
        using (Assert.EnterMultipleScope())
        {
            // ReSharper disable once NullableWarningSuppressionIsUsed
            Assert.Throws<ArgumentNullException>(() => _ = new PostgresAuthenticationHandshakeRepository(null!));
            Assert.DoesNotThrow(() => _ = new PostgresAuthenticationHandshakeRepository(_serviceProvider.GetRequiredService<IPostgresConnectionProvider>(), null));
        }
    }

    [Test]
    public async Task CreateAndFetchHandshakeWithNullMetadataShouldWork()
    {
        var userRepository = GetUserRepository();
        var repository = GetRepository();
        var user = await CreateTestUser(userRepository);

        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            user.Id,
            "hashed:null-metadata",
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddMinutes(15),
            false,
            false,
            new HashSet<string> { "totp" },
            new HashSet<string>()
        );

        await repository.CreateAsync(handshake);

        var fetched = await repository.FindByTokenHashAsync(handshake.TokenHash);
        var metadataIsSqlNull = await IsHandshakeMetadataSqlNullAsync(handshake.Id);

        Assert.That(fetched, Is.Not.Null);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched.Metadata, Is.Null);
            Assert.That(metadataIsSqlNull, Is.True);
        }
    }

    [Test]
    public async Task UpdateHandshakeWithNullMetadataShouldStoreSqlNull()
    {
        var userRepository = GetUserRepository();
        var repository = GetRepository();
        var user = await CreateTestUser(userRepository);

        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            user.Id,
            "hashed:update-null-metadata",
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddMinutes(15),
            false,
            false,
            new HashSet<string> { "totp" },
            new HashSet<string>(),
            new Dictionary<string, string> { ["initial"] = "true" }
        );

        await repository.CreateAsync(handshake);

        var updatedHandshake = handshake with { Metadata = null };

        var updateApplied = await repository.UpdateAsync(updatedHandshake);

        var fetched = await repository.FindByTokenHashAsync(handshake.TokenHash);
        var metadataIsSqlNull = await IsHandshakeMetadataSqlNullAsync(handshake.Id);

        Assert.That(fetched, Is.Not.Null);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(updateApplied, Is.True);
            Assert.That(fetched.Metadata, Is.Null);
            Assert.That(metadataIsSqlNull, Is.True);
        }
    }

    [Test]
    public void CreateHandshakeNullShouldThrow()
    {
        var repository = GetRepository();
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(async () => await repository.CreateAsync(null!));
    }

    [Test]
    public void UpdateHandshakeNullShouldThrow()
    {
        var repository = GetRepository();
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(async () => await repository.UpdateAsync(null!));
    }

    [Test]
    public async Task FindByTokenHashShouldHandleNullJsonGracefully()
    {
        var userRepository = GetUserRepository();
        var repository = GetRepository();
        var user = await CreateTestUser(userRepository);
        var tokenHash = "hashed:null-json";

        // Manually insert a row with "null" JSON values
        var connectionProvider = _serviceProvider.GetRequiredService<IPostgresConnectionProvider>();
        var connectionHandle = await connectionProvider.GetConnectionAsync(CancellationToken.None);
        await using (connectionHandle)
        {
            await connectionHandle.Connection.ExecuteAsync(
                "INSERT INTO ashlar_mfa_handshakes (id, user_id, token_hash, created_at, expires_at, required_factors, verified_factors) VALUES (@Id, @UserId, @TokenHash, @Now, @Now, 'null'::jsonb, 'null'::jsonb)",
                new { Id = Guid.NewGuid(), UserId = user.Id, TokenHash = tokenHash, Now = DateTimeOffset.UtcNow },
                transaction: connectionHandle.Transaction);
        }

        var fetched = await repository.FindByTokenHashAsync(tokenHash);

        Assert.That(fetched, Is.Not.Null);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched.RequiredFactors, Is.Empty);
            Assert.That(fetched.VerifiedFactors, Is.Empty);
        }
    }

    private IAuthenticationHandshakeRepository GetRepository() => _serviceProvider.GetRequiredService<IAuthenticationHandshakeRepository>();
    private IUserRepository GetUserRepository() => _serviceProvider.GetRequiredService<IUserRepository>();

    private async Task<bool> IsHandshakeMetadataSqlNullAsync(Guid handshakeId)
    {
        var connectionProvider = _serviceProvider.GetRequiredService<IPostgresConnectionProvider>();
        var connectionHandle = await connectionProvider.GetConnectionAsync(CancellationToken.None);
        await using (connectionHandle)
        {
            return await connectionHandle.Connection.QuerySingleAsync<bool>(
                "SELECT metadata IS NULL FROM ashlar_mfa_handshakes WHERE id = @Id",
                new { Id = handshakeId },
                transaction: connectionHandle.Transaction);
        }
    }

    private static async Task<AshlarPostgresUser> CreateTestUser(IUserRepository repo)
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
