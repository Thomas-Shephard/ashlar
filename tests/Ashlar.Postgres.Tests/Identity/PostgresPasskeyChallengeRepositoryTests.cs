using Ashlar.Postgres.Models;
using Dapper;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using System.Text.Json;

namespace Ashlar.Postgres.Tests.Identity;

internal sealed class PostgresPasskeyChallengeRepositoryTests : PostgresTestBase
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
    public void ConstructorShouldRejectNullConnectionProvider()
    {
        Assert.Throws<ArgumentNullException>(() => _ = new PostgresPasskeyChallengeRepository(null!));
    }

    [Test]
    public async Task CreateAndGetAsyncShouldMapFields()
    {
        var repository = GetRepository();
        var userId = await CreateUserAsync();
        var challenge = CreateChallenge(userId);

        await repository.CreateAsync(challenge);

        var fetched = await repository.GetAsync(challenge.Id);

        Assert.That(fetched, Is.Not.Null);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched.Id, Is.EqualTo(challenge.Id));
            Assert.That(fetched.Version, Is.EqualTo(challenge.Version));
            Assert.That(fetched.Purpose, Is.EqualTo(challenge.Purpose));
            Assert.That(fetched.UserId, Is.EqualTo(challenge.UserId));
            Assert.That(fetched.HandshakeTokenHash, Is.EqualTo(challenge.HandshakeTokenHash));
            Assert.That(fetched.FactorType, Is.EqualTo(challenge.FactorType));
            Assert.That(fetched.DisplayName, Is.EqualTo(challenge.DisplayName));
            Assert.That(fetched.Challenge, Is.EqualTo(challenge.Challenge));
            Assert.That(JsonDocument.Parse(fetched.OptionsJson).RootElement.GetProperty("challenge").GetString(), Is.EqualTo("test"));
            Assert.That(fetched.RelyingPartyId, Is.EqualTo(challenge.RelyingPartyId));
            Assert.That(fetched.Origin, Is.EqualTo(challenge.Origin));
            Assert.That(fetched.ExpiresAt, Is.EqualTo(challenge.ExpiresAt).Within(TimeSpan.FromSeconds(1)));
            Assert.That(fetched.ConsumedAt, Is.Null);
        }
    }

    [Test]
    public async Task ConsumeAsyncShouldConsumeOnce()
    {
        var repository = GetRepository();
        var challenge = CreateChallenge(await CreateUserAsync());
        await repository.CreateAsync(challenge);

        var consumed = await repository.ConsumeAsync(challenge.Id, challenge.Version, DateTimeOffset.UtcNow);
        var replayed = await repository.ConsumeAsync(challenge.Id, challenge.Version, DateTimeOffset.UtcNow);
        var fetched = await repository.GetAsync(challenge.Id);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(consumed, Is.True);
            Assert.That(replayed, Is.False);
            Assert.That(fetched?.ConsumedAt, Is.Not.Null);
            Assert.That(fetched?.Version, Is.Not.EqualTo(challenge.Version));
        }
    }

    [Test]
    public async Task ConsumeAsyncShouldRejectVersionMismatch()
    {
        var repository = GetRepository();
        var challenge = CreateChallenge(await CreateUserAsync());
        await repository.CreateAsync(challenge);

        var consumed = await repository.ConsumeAsync(challenge.Id, "wrong", DateTimeOffset.UtcNow);

        Assert.That(consumed, Is.False);
    }

    [Test]
    public async Task ConsumeAsyncShouldRejectExpiredChallengeUsingDatabaseClock()
    {
        var repository = GetRepository();
        var challenge = CreateChallenge(await CreateUserAsync(), createdAt: DateTimeOffset.UtcNow.AddMinutes(-10), expiresAt: DateTimeOffset.UtcNow.AddMinutes(-1));
        await repository.CreateAsync(challenge);

        var consumed = await repository.ConsumeAsync(challenge.Id, challenge.Version, DateTimeOffset.UtcNow.AddHours(-1));

        Assert.That(consumed, Is.False);
    }

    [Test]
    public async Task ConsumeAsyncShouldUseWallClockInsideLongRunningTransaction()
    {
        var setupRepository = GetRepository();
        var challenge = CreateChallenge(await CreateUserAsync(), expiresAt: DateTimeOffset.UtcNow.AddMinutes(5));
        await setupRepository.CreateAsync(challenge);
        await using (var connection = await GetDataSource().OpenConnectionAsync())
        {
            await connection.ExecuteAsync(
                "UPDATE ashlar_passkey_challenges SET created_at = clock_timestamp(), expires_at = clock_timestamp() + interval '150 milliseconds' WHERE id = @Id",
                new { challenge.Id });
        }

        await using var manager = new PostgresTransactionManager(GetDataSource());
        await using var transaction = await manager.BeginTransactionAsync();
        await Task.Delay(TimeSpan.FromMilliseconds(500));
        var repository = new PostgresPasskeyChallengeRepository(manager);

        var consumed = await repository.ConsumeAsync(challenge.Id, challenge.Version, DateTimeOffset.UtcNow);

        Assert.That(consumed, Is.False);
    }

    [Test]
    public async Task CreateAsyncShouldEnforceUniqueChallengeValue()
    {
        var repository = GetRepository();
        var userId = await CreateUserAsync();
        var challenge = CreateChallenge(userId);
        var duplicate = CreateChallenge(userId, challengeValue: challenge.Challenge);
        await repository.CreateAsync(challenge);

        Assert.ThrowsAsync<PostgresException>(async () => await repository.CreateAsync(duplicate));
    }

    private IPasskeyChallengeRepository GetRepository() => _serviceProvider.GetRequiredService<IPasskeyChallengeRepository>();

    private async Task<Guid> CreateUserAsync()
    {
        var user = new AshlarPostgresUser
        {
            Id = Guid.NewGuid(),
            Email = $"{Guid.NewGuid():N}@example.com",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };
        await _serviceProvider.GetRequiredService<IIdentityRepository>().CreateUserAsync(user);
        return user.Id;
    }

    private static PasskeyChallenge CreateChallenge(Guid userId, DateTimeOffset? createdAt = null, DateTimeOffset? expiresAt = null, string? challengeValue = null)
    {
        var now = createdAt ?? DateTimeOffset.UtcNow;
        return new PasskeyChallenge
        {
            Id = Guid.NewGuid(),
            Version = Guid.NewGuid().ToString("N"),
            Purpose = "passkey-authentication",
            UserId = userId,
            HandshakeTokenHash = "hashed-token",
            FactorType = "passkey",
            DisplayName = "Work Laptop",
            Challenge = challengeValue ?? Guid.NewGuid().ToString("N"),
            OptionsJson = """{"challenge":"test"}""",
            RelyingPartyId = "example.com",
            Origin = "https://example.com",
            CreatedAt = now,
            ExpiresAt = expiresAt ?? now.AddMinutes(5)
        };
    }
}


