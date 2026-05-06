using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Microsoft.Extensions.DependencyInjection;

namespace Ashlar.Postgres.Tests.Identity;

public sealed class PostgresInvitationRepositoryTests : PostgresTestBase
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

    private PostgresInvitationRepository GetRepository() => (PostgresInvitationRepository)_serviceProvider.GetRequiredService<IInvitationRepository>();

    [Test]
    public async Task CreateAndFetchInvitationShouldSucceed()
    {
        var repo = GetRepository();
        var invitation = new UserInvitation
        {
            Id = Guid.NewGuid(),
            Email = "test@example.com",
            TokenHash = "hash123",
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(7),
            Version = "v1",
            Metadata = "{\"key\":\"val\"}"
        };

        await repo.CreateInvitationAsync(invitation);

        var fetched = await repo.GetInvitationByTokenHashAsync("hash123");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched, Is.Not.Null);
            Assert.That(fetched!.Id, Is.EqualTo(invitation.Id));
            Assert.That(fetched.Email, Is.EqualTo("test@example.com"));
            Assert.That(fetched.Metadata, Does.Contain("\"key\"").And.Contain("\"val\""));
            Assert.That(fetched.UpdatedAt, Is.Not.Null);
        }
    }

    [Test]
    public void CreateInvitationWithInvalidMetadataShouldThrow()
    {
        var repo = GetRepository();
        var invitation = CreateInvitation("invalid-metadata@example.com", "h-inv");
        invitation.Metadata = "not-json";

        Assert.ThrowsAsync<ArgumentException>(() => repo.CreateInvitationAsync(invitation));
    }

    [Test]
    public async Task UpdateInvitationShouldSucceedWithCorrectVersion()
    {
        var repo = GetRepository();
        var invitation = new UserInvitation
        {
            Id = Guid.NewGuid(),
            Email = "update@example.com",
            TokenHash = "hash-update",
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(7),
            Version = "v1"
        };

        await repo.CreateInvitationAsync(invitation);
        var originalUpdatedAt = (await repo.GetInvitationByTokenHashAsync("hash-update"))!.UpdatedAt ?? DateTimeOffset.MinValue;

        invitation.AcceptedAt = DateTimeOffset.UtcNow;
        var result = await repo.UpdateInvitationAsync(invitation, "v1");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result, Is.True);
            Assert.That(invitation.Version, Is.Not.EqualTo("v1"));
            Assert.That(invitation.UpdatedAt, Is.GreaterThanOrEqualTo(originalUpdatedAt));
        }

        var fetched = await repo.GetInvitationByTokenHashAsync("hash-update");
        Assert.That(fetched, Is.Not.Null);
        Assert.That(fetched!.AcceptedAt, Is.Not.Null);
    }

    [Test]
    public async Task UpdateInvitationShouldFailWithWrongVersion()
    {
        var repo = GetRepository();
        var invitation = new UserInvitation
        {
            Id = Guid.NewGuid(),
            Email = "wrong-version@example.com",
            TokenHash = "hash-wrong",
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(7),
            Version = "v1"
        };

        await repo.CreateInvitationAsync(invitation);

        var result = await repo.UpdateInvitationAsync(invitation, "v2");

        Assert.That(result, Is.False);
    }

    [Test]
    public async Task RevokeInvitationsByEmailShouldSucceed()
    {
        var repo = GetRepository();
        var email = "revoke@example.com";
        var inv1 = CreateInvitation(email, "h1");
        var inv2 = CreateInvitation(email, "h2");
        var other = CreateInvitation("other@example.com", "h3");

        await repo.CreateInvitationAsync(inv1);
        await repo.CreateInvitationAsync(inv2);
        await repo.CreateInvitationAsync(other);

        var revokedCount = await repo.RevokeInvitationsByEmailAsync(email);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revokedCount, Is.EqualTo(2));
            Assert.That((await repo.GetInvitationByTokenHashAsync("h1"))!.RevokedAt, Is.Not.Null);
            Assert.That((await repo.GetInvitationByTokenHashAsync("h2"))!.RevokedAt, Is.Not.Null);
            Assert.That((await repo.GetInvitationByTokenHashAsync("h3"))!.RevokedAt, Is.Null);
        }
    }

    [Test]
    public void ConstructorValidatesArguments()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new PostgresInvitationRepository(null!));
    }

    private static UserInvitation CreateInvitation(string email, string hash)
    {
        return new UserInvitation
        {
            Id = Guid.NewGuid(),
            Email = email,
            TokenHash = hash,
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(7),
            Version = Guid.NewGuid().ToString("N")
        };
    }
}
