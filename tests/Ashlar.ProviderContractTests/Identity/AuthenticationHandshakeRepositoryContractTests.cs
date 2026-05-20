
namespace Ashlar.ProviderContractTests.Identity;

internal abstract class AuthenticationHandshakeRepositoryContractTests : ProviderContractFixture
{
    private static readonly DateTimeOffset CreatedAt = new(2026, 6, 3, 12, 0, 0, TimeSpan.Zero);
    private static readonly string[] TotpFactor = ["totp"];
    private static readonly string[] PasskeyFactor = ["passkey"];
    private static readonly string[] TotpAndEmailFactors = ["totp", "email"];
    private static readonly string[] TotpAndPasskeyFactors = ["totp", "passkey"];
    private static readonly Dictionary<string, string> UpdatedMetadata = new() { ["updated"] = "true" };

    [Test]
    public async Task CreateAndFetchByTokenHashMapsAllFields()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var repository = GetAuthenticationHandshakeRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identityRepository);
        var handshake = CreateHandshake(user.Id, requiredFactors: new HashSet<string>(TotpAndEmailFactors), verifiedFactors: new HashSet<string>(TotpFactor), metadata: new Dictionary<string, string> { ["device"] = "test", ["risk"] = "low" });

        await repository.CreateAsync(handshake);

        var fetched = await repository.FindByTokenHashAsync(handshake.TokenHash);

        Assert.That(fetched, Is.Not.Null);
        AssertHandshake(fetched!, handshake);
    }

    [Test]
    public async Task FetchMissingTokenReturnsNull()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetAuthenticationHandshakeRepository(scope.ServiceProvider);

        Assert.That(await repository.FindByTokenHashAsync("missing-token"), Is.Null);
    }

    [Test]
    public async Task FindByTokenHashForUpdateReturnsExpectedHandshakeAndCanBeUpdated()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var repository = GetAuthenticationHandshakeRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identityRepository);
        var handshake = CreateHandshake(user.Id);
        await repository.CreateAsync(handshake);

        var fetched = await repository.FindByTokenHashAsync(handshake.TokenHash, forUpdate: true);
        await repository.UpdateAsync(fetched! with { VerifiedFactors = new HashSet<string> { "totp" } });
        var updated = await repository.FindByTokenHashAsync(handshake.TokenHash);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched?.Id, Is.EqualTo(handshake.Id));
            Assert.That(updated!.VerifiedFactors, Is.EquivalentTo(TotpFactor));
        }
    }

    [Test]
    public async Task RequiredAndVerifiedFactorsRoundTrip()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var repository = GetAuthenticationHandshakeRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identityRepository);
        var handshake = CreateHandshake(user.Id, requiredFactors: new HashSet<string>(TotpAndPasskeyFactors), verifiedFactors: new HashSet<string>(PasskeyFactor));

        await repository.CreateAsync(handshake);

        var fetched = await repository.FindByTokenHashAsync(handshake.TokenHash);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched!.RequiredFactors, Is.EquivalentTo(TotpAndPasskeyFactors));
            Assert.That(fetched.VerifiedFactors, Is.EquivalentTo(PasskeyFactor));
        }
    }

    [Test]
    public async Task MetadataRoundTripsIncludingNullMetadata()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var repository = GetAuthenticationHandshakeRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identityRepository);
        var withMetadata = CreateHandshake(user.Id, tokenHash: "hash:metadata", metadata: new Dictionary<string, string> { ["flow"] = "step-up" });
        var withoutMetadata = CreateHandshake(user.Id, tokenHash: "hash:null-metadata", metadata: null);
        await repository.CreateAsync(withMetadata);
        await repository.CreateAsync(withoutMetadata);

        var fetchedWithMetadata = await repository.FindByTokenHashAsync(withMetadata.TokenHash);
        var fetchedWithoutMetadata = await repository.FindByTokenHashAsync(withoutMetadata.TokenHash);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetchedWithMetadata!.Metadata, Is.EquivalentTo(withMetadata.Metadata!));
            Assert.That(fetchedWithoutMetadata!.Metadata, Is.Null);
        }
    }

    [Test]
    public async Task UpdatePersistsCompletionStateAndTimestamp()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var repository = GetAuthenticationHandshakeRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identityRepository);
        var handshake = CreateHandshake(user.Id);
        var completedAt = CreatedAt.AddMinutes(10);
        await repository.CreateAsync(handshake);

        await repository.UpdateAsync(handshake with { IsCompleted = true, CompletedAt = completedAt });

        var fetched = await repository.FindByTokenHashAsync(handshake.TokenHash);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched!.IsCompleted, Is.True);
            Assert.That(fetched.CompletedAt, Is.EqualTo(completedAt));
        }
    }

    [Test]
    public async Task UpdateComputesCompletionTimestampWhenMissing()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var repository = GetAuthenticationHandshakeRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identityRepository);
        var handshake = CreateHandshake(user.Id);
        await repository.CreateAsync(handshake);

        await repository.UpdateAsync(handshake with { IsCompleted = true, CompletedAt = null });

        var fetched = await repository.FindByTokenHashAsync(handshake.TokenHash);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched!.IsCompleted, Is.True);
            Assert.That(fetched.CompletedAt, Is.Not.Null);
        }
    }

    [Test]
    public async Task UpdatePersistsRevocationStateAndTimestamp()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var repository = GetAuthenticationHandshakeRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identityRepository);
        var handshake = CreateHandshake(user.Id);
        var revokedAt = CreatedAt.AddMinutes(11);
        await repository.CreateAsync(handshake);

        await repository.UpdateAsync(handshake with { IsRevoked = true, RevokedAt = revokedAt });

        var fetched = await repository.FindByTokenHashAsync(handshake.TokenHash);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched!.IsRevoked, Is.True);
            Assert.That(fetched.RevokedAt, Is.EqualTo(revokedAt));
        }
    }

    [Test]
    public async Task UpdateComputesRevocationTimestampWhenMissing()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var repository = GetAuthenticationHandshakeRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identityRepository);
        var handshake = CreateHandshake(user.Id);
        await repository.CreateAsync(handshake);

        await repository.UpdateAsync(handshake with { IsRevoked = true, RevokedAt = null });

        var fetched = await repository.FindByTokenHashAsync(handshake.TokenHash);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched!.IsRevoked, Is.True);
            Assert.That(fetched.RevokedAt, Is.Not.Null);
        }
    }

    [Test]
    public async Task UpdateCanStoreAndResetVerifiedFactorsAndMetadata()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var repository = GetAuthenticationHandshakeRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identityRepository);
        var handshake = CreateHandshake(user.Id, verifiedFactors: new HashSet<string>(TotpFactor), metadata: new Dictionary<string, string> { ["initial"] = "true" });
        await repository.CreateAsync(handshake);

        await repository.UpdateAsync(handshake with
        {
            VerifiedFactors = new HashSet<string> { "passkey" },
            Metadata = new Dictionary<string, string> { ["updated"] = "true" }
        });
        var updated = await repository.FindByTokenHashAsync(handshake.TokenHash);
        await repository.UpdateAsync(handshake with { VerifiedFactors = new HashSet<string>(), Metadata = null });
        var reset = await repository.FindByTokenHashAsync(handshake.TokenHash);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(updated!.VerifiedFactors, Is.EquivalentTo(PasskeyFactor));
            Assert.That(updated.Metadata, Is.EquivalentTo(UpdatedMetadata));
            Assert.That(reset!.VerifiedFactors, Is.Empty);
            Assert.That(reset.Metadata, Is.Null);
        }
    }

    [Test]
    public async Task CreateRejectsNullHandshake()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetAuthenticationHandshakeRepository(scope.ServiceProvider);

        Assert.ThrowsAsync<ArgumentNullException>(async () => await repository.CreateAsync(null!));
    }

    [Test]
    public async Task UpdateRejectsNullHandshake()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetAuthenticationHandshakeRepository(scope.ServiceProvider);

        Assert.ThrowsAsync<ArgumentNullException>(async () => await repository.UpdateAsync(null!));
    }

    [Test]
    public async Task HandshakeWritesRollBackWhenProviderSupportsTransactions()
    {
        Guid handshakeId;
        await using (var scope = CreateAsyncScope())
        {
            var transactionProvider = GetTransactionProvider(scope.ServiceProvider);
            if (transactionProvider == null)
            {
                Assert.Ignore("Provider does not register IAshlarTransactionProvider.");
            }

            var identityRepository = GetIdentityRepository(scope.ServiceProvider);
            var repository = GetAuthenticationHandshakeRepository(scope.ServiceProvider);
            var user = await CreateUserAsync(identityRepository);
            var handshake = CreateHandshake(user.Id);
            handshakeId = handshake.Id;

            await using var transaction = await transactionProvider.BeginTransactionAsync();
            await repository.CreateAsync(handshake);
            await transaction.RollbackAsync();
        }

        await using var verificationScope = CreateAsyncScope();
        var verificationRepository = GetAuthenticationHandshakeRepository(verificationScope.ServiceProvider);
        Assert.That(await verificationRepository.FindByTokenHashAsync($"hash:{handshakeId:N}"), Is.Null);
    }

    private static AuthenticationHandshake CreateHandshake(
        Guid userId,
        string? tokenHash = null,
        IReadOnlySet<string>? requiredFactors = null,
        IReadOnlySet<string>? verifiedFactors = null,
        IDictionary<string, string>? metadata = null)
    {
        var id = Guid.NewGuid();
        return new AuthenticationHandshake(
            id,
            userId,
            tokenHash ?? $"hash:{id:N}",
            CreatedAt,
            CreatedAt.AddMinutes(15),
            false,
            false,
            requiredFactors ?? new HashSet<string> { "totp" },
            verifiedFactors ?? new HashSet<string>(),
            metadata);
    }

    private static void AssertHandshake(AuthenticationHandshake actual, AuthenticationHandshake expected)
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(actual.Id, Is.EqualTo(expected.Id));
            Assert.That(actual.UserId, Is.EqualTo(expected.UserId));
            Assert.That(actual.TokenHash, Is.EqualTo(expected.TokenHash));
            Assert.That(actual.CreatedAt, Is.EqualTo(expected.CreatedAt));
            Assert.That(actual.ExpiresAt, Is.EqualTo(expected.ExpiresAt));
            Assert.That(actual.IsRevoked, Is.EqualTo(expected.IsRevoked));
            Assert.That(actual.IsCompleted, Is.EqualTo(expected.IsCompleted));
            Assert.That(actual.RequiredFactors, Is.EquivalentTo(expected.RequiredFactors));
            Assert.That(actual.VerifiedFactors, Is.EquivalentTo(expected.VerifiedFactors));
            if (expected.Metadata == null)
            {
                Assert.That(actual.Metadata, Is.Null);
            }
            else
            {
                Assert.That(actual.Metadata, Is.EquivalentTo(expected.Metadata));
            }
            Assert.That(actual.RevokedAt, Is.EqualTo(expected.RevokedAt));
            Assert.That(actual.CompletedAt, Is.EqualTo(expected.CompletedAt));
        }
    }
}
