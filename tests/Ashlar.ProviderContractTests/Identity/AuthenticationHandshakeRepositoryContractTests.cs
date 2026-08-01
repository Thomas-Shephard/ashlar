namespace Ashlar.ProviderContractTests.Identity;

/// <summary>Tests handshake persistence, tenant binding, terminal transitions, concurrency, and rollback.</summary>
public abstract class AuthenticationHandshakeRepositoryContractTests : ProviderContractFixture
{
    private static readonly DateTimeOffset CreatedAt = new(2026, 6, 3, 12, 0, 0, TimeSpan.Zero);
    private static readonly string[] TotpFactor = ["totp"];
    private static readonly string[] PasskeyFactor = ["passkey"];
    private static readonly string[] TotpAndEmailFactors = ["totp", "email"];
    private static readonly string[] TotpAndPasskeyFactors = ["totp", "passkey"];
    private static readonly Dictionary<string, string> UpdatedMetadata = new() { ["updated"] = "true" };

    /// <summary>Verifies that token lookup recovers every stored handshake field.</summary>
    [Test]
    public async Task CreateAndFetchByTokenHashMapsAllFields()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetAuthenticationHandshakeRepository(scope.ServiceProvider);
        var tenantId = Guid.NewGuid();
        var user = await CreateUserAsync(userRepository, tenantId: tenantId);
        var handshake = CreateHandshake(user.Id, tenantId, requiredFactors: new HashSet<string>(TotpAndEmailFactors), verifiedFactors: new HashSet<string>(TotpFactor), metadata: new Dictionary<string, string> { ["device"] = "test", ["risk"] = "low" }, targetSessionId: Guid.NewGuid());

        await repository.CreateAsync(handshake);

        var fetched = await repository.FindByTokenHashAsync(handshake.TokenHash);

        Assert.That(fetched, Is.Not.Null);
        AssertHandshake(fetched!, handshake);
    }

    /// <summary>Preserves the global or tenant ownership assigned to each stored handshake.</summary>
    [Test]
    public async Task GlobalAndTenantHandshakesRoundTripDistinctTenantScopes()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetAuthenticationHandshakeRepository(scope.ServiceProvider);
        var tenantId = Guid.NewGuid();
        var globalUser = await CreateUserAsync(userRepository);
        var tenantUser = await CreateUserAsync(userRepository, tenantId: tenantId);
        var globalHandshake = CreateHandshake(globalUser.Id, tokenHash: "hash:global");
        var tenantHandshake = CreateHandshake(tenantUser.Id, tenantId, tokenHash: "hash:tenant");

        await repository.CreateAsync(globalHandshake);
        await repository.CreateAsync(tenantHandshake);

        var fetchedGlobal = await repository.FindByTokenHashAsync(globalHandshake.TokenHash);
        var fetchedTenant = await repository.FindByTokenHashAsync(tenantHandshake.TokenHash);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetchedGlobal!.TenantId, Is.Null);
            Assert.That(fetchedTenant!.TenantId, Is.EqualTo(tenantId));
            AssertHandshake(fetchedGlobal, globalHandshake);
            AssertHandshake(fetchedTenant, tenantHandshake);
        }
    }

    /// <summary>Verifies that creation rejects a handshake outside its user's tenant.</summary>
    [Test]
    public async Task CreateRejectsHandshakeTenantThatDoesNotMatchUserTenant()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetAuthenticationHandshakeRepository(scope.ServiceProvider);
        var tenantUser = await CreateUserAsync(userRepository, tenantId: Guid.NewGuid());
        var handshake = CreateHandshake(tenantUser.Id, Guid.NewGuid());

        Assert.That(async () => await repository.CreateAsync(handshake), Throws.InstanceOf<Exception>());
    }

    /// <summary>Verifies that an unknown token hash returns no fabricated handshake.</summary>
    [Test]
    public async Task FetchMissingTokenReturnsNull()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetAuthenticationHandshakeRepository(scope.ServiceProvider);

        Assert.That(await repository.FindByTokenHashAsync("missing-token"), Is.Null);
    }

    /// <summary>Verifies that update lookup returns a mutable handle for the matching handshake.</summary>
    [Test]
    public async Task FindByTokenHashForUpdateReturnsExpectedHandshakeAndCanBeUpdated()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetAuthenticationHandshakeRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(userRepository);
        var handshake = CreateHandshake(user.Id);
        await repository.CreateAsync(handshake);

        var fetched = await repository.FindByTokenHashAsync(handshake.TokenHash, forUpdate: true);
        var updateApplied = await repository.UpdateAsync(fetched! with { VerifiedFactors = new HashSet<string> { "totp" } });
        var updated = await repository.FindByTokenHashAsync(handshake.TokenHash);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched?.Id, Is.EqualTo(handshake.Id));
            Assert.That(updateApplied, Is.True);
            Assert.That(updated!.VerifiedFactors, Is.EquivalentTo(TotpFactor));
        }
    }

    /// <summary>Preserves the required and completed authentication-factor sets.</summary>
    [Test]
    public async Task RequiredAndVerifiedFactorsRoundTrip()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetAuthenticationHandshakeRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(userRepository);
        var handshake = CreateHandshake(user.Id, requiredFactors: new HashSet<string>(TotpAndPasskeyFactors), verifiedFactors: new HashSet<string>(PasskeyFactor));

        await repository.CreateAsync(handshake);

        var fetched = await repository.FindByTokenHashAsync(handshake.TokenHash);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fetched!.RequiredFactors, Is.EquivalentTo(TotpAndPasskeyFactors));
            Assert.That(fetched.VerifiedFactors, Is.EquivalentTo(PasskeyFactor));
        }
    }

    /// <summary>Preserves both populated metadata and the absence of metadata.</summary>
    [Test]
    public async Task MetadataRoundTripsIncludingNullMetadata()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetAuthenticationHandshakeRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(userRepository);
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

    /// <summary>Verifies that completion updates both terminal state and its timestamp.</summary>
    [Test]
    public async Task UpdatePersistsCompletionStateAndTimestamp()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetAuthenticationHandshakeRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(userRepository);
        var handshake = CreateHandshake(user.Id);
        var completedAt = CreatedAt.AddMinutes(10);
        await repository.CreateAsync(handshake);

        var updateApplied = await repository.UpdateAsync(handshake with { IsCompleted = true, CompletedAt = completedAt });

        var fetched = await repository.FindByTokenHashAsync(handshake.TokenHash);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(updateApplied, Is.True);
            Assert.That(fetched!.IsCompleted, Is.True);
            Assert.That(fetched.CompletedAt, Is.EqualTo(completedAt));
        }
    }

    /// <summary>Verifies that completion supplies a timestamp when the caller omits one.</summary>
    [Test]
    public async Task UpdateComputesCompletionTimestampWhenMissing()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetAuthenticationHandshakeRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(userRepository);
        var handshake = CreateHandshake(user.Id);
        await repository.CreateAsync(handshake);

        var updateApplied = await repository.UpdateAsync(handshake with { IsCompleted = true, CompletedAt = null });

        var fetched = await repository.FindByTokenHashAsync(handshake.TokenHash);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(updateApplied, Is.True);
            Assert.That(fetched!.IsCompleted, Is.True);
            Assert.That(fetched.CompletedAt, Is.Not.Null);
        }
    }

    /// <summary>Verifies that revocation updates both terminal state and its timestamp.</summary>
    [Test]
    public async Task UpdatePersistsRevocationStateAndTimestamp()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetAuthenticationHandshakeRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(userRepository);
        var handshake = CreateHandshake(user.Id);
        var revokedAt = CreatedAt.AddMinutes(11);
        await repository.CreateAsync(handshake);

        var updateApplied = await repository.UpdateAsync(handshake with { IsRevoked = true, RevokedAt = revokedAt });

        var fetched = await repository.FindByTokenHashAsync(handshake.TokenHash);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(updateApplied, Is.True);
            Assert.That(fetched!.IsRevoked, Is.True);
            Assert.That(fetched.RevokedAt, Is.EqualTo(revokedAt));
        }
    }

    /// <summary>Verifies that revocation supplies a timestamp when the caller omits one.</summary>
    [Test]
    public async Task UpdateComputesRevocationTimestampWhenMissing()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetAuthenticationHandshakeRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(userRepository);
        var handshake = CreateHandshake(user.Id);
        await repository.CreateAsync(handshake);

        var updateApplied = await repository.UpdateAsync(handshake with { IsRevoked = true, RevokedAt = null });

        var fetched = await repository.FindByTokenHashAsync(handshake.TokenHash);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(updateApplied, Is.True);
            Assert.That(fetched!.IsRevoked, Is.True);
            Assert.That(fetched.RevokedAt, Is.Not.Null);
        }
    }

    /// <summary>Verifies that updates can replace or clear optional factor and metadata state.</summary>
    [Test]
    public async Task UpdateCanStoreAndResetVerifiedFactorsAndMetadata()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetAuthenticationHandshakeRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(userRepository);
        var handshake = CreateHandshake(user.Id, verifiedFactors: new HashSet<string>(TotpFactor), metadata: new Dictionary<string, string> { ["initial"] = "true" });
        await repository.CreateAsync(handshake);

        var firstUpdateApplied = await repository.UpdateAsync(handshake with
        {
            VerifiedFactors = new HashSet<string> { "passkey" },
            Metadata = new Dictionary<string, string> { ["updated"] = "true" }
        });
        var updated = await repository.FindByTokenHashAsync(handshake.TokenHash);
        var resetUpdateApplied = await repository.UpdateAsync(handshake with { VerifiedFactors = new HashSet<string>(), Metadata = null });
        var reset = await repository.FindByTokenHashAsync(handshake.TokenHash);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(firstUpdateApplied, Is.True);
            Assert.That(updated!.VerifiedFactors, Is.EquivalentTo(PasskeyFactor));
            Assert.That(updated.Metadata, Is.EquivalentTo(UpdatedMetadata));
            Assert.That(resetUpdateApplied, Is.True);
            Assert.That(reset!.VerifiedFactors, Is.Empty);
            Assert.That(reset.Metadata, Is.Null);
        }
    }

    /// <summary>Verifies that completion makes a handshake immutable to later updates.</summary>
    [Test]
    public async Task UpdateReturnsFalseAndDoesNotModifyCompletedHandshake()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetAuthenticationHandshakeRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(userRepository);
        var handshake = CreateHandshake(user.Id, metadata: new Dictionary<string, string> { ["initial"] = "true" });
        var completedAt = CreatedAt.AddMinutes(12);
        await repository.CreateAsync(handshake);
        var completedUpdateApplied = await repository.UpdateAsync(handshake with
        {
            IsCompleted = true,
            CompletedAt = completedAt,
            VerifiedFactors = new HashSet<string>(TotpFactor),
            Metadata = new Dictionary<string, string> { ["completed"] = "true" }
        });
        var completed = await repository.FindByTokenHashAsync(handshake.TokenHash);

        var staleUpdateApplied = await repository.UpdateAsync(completed! with
        {
            IsCompleted = false,
            CompletedAt = null,
            IsRevoked = true,
            RevokedAt = CreatedAt.AddMinutes(13),
            VerifiedFactors = new HashSet<string>(PasskeyFactor),
            Metadata = UpdatedMetadata
        });
        var afterStaleUpdate = await repository.FindByTokenHashAsync(handshake.TokenHash);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(completedUpdateApplied, Is.True);
            Assert.That(staleUpdateApplied, Is.False);
            AssertHandshake(afterStaleUpdate!, completed!);
        }
    }

    /// <summary>Verifies that revocation makes a handshake immutable to later updates.</summary>
    [Test]
    public async Task UpdateReturnsFalseAndDoesNotModifyRevokedHandshake()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var repository = GetAuthenticationHandshakeRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(userRepository);
        var handshake = CreateHandshake(user.Id, metadata: new Dictionary<string, string> { ["initial"] = "true" });
        var revokedAt = CreatedAt.AddMinutes(14);
        await repository.CreateAsync(handshake);
        var revokedUpdateApplied = await repository.UpdateAsync(handshake with
        {
            IsRevoked = true,
            RevokedAt = revokedAt,
            Metadata = new Dictionary<string, string> { ["revoked"] = "true" }
        });
        var revoked = await repository.FindByTokenHashAsync(handshake.TokenHash);

        var staleUpdateApplied = await repository.UpdateAsync(revoked! with
        {
            IsRevoked = false,
            RevokedAt = null,
            IsCompleted = true,
            CompletedAt = CreatedAt.AddMinutes(15),
            VerifiedFactors = new HashSet<string>(PasskeyFactor),
            Metadata = UpdatedMetadata
        });
        var afterStaleUpdate = await repository.FindByTokenHashAsync(handshake.TokenHash);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revokedUpdateApplied, Is.True);
            Assert.That(staleUpdateApplied, Is.False);
            AssertHandshake(afterStaleUpdate!, revoked!);
        }
    }

    /// <summary>Verifies that updating an absent handshake reports no change.</summary>
    [Test]
    public async Task UpdateMissingHandshakeReturnsFalse()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetAuthenticationHandshakeRepository(scope.ServiceProvider);
        var missing = CreateHandshake(Guid.NewGuid(), verifiedFactors: new HashSet<string>(TotpFactor));

        var updateApplied = await repository.UpdateAsync(missing);

        Assert.That(updateApplied, Is.False);
    }

    /// <summary>Verifies that creation rejects a missing handshake value before persistence.</summary>
    [Test]
    public async Task CreateRejectsNullHandshake()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetAuthenticationHandshakeRepository(scope.ServiceProvider);

        Assert.ThrowsAsync<ArgumentNullException>(async () => await repository.CreateAsync(null!));
    }

    /// <summary>Verifies that update rejects a missing handshake value before persistence.</summary>
    [Test]
    public async Task UpdateRejectsNullHandshake()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetAuthenticationHandshakeRepository(scope.ServiceProvider);

        Assert.ThrowsAsync<ArgumentNullException>(async () => await repository.UpdateAsync(null!));
    }

    /// <summary>Leaves no persisted handshake after its surrounding transaction is rolled back.</summary>
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

            var userRepository = GetUserRepository(scope.ServiceProvider);
            var repository = GetAuthenticationHandshakeRepository(scope.ServiceProvider);
            var user = await CreateUserAsync(userRepository);
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
        Guid? tenantId = null,
        string? tokenHash = null,
        IReadOnlySet<string>? requiredFactors = null,
        IReadOnlySet<string>? verifiedFactors = null,
        IDictionary<string, string>? metadata = null,
        Guid? targetSessionId = null)
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
            metadata)
        {
            TenantId = tenantId,
            Purpose = targetSessionId == null ? AuthenticationHandshakePurpose.LoginSession : AuthenticationHandshakePurpose.ExistingSessionStepUp,
            TargetSessionId = targetSessionId
        };
    }

    private static void AssertHandshake(AuthenticationHandshake actual, AuthenticationHandshake expected)
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(actual.Id, Is.EqualTo(expected.Id));
            Assert.That(actual.UserId, Is.EqualTo(expected.UserId));
            Assert.That(actual.TenantId, Is.EqualTo(expected.TenantId));
            Assert.That(actual.Purpose, Is.EqualTo(expected.Purpose));
            Assert.That(actual.TargetSessionId, Is.EqualTo(expected.TargetSessionId));
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
