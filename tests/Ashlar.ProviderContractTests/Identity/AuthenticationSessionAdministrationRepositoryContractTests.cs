namespace Ashlar.ProviderContractTests.Identity;

internal abstract class AuthenticationSessionAdministrationRepositoryContractTests : ProviderContractFixture
{
    private static readonly DateTimeOffset BaseTime = new(2026, 6, 2, 12, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Now = BaseTime.AddHours(1);

    [Test]
    public async Task SearchAuthenticationSessionsSearchesAcrossMultipleUsersAndFiltersByUser()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var sessionRepository = GetAuthenticationSessionRepository(scope.ServiceProvider);
        var firstUser = await CreateUserAsync(userRepository);
        var secondUser = await CreateUserAsync(userRepository);
        var first = CreateSession(firstUser.Id, createdAt: BaseTime.AddMinutes(1));
        var second = CreateSession(secondUser.Id, createdAt: BaseTime.AddMinutes(2));
        await sessionRepository.CreateSessionAsync(first);
        await sessionRepository.CreateSessionAsync(second);

        var repository = GetAuthenticationSessionAdministrationRepository(scope.ServiceProvider);
        var all = await repository.SearchAuthenticationSessionsAsync(new SearchAuthenticationSessionsRequest { Limit = 10 }, Now);
        var filtered = await repository.SearchAuthenticationSessionsAsync(new SearchAuthenticationSessionsRequest { UserId = firstUser.Id, Limit = 10 }, Now);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(all.Select(static session => session.Id), Does.Contain(first.Id));
            Assert.That(all.Select(static session => session.Id), Does.Contain(second.Id));
            Assert.That(filtered.Select(static session => session.Id), Is.EqualTo(new[] { first.Id }));
        }
    }

    [Test]
    public async Task SearchAuthenticationSessionsFiltersTenantScopes()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var sessionRepository = GetAuthenticationSessionRepository(scope.ServiceProvider);
        var tenantId = Guid.NewGuid();
        var tenantUser = await CreateUserAsync(userRepository, tenantId: tenantId);
        var globalUser = await CreateUserAsync(userRepository);
        var otherTenantUser = await CreateUserAsync(userRepository, tenantId: Guid.NewGuid());
        var tenantSession = CreateSession(tenantUser.Id, tenantId: tenantId);
        var globalSession = CreateSession(globalUser.Id);
        var otherTenantSession = CreateSession(otherTenantUser.Id, tenantId: otherTenantUser.TenantId);
        await sessionRepository.CreateSessionAsync(tenantSession);
        await sessionRepository.CreateSessionAsync(globalSession);
        await sessionRepository.CreateSessionAsync(otherTenantSession);

        var repository = GetAuthenticationSessionAdministrationRepository(scope.ServiceProvider);
        var scoped = await repository.SearchAuthenticationSessionsAsync(new SearchAuthenticationSessionsRequest { Tenant = new TenantContext(tenantId), Limit = 10 }, Now);
        var global = await repository.SearchAuthenticationSessionsAsync(new SearchAuthenticationSessionsRequest { Tenant = TenantContext.Global, Limit = 10 }, Now);
        var unscoped = await repository.SearchAuthenticationSessionsAsync(new SearchAuthenticationSessionsRequest { Limit = 10 }, Now);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scoped.Select(static session => session.Id), Is.EqualTo(new[] { tenantSession.Id }));
            Assert.That(global.Select(static session => session.Id), Is.EqualTo(new[] { globalSession.Id }));
            Assert.That(unscoped.Select(static session => session.Id), Does.Contain(tenantSession.Id));
            Assert.That(unscoped.Select(static session => session.Id), Does.Contain(globalSession.Id));
            Assert.That(unscoped.Select(static session => session.Id), Does.Contain(otherTenantSession.Id));
        }
    }

    [Test]
    public async Task SearchAuthenticationSessionsFiltersActiveRevokedAndExpiredCorrectly()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var sessionRepository = GetAuthenticationSessionRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(userRepository);
        var active = CreateSession(user.Id);
        var revoked = CreateSession(user.Id);
        var expired = CreateSession(user.Id, expiresAt: Now.AddMilliseconds(-1));
        await sessionRepository.CreateSessionAsync(active);
        await sessionRepository.CreateSessionAsync(revoked);
        await sessionRepository.CreateSessionAsync(expired);
        await sessionRepository.RevokeSessionAsync(revoked.Id, BaseTime.AddMinutes(30), "manual");

        var repository = GetAuthenticationSessionAdministrationRepository(scope.ServiceProvider);
        var activeResult = await repository.SearchAuthenticationSessionsAsync(new SearchAuthenticationSessionsRequest { Active = true, Limit = 10 }, Now);
        var inactiveResult = await repository.SearchAuthenticationSessionsAsync(new SearchAuthenticationSessionsRequest { Active = false, Limit = 10 }, Now);
        var revokedResult = await repository.SearchAuthenticationSessionsAsync(new SearchAuthenticationSessionsRequest { Revoked = true, Limit = 10 }, Now);
        var unrevokedResult = await repository.SearchAuthenticationSessionsAsync(new SearchAuthenticationSessionsRequest { Revoked = false, Limit = 10 }, Now);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(activeResult.Select(static session => session.Id), Is.EqualTo(new[] { active.Id }));
            Assert.That(inactiveResult.Select(static session => session.Id), Is.EquivalentTo(new[] { revoked.Id, expired.Id }));
            Assert.That(revokedResult.Select(static session => session.Id), Is.EqualTo(new[] { revoked.Id }));
            Assert.That(unrevokedResult.Select(static session => session.Id), Is.EquivalentTo(new[] { active.Id, expired.Id }));
            Assert.That(activeResult.Single().IsActive, Is.True);
            Assert.That(inactiveResult.All(static session => !session.IsActive), Is.True);
        }
    }

    [Test]
    public async Task SearchAuthenticationSessionsFiltersByPrimaryProviderAndDateRanges()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var sessionRepository = GetAuthenticationSessionRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(userRepository);
        var matching = CreateSession(user.Id, createdAt: BaseTime.AddMinutes(10), expiresAt: BaseTime.AddHours(3));
        matching.PrimaryProvider = AuthenticationProviderKey.MagicLink;
        matching.LastSeenAt = BaseTime.AddMinutes(20);
        var wrongProvider = CreateSession(user.Id, createdAt: BaseTime.AddMinutes(10), expiresAt: BaseTime.AddHours(3));
        wrongProvider.PrimaryProvider = AuthenticationProviderKey.Local;
        wrongProvider.LastSeenAt = BaseTime.AddMinutes(20);
        var outsideCreated = CreateSession(user.Id, createdAt: BaseTime.AddMinutes(1), expiresAt: BaseTime.AddHours(3));
        outsideCreated.PrimaryProvider = AuthenticationProviderKey.MagicLink;
        outsideCreated.LastSeenAt = BaseTime.AddMinutes(20);
        var outsideLastSeen = CreateSession(user.Id, createdAt: BaseTime.AddMinutes(10), expiresAt: BaseTime.AddHours(3));
        outsideLastSeen.PrimaryProvider = AuthenticationProviderKey.MagicLink;
        outsideLastSeen.LastSeenAt = BaseTime.AddMinutes(40);
        var outsideExpires = CreateSession(user.Id, createdAt: BaseTime.AddMinutes(10), expiresAt: BaseTime.AddHours(5));
        outsideExpires.PrimaryProvider = AuthenticationProviderKey.MagicLink;
        outsideExpires.LastSeenAt = BaseTime.AddMinutes(20);
        await sessionRepository.CreateSessionAsync(matching);
        await sessionRepository.CreateSessionAsync(wrongProvider);
        await sessionRepository.CreateSessionAsync(outsideCreated);
        await sessionRepository.CreateSessionAsync(outsideLastSeen);
        await sessionRepository.CreateSessionAsync(outsideExpires);

        var result = await GetAuthenticationSessionAdministrationRepository(scope.ServiceProvider).SearchAuthenticationSessionsAsync(new SearchAuthenticationSessionsRequest
        {
            PrimaryProvider = AuthenticationProviderKey.MagicLink,
            CreatedFrom = BaseTime.AddMinutes(5),
            CreatedTo = BaseTime.AddMinutes(15),
            LastSeenFrom = BaseTime.AddMinutes(15),
            LastSeenTo = BaseTime.AddMinutes(25),
            ExpiresFrom = BaseTime.AddHours(2),
            ExpiresTo = BaseTime.AddHours(4),
            Limit = 10
        }, Now);

        Assert.That(result.Select(static session => session.Id), Is.EqualTo(new[] { matching.Id }));
    }

    [Test]
    public async Task SearchAuthenticationSessionsOrdersByLastSeenCreatedAndIdDescending()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var sessionRepository = GetAuthenticationSessionRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(userRepository);
        var noLastSeen = CreateSession(user.Id, id: Guid.Parse("00000000-0000-0000-0000-000000000003"), createdAt: BaseTime.AddMinutes(10));
        var olderLastSeen = CreateSession(user.Id, id: Guid.Parse("00000000-0000-0000-0000-000000000001"), createdAt: BaseTime.AddMinutes(1));
        olderLastSeen.LastSeenAt = BaseTime.AddMinutes(20);
        var lowerTie = CreateSession(user.Id, id: Guid.Parse("00000000-0000-0000-0000-000000000002"), createdAt: BaseTime.AddMinutes(30));
        lowerTie.LastSeenAt = BaseTime.AddMinutes(30);
        var higherTie = CreateSession(user.Id, id: Guid.Parse("ffffffff-ffff-ffff-ffff-ffffffffffff"), createdAt: BaseTime.AddMinutes(30), tokenHash: "sha256:higher");
        higherTie.LastSeenAt = BaseTime.AddMinutes(30);
        await sessionRepository.CreateSessionAsync(noLastSeen);
        await sessionRepository.CreateSessionAsync(olderLastSeen);
        await sessionRepository.CreateSessionAsync(lowerTie);
        await sessionRepository.CreateSessionAsync(higherTie);

        var result = await GetAuthenticationSessionAdministrationRepository(scope.ServiceProvider).SearchAuthenticationSessionsAsync(new SearchAuthenticationSessionsRequest { Limit = 10 }, Now);

        Assert.That(result.Select(static session => session.Id), Is.EqualTo(new[] { higherTie.Id, lowerTie.Id, olderLastSeen.Id, noLastSeen.Id }));
    }

    [Test]
    public async Task GetAuthenticationSessionReturnsDetailByIdAndMissingReturnsNull()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var sessionRepository = GetAuthenticationSessionRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(userRepository);
        var session = CreateSession(user.Id, tenantId: Guid.NewGuid());
        session.AuthenticatedAt = BaseTime.AddMinutes(1);
        session.PrimaryProvider = AuthenticationProviderKey.Local;
        session.AdditionalVerificationAt = BaseTime.AddMinutes(2);
        session.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, "totp");
        session.AdditionalVerificationFactor = "totp";
        session.IpAddress = "203.0.113.10";
        session.UserAgent = "Contract Test";
        session.Metadata = """{"secret":"not returned"}""";
        await sessionRepository.CreateSessionAsync(session);

        var repository = GetAuthenticationSessionAdministrationRepository(scope.ServiceProvider);
        var found = await repository.GetAuthenticationSessionAsync(session.Id, Now);
        var missing = await repository.GetAuthenticationSessionAsync(Guid.NewGuid(), Now);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(found?.Id, Is.EqualTo(session.Id));
            Assert.That(found?.UserId, Is.EqualTo(user.Id));
            Assert.That(found?.TenantId, Is.EqualTo(session.TenantId));
            Assert.That(found?.PrimaryProvider, Is.EqualTo(AuthenticationProviderKey.Local));
            Assert.That(found?.AdditionalVerificationProvider, Is.EqualTo(session.AdditionalVerificationProvider));
            Assert.That(found?.AdditionalVerificationFactor, Is.EqualTo("totp"));
            Assert.That(found?.IpAddress, Is.EqualTo("203.0.113.10"));
            Assert.That(found?.UserAgent, Is.EqualTo("Contract Test"));
            Assert.That(found?.IsActive, Is.True);
            Assert.That(missing, Is.Null);
        }
    }

    [Test]
    public async Task AuthenticationSessionAdministrationDoesNotReturnTokenHash()
    {
        await using var scope = CreateAsyncScope();
        var userRepository = GetUserRepository(scope.ServiceProvider);
        var sessionRepository = GetAuthenticationSessionRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(userRepository);
        var session = CreateSession(user.Id, tokenHash: "sha256:secret-token-hash");
        await sessionRepository.CreateSessionAsync(session);

        var repository = GetAuthenticationSessionAdministrationRepository(scope.ServiceProvider);
        var search = await repository.SearchAuthenticationSessionsAsync(new SearchAuthenticationSessionsRequest { Limit = 10 }, Now);
        var detail = await repository.GetAuthenticationSessionAsync(session.Id, Now);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(search.Single().ToString(), Does.Not.Contain("secret-token-hash"));
            Assert.That(detail?.ToString(), Does.Not.Contain("secret-token-hash"));
        }
    }

    private static AuthenticationSession CreateSession(
        Guid userId,
        Guid? id = null,
        string? tokenHash = null,
        DateTimeOffset? createdAt = null,
        DateTimeOffset? expiresAt = null,
        Guid? tenantId = null)
    {
        return new AuthenticationSession
        {
            Id = id ?? Guid.NewGuid(),
            UserId = userId,
            TenantId = tenantId,
            TokenHash = tokenHash ?? $"sha256:{Guid.NewGuid():N}",
            CreatedAt = createdAt ?? BaseTime,
            ExpiresAt = expiresAt ?? BaseTime.AddDays(1)
        };
    }
}
