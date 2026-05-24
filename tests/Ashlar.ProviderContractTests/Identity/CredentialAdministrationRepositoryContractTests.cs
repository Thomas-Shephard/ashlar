namespace Ashlar.ProviderContractTests.Identity;

internal abstract class CredentialAdministrationRepositoryContractTests : ProviderContractFixture
{
    private static readonly DateTimeOffset BaseTime = new(2026, 6, 2, 12, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Now = BaseTime.AddHours(1);

    [Test]
    public async Task SearchCredentialsSearchesAcrossMultipleUsersAndFiltersByUser()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var firstUser = await CreateUserAsync(identityRepository);
        var secondUser = await CreateUserAsync(identityRepository);
        var first = CreateCredential(firstUser.Id, AuthenticationProviderKey.Local, createdAt: BaseTime.AddMinutes(1));
        var second = CreateCredential(secondUser.Id, AuthenticationProviderKey.MagicLink, createdAt: BaseTime.AddMinutes(2));
        await identityRepository.CreateCredentialAsync(first);
        await identityRepository.CreateCredentialAsync(second);

        var repository = GetCredentialAdministrationRepository(scope.ServiceProvider);
        var all = await repository.SearchCredentialsAsync(new SearchCredentialsRequest { Limit = 10 }, Now);
        var filtered = await repository.SearchCredentialsAsync(new SearchCredentialsRequest { UserId = firstUser.Id, Limit = 10 }, Now);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(all.Select(static credential => credential.CredentialId), Does.Contain(first.Id));
            Assert.That(all.Select(static credential => credential.CredentialId), Does.Contain(second.Id));
            Assert.That(filtered.Select(static credential => credential.CredentialId), Is.EqualTo(new[] { first.Id }));
        }
    }

    [Test]
    public async Task SearchCredentialsFiltersTenantScopes()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var tenantId = Guid.NewGuid();
        var tenantUser = await CreateUserAsync(identityRepository, tenantId: tenantId);
        var globalUser = await CreateUserAsync(identityRepository);
        var otherTenantUser = await CreateUserAsync(identityRepository, tenantId: Guid.NewGuid());
        var tenantCredential = CreateCredential(tenantUser.Id, AuthenticationProviderKey.Local);
        var globalCredential = CreateCredential(globalUser.Id, AuthenticationProviderKey.MagicLink);
        var otherTenantCredential = CreateCredential(otherTenantUser.Id, AuthenticationProviderKey.Passkey);
        await identityRepository.CreateCredentialAsync(tenantCredential);
        await identityRepository.CreateCredentialAsync(globalCredential);
        await identityRepository.CreateCredentialAsync(otherTenantCredential);

        var repository = GetCredentialAdministrationRepository(scope.ServiceProvider);
        var scoped = await repository.SearchCredentialsAsync(new SearchCredentialsRequest { Tenant = new TenantContext(tenantId), Limit = 10 }, Now);
        var global = await repository.SearchCredentialsAsync(new SearchCredentialsRequest { Tenant = TenantContext.Global, Limit = 10 }, Now);
        var unscoped = await repository.SearchCredentialsAsync(new SearchCredentialsRequest { Limit = 10 }, Now);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scoped.Select(static credential => credential.CredentialId), Is.EqualTo(new[] { tenantCredential.Id }));
            Assert.That(scoped.Single().TenantId, Is.EqualTo(tenantId));
            Assert.That(global.Select(static credential => credential.CredentialId), Is.EqualTo(new[] { globalCredential.Id }));
            Assert.That(global.Single().TenantId, Is.Null);
            Assert.That(unscoped.Select(static credential => credential.CredentialId), Does.Contain(tenantCredential.Id));
            Assert.That(unscoped.Select(static credential => credential.CredentialId), Does.Contain(globalCredential.Id));
            Assert.That(unscoped.Select(static credential => credential.CredentialId), Does.Contain(otherTenantCredential.Id));
        }
    }

    [Test]
    public async Task SearchCredentialsFiltersByProviderPurposeAndStatus()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identityRepository);
        var matching = CreateCredential(user.Id, AuthenticationProviderKey.Passkey, purpose: "mfa", createdAt: BaseTime.AddMinutes(3));
        var wrongProvider = CreateCredential(user.Id, AuthenticationProviderKey.Local, purpose: "mfa", createdAt: BaseTime.AddMinutes(2));
        var wrongPurpose = CreateCredential(user.Id, AuthenticationProviderKey.Passkey, purpose: "primary", createdAt: BaseTime.AddMinutes(1));
        var revoked = CreateCredential(user.Id, AuthenticationProviderKey.Passkey, purpose: "mfa", status: CredentialStatus.Revoked, revokedAt: BaseTime.AddMinutes(4));
        await identityRepository.CreateCredentialAsync(matching);
        await identityRepository.CreateCredentialAsync(wrongProvider);
        await identityRepository.CreateCredentialAsync(wrongPurpose);
        await identityRepository.CreateCredentialAsync(revoked);

        var repository = GetCredentialAdministrationRepository(scope.ServiceProvider);
        var active = await repository.SearchCredentialsAsync(new SearchCredentialsRequest
        {
            Provider = AuthenticationProviderKey.Passkey,
            Purpose = "mfa",
            Status = CredentialStatus.Active,
            Limit = 10
        }, Now);
        var revokedResult = await repository.SearchCredentialsAsync(new SearchCredentialsRequest { Status = CredentialStatus.Revoked, Limit = 10 }, Now);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(active.Select(static credential => credential.CredentialId), Is.EqualTo(new[] { matching.Id }));
            Assert.That(active.Single().Provider, Is.EqualTo(AuthenticationProviderKey.Passkey));
            Assert.That(active.Single().Purpose, Is.EqualTo("mfa"));
            Assert.That(active.Single().Status, Is.EqualTo(CredentialStatus.Active));
            Assert.That(revokedResult.Select(static credential => credential.CredentialId), Is.EqualTo(new[] { revoked.Id }));
        }
    }

    [Test]
    public async Task SearchCredentialsFiltersAvailableUnavailableAndRevokedCorrectly()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identityRepository);
        var active = CreateCredential(user.Id, AuthenticationProviderKey.Local, createdAt: BaseTime.AddMinutes(1));
        var noExpiry = CreateCredential(user.Id, AuthenticationProviderKey.MagicLink, createdAt: BaseTime.AddMinutes(2));
        var expired = CreateCredential(user.Id, AuthenticationProviderKey.Passkey, expiresAt: Now.AddMilliseconds(-1), createdAt: BaseTime.AddMinutes(3));
        var revoked = CreateCredential(user.Id, new AuthenticationProviderKey(ProviderType.Mfa, "totp"), status: CredentialStatus.Revoked, revokedAt: BaseTime.AddMinutes(4), createdAt: BaseTime.AddMinutes(4));
        active.ExpiresAt = Now.AddDays(1);
        await identityRepository.CreateCredentialAsync(active);
        await identityRepository.CreateCredentialAsync(noExpiry);
        await identityRepository.CreateCredentialAsync(expired);
        await identityRepository.CreateCredentialAsync(revoked);

        var repository = GetCredentialAdministrationRepository(scope.ServiceProvider);
        var available = await repository.SearchCredentialsAsync(new SearchCredentialsRequest { Available = true, Limit = 10 }, Now);
        var unavailable = await repository.SearchCredentialsAsync(new SearchCredentialsRequest { Available = false, Limit = 10 }, Now);
        var revokedResult = await repository.SearchCredentialsAsync(new SearchCredentialsRequest { Revoked = true, Limit = 10 }, Now);
        var unrevoked = await repository.SearchCredentialsAsync(new SearchCredentialsRequest { Revoked = false, Limit = 10 }, Now);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(available.Select(static credential => credential.CredentialId), Is.EquivalentTo(new[] { active.Id, noExpiry.Id }));
            Assert.That(unavailable.Select(static credential => credential.CredentialId), Is.EquivalentTo(new[] { expired.Id, revoked.Id }));
            Assert.That(revokedResult.Select(static credential => credential.CredentialId), Is.EqualTo(new[] { revoked.Id }));
            Assert.That(unrevoked.Select(static credential => credential.CredentialId), Is.EquivalentTo(new[] { active.Id, noExpiry.Id, expired.Id }));
            Assert.That(available.All(static credential => credential.IsAvailable), Is.True);
            Assert.That(unavailable.All(static credential => !credential.IsAvailable), Is.True);
        }
    }

    [Test]
    public async Task SearchCredentialsFiltersByDateRanges()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identityRepository);
        var matching = CreateCredential(
            user.Id,
            AuthenticationProviderKey.Local,
            createdAt: BaseTime.AddMinutes(10),
            updatedAt: BaseTime.AddMinutes(15),
            lastUsedAt: BaseTime.AddMinutes(20),
            expiresAt: BaseTime.AddHours(3));
        var outsideCreated = CreateCredential(user.Id, AuthenticationProviderKey.EmailCode, createdAt: BaseTime.AddMinutes(1), updatedAt: BaseTime.AddMinutes(15), lastUsedAt: BaseTime.AddMinutes(20), expiresAt: BaseTime.AddHours(3));
        var outsideUpdated = CreateCredential(user.Id, AuthenticationProviderKey.MagicLink, createdAt: BaseTime.AddMinutes(10), updatedAt: BaseTime.AddMinutes(40), lastUsedAt: BaseTime.AddMinutes(20), expiresAt: BaseTime.AddHours(3));
        var outsideLastUsed = CreateCredential(user.Id, AuthenticationProviderKey.Passkey, createdAt: BaseTime.AddMinutes(10), updatedAt: BaseTime.AddMinutes(15), lastUsedAt: BaseTime.AddMinutes(50), expiresAt: BaseTime.AddHours(3));
        var outsideExpires = CreateCredential(user.Id, new AuthenticationProviderKey(ProviderType.Mfa, "totp"), createdAt: BaseTime.AddMinutes(10), updatedAt: BaseTime.AddMinutes(15), lastUsedAt: BaseTime.AddMinutes(20), expiresAt: BaseTime.AddHours(5));
        await identityRepository.CreateCredentialAsync(matching);
        await identityRepository.CreateCredentialAsync(outsideCreated);
        await identityRepository.CreateCredentialAsync(outsideUpdated);
        await identityRepository.CreateCredentialAsync(outsideLastUsed);
        await identityRepository.CreateCredentialAsync(outsideExpires);

        var result = await GetCredentialAdministrationRepository(scope.ServiceProvider).SearchCredentialsAsync(new SearchCredentialsRequest
        {
            CreatedFrom = BaseTime.AddMinutes(5),
            CreatedTo = BaseTime.AddMinutes(15),
            UpdatedFrom = BaseTime.AddMinutes(10),
            UpdatedTo = BaseTime.AddMinutes(30),
            LastUsedFrom = BaseTime.AddMinutes(15),
            LastUsedTo = BaseTime.AddMinutes(25),
            ExpiresFrom = BaseTime.AddHours(2),
            ExpiresTo = BaseTime.AddHours(4),
            Limit = 10
        }, Now);

        Assert.That(result.Select(static credential => credential.CredentialId), Is.EqualTo(new[] { matching.Id }));
    }

    [Test]
    public async Task SearchCredentialsOrdersByLastUsedCreatedAndCredentialIdDescending()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identityRepository);
        var noLastUsed = CreateCredential(user.Id, AuthenticationProviderKey.Local, id: Guid.Parse("00000000-0000-0000-0000-000000000003"), createdAt: BaseTime.AddMinutes(10));
        var olderLastUsed = CreateCredential(user.Id, AuthenticationProviderKey.EmailCode, id: Guid.Parse("00000000-0000-0000-0000-000000000001"), createdAt: BaseTime.AddMinutes(1), lastUsedAt: BaseTime.AddMinutes(20));
        var lowerTie = CreateCredential(user.Id, AuthenticationProviderKey.MagicLink, id: Guid.Parse("00000000-0000-0000-0000-000000000002"), createdAt: BaseTime.AddMinutes(30), lastUsedAt: BaseTime.AddMinutes(30));
        var higherTie = CreateCredential(user.Id, AuthenticationProviderKey.Passkey, id: Guid.Parse("ffffffff-ffff-ffff-ffff-ffffffffffff"), createdAt: BaseTime.AddMinutes(30), lastUsedAt: BaseTime.AddMinutes(30));
        await identityRepository.CreateCredentialAsync(noLastUsed);
        await identityRepository.CreateCredentialAsync(olderLastUsed);
        await identityRepository.CreateCredentialAsync(lowerTie);
        await identityRepository.CreateCredentialAsync(higherTie);

        var result = await GetCredentialAdministrationRepository(scope.ServiceProvider).SearchCredentialsAsync(new SearchCredentialsRequest { Limit = 10 }, Now);

        Assert.That(result.Select(static credential => credential.CredentialId), Is.EqualTo(new[] { higherTie.Id, lowerTie.Id, olderLastUsed.Id, noLastUsed.Id }));
    }

    [Test]
    public async Task GetCredentialReturnsDetailByIdAndMissingReturnsNull()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var tenantId = Guid.NewGuid();
        var user = await CreateUserAsync(identityRepository, tenantId: tenantId);
        var credential = CreateCredential(
            user.Id,
            AuthenticationProviderKey.Passkey,
            providerKey: "provider-secret",
            purpose: "mfa",
            createdAt: BaseTime.AddMinutes(1),
            updatedAt: BaseTime.AddMinutes(2),
            lastUsedAt: BaseTime.AddMinutes(3),
            expiresAt: BaseTime.AddDays(1));
        credential.CredentialValue = "credential-secret";
        credential.Metadata = """{"secret":"not returned"}""";
        credential.Version = "version-secret";
        await identityRepository.CreateCredentialAsync(credential);

        var repository = GetCredentialAdministrationRepository(scope.ServiceProvider);
        var found = await repository.GetCredentialAsync(credential.Id, Now);
        var missing = await repository.GetCredentialAsync(Guid.NewGuid(), Now);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(found?.CredentialId, Is.EqualTo(credential.Id));
            Assert.That(found?.UserId, Is.EqualTo(user.Id));
            Assert.That(found?.TenantId, Is.EqualTo(tenantId));
            Assert.That(found?.Provider, Is.EqualTo(AuthenticationProviderKey.Passkey));
            Assert.That(found?.Purpose, Is.EqualTo("mfa"));
            Assert.That(found?.Status, Is.EqualTo(CredentialStatus.Active));
            Assert.That(found?.IsAvailable, Is.True);
            Assert.That(found?.CreatedAt, Is.EqualTo(credential.CreatedAt));
            Assert.That(found?.UpdatedAt, Is.EqualTo(credential.UpdatedAt));
            Assert.That(found?.LastUsedAt, Is.EqualTo(credential.LastUsedAt));
            Assert.That(found?.ExpiresAt, Is.EqualTo(credential.ExpiresAt));
            Assert.That(found?.RevokedAt, Is.Null);
            Assert.That(missing, Is.Null);
        }
    }

    [Test]
    public async Task CredentialAdministrationDoesNotReturnSensitiveStorageFields()
    {
        await using var scope = CreateAsyncScope();
        var identityRepository = GetIdentityRepository(scope.ServiceProvider);
        var user = await CreateUserAsync(identityRepository);
        var credential = CreateCredential(user.Id, AuthenticationProviderKey.Local, providerKey: "provider-key-secret");
        credential.CredentialValue = "password-hash-secret";
        credential.Metadata = "metadata-secret";
        credential.Version = "version-secret";
        await identityRepository.CreateCredentialAsync(credential);

        var repository = GetCredentialAdministrationRepository(scope.ServiceProvider);
        var search = await repository.SearchCredentialsAsync(new SearchCredentialsRequest { Limit = 10 }, Now);
        var detail = await repository.GetCredentialAsync(credential.Id, Now);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(search.Single().ToString(), Does.Not.Contain("password-hash-secret"));
            Assert.That(search.Single().ToString(), Does.Not.Contain("provider-key-secret"));
            Assert.That(search.Single().ToString(), Does.Not.Contain("metadata-secret"));
            Assert.That(search.Single().ToString(), Does.Not.Contain("version-secret"));
            Assert.That(detail?.ToString(), Does.Not.Contain("password-hash-secret"));
            Assert.That(detail?.ToString(), Does.Not.Contain("provider-key-secret"));
            Assert.That(detail?.ToString(), Does.Not.Contain("metadata-secret"));
            Assert.That(detail?.ToString(), Does.Not.Contain("version-secret"));
        }
    }

    private static UserCredential CreateCredential(
        Guid userId,
        AuthenticationProviderKey provider,
        Guid? id = null,
        string? providerKey = null,
        string? purpose = null,
        CredentialStatus status = CredentialStatus.Active,
        DateTimeOffset? createdAt = null,
        DateTimeOffset? updatedAt = null,
        DateTimeOffset? lastUsedAt = null,
        DateTimeOffset? expiresAt = null,
        DateTimeOffset? revokedAt = null)
    {
        return new UserCredential
        {
            Id = id ?? Guid.NewGuid(),
            UserId = userId,
            ProviderType = provider.Type,
            ProviderName = provider.Name,
            ProviderKey = providerKey ?? $"{provider.Name}-{Guid.NewGuid():N}",
            Version = Guid.NewGuid().ToString("N"),
            CreatedAt = createdAt ?? BaseTime,
            UpdatedAt = updatedAt,
            ExpiresAt = expiresAt,
            RevokedAt = revokedAt,
            LastUsedAt = lastUsedAt,
            Status = status,
            Purpose = purpose
        };
    }
}
