using Ashlar.Auditing;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Identity.Features.Mfa;

internal sealed class RememberedMfaDeviceServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 6, 2, 12, 0, 0, TimeSpan.Zero);
    private static readonly string[] ExpectedDisplayNames = ["laptop", "phone"];

    [Test]
    public async Task CreateAsyncStoresOnlyHashedVerifierAndReturnsRawTokenOnce()
    {
        var fixture = CreateFixture(generator: new SequenceTokenGenerator("selector-token", "verifier-token"));
        var user = fixture.Users.AddUser();

        var result = await fixture.Service.CreateAsync(user.Id, new CreateRememberedMfaDeviceRequest { DisplayName = " laptop " });

        Assert.That(result.Succeeded, Is.True);
        var stored = fixture.Repository.Devices.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value!.Token, Is.EqualTo("selector-token.verifier-token"));
            Assert.That(result.Value.Device.DisplayName, Is.EqualTo("laptop"));
            Assert.That(stored.TokenSelector, Is.EqualTo("selector-token"));
            Assert.That(stored.TokenHash, Is.EqualTo(fixture.Hasher.HashToken("verifier-token")));
            Assert.That(stored.TokenHash, Is.Not.EqualTo("verifier-token"));
            Assert.That(stored.DisplayName, Is.EqualTo("laptop"));
            Assert.That(fixture.Events.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.RememberedMfaDeviceCreated));
        }
    }

    [Test]
    public async Task ValidateAsyncAcceptsActiveOwnedDeviceAndUpdatesLastUsed()
    {
        var fixture = CreateFixture(generator: new SequenceTokenGenerator("selector", "verifier"));
        var user = fixture.Users.AddUser();
        var created = await fixture.Service.CreateAsync(user.Id, new CreateRememberedMfaDeviceRequest());
        fixture.Events.Events.Clear();

        var result = await fixture.Service.ValidateAsync(user.Id, new ValidateRememberedMfaDeviceRequest(created.Value!.Token));
        var repeated = await fixture.Service.ValidateAsync(user.Id, new ValidateRememberedMfaDeviceRequest(created.Value.Token));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(repeated.Succeeded, Is.True);
            Assert.That(result.Status, Is.EqualTo(RememberedMfaDeviceValidationStatus.Success));
            Assert.That(result.Device!.LastUsedAt, Is.EqualTo(Now));
            Assert.That(fixture.Repository.Devices.Single().LastUsedAt, Is.EqualTo(Now));
            Assert.That(fixture.Events.Events.Select(e => e.EventType), Is.EqualTo(new[] { AshlarSecurityEventTypes.RememberedMfaDeviceUsed, AshlarSecurityEventTypes.RememberedMfaDeviceUsed }));
        }
    }

    [Test]
    public async Task ValidateAsyncRejectsMalformedMissingExpiredRevokedWrongUserAndWrongTenant()
    {
        var fixture = CreateFixture(generator: new SequenceTokenGenerator("selector", "verifier", "expired", "expired-verifier", "revoked", "revoked-verifier", "tenant", "tenant-verifier"));
        var user = fixture.Users.AddUser();
        var other = fixture.Users.AddUser();
        var tenantId = Guid.NewGuid();
        var tenantUser = fixture.Users.AddUser(tenantId);
        var active = await fixture.Service.CreateAsync(user.Id, new CreateRememberedMfaDeviceRequest());
        var expired = await fixture.Service.CreateAsync(user.Id, new CreateRememberedMfaDeviceRequest { Lifetime = TimeSpan.FromMinutes(1) });
        var revoked = await fixture.Service.CreateAsync(user.Id, new CreateRememberedMfaDeviceRequest());
        var tenant = await fixture.Service.CreateAsync(tenantUser.Id, new CreateRememberedMfaDeviceRequest { Tenant = new TenantContext(tenantId) });
        fixture.Time.Advance(TimeSpan.FromMinutes(2));
        await fixture.Service.RevokeAsync(user.Id, new RevokeRememberedMfaDeviceRequest(fixture.Repository.Devices.Single(d => d.TokenSelector == "revoked").Id));
        fixture.Events.Events.Clear();

        var malformed = await fixture.Service.ValidateAsync(user.Id, new ValidateRememberedMfaDeviceRequest("not-a-selector-token"));
        var missing = await fixture.Service.ValidateAsync(user.Id, new ValidateRememberedMfaDeviceRequest("missing.verifier"));
        var expiredResult = await fixture.Service.ValidateAsync(user.Id, new ValidateRememberedMfaDeviceRequest(expired.Value!.Token));
        var revokedResult = await fixture.Service.ValidateAsync(user.Id, new ValidateRememberedMfaDeviceRequest(revoked.Value!.Token));
        var wrongUser = await fixture.Service.ValidateAsync(other.Id, new ValidateRememberedMfaDeviceRequest(active.Value!.Token));
        var wrongTenant = await fixture.Service.ValidateAsync(tenantUser.Id, new ValidateRememberedMfaDeviceRequest(tenant.Value!.Token));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(malformed.Status, Is.EqualTo(RememberedMfaDeviceValidationStatus.Failed));
            Assert.That(missing.Status, Is.EqualTo(RememberedMfaDeviceValidationStatus.Failed));
            Assert.That(expiredResult.Status, Is.EqualTo(RememberedMfaDeviceValidationStatus.Expired));
            Assert.That(revokedResult.Status, Is.EqualTo(RememberedMfaDeviceValidationStatus.Revoked));
            Assert.That(wrongUser.Status, Is.EqualTo(RememberedMfaDeviceValidationStatus.Failed));
            Assert.That(wrongTenant.Status, Is.EqualTo(RememberedMfaDeviceValidationStatus.Failed));
            Assert.That(fixture.Events.Events, Has.All.Matches<AshlarSecurityEvent>(e => e.EventType == AshlarSecurityEventTypes.RememberedMfaDeviceRejected));
            Assert.That(
                fixture.Events.Events.Single(e => e.FailureReason == RememberedMfaDeviceValidationStatus.WrongUser.ToString()).Properties?["remembered_device_id"],
                Is.EqualTo(active.Value!.Device.Id.ToString("D")));
            Assert.That(
                fixture.Events.Events.Single(e => e.FailureReason == RememberedMfaDeviceValidationStatus.WrongTenant.ToString()).Properties?["remembered_device_id"],
                Is.EqualTo(tenant.Value!.Device.Id.ToString("D")));
        }
    }

    [Test]
    public async Task ListAndRevocationExposeOnlySafeMetadata()
    {
        var fixture = CreateFixture(generator: new SequenceTokenGenerator("selector", "verifier", "second", "second-verifier"));
        var user = fixture.Users.AddUser();
        var first = await fixture.Service.CreateAsync(user.Id, new CreateRememberedMfaDeviceRequest { DisplayName = "laptop" });
        var second = await fixture.Service.CreateAsync(user.Id, new CreateRememberedMfaDeviceRequest { DisplayName = "phone" });

        var revoked = await fixture.Service.RevokeAsync(user.Id, new RevokeRememberedMfaDeviceRequest(first.Value!.Device.Id) { Reason = " user " });
        var summaries = await fixture.Service.ListAsync(user.Id, new ListRememberedMfaDevicesRequest { ActiveOnly = false });
        var count = await fixture.Service.RevokeAllAsync(user.Id, new RevokeAllRememberedMfaDevicesRequest { Reason = " " });
        var revokedEvent = fixture.Events.Events.Single(e => e.EventType == AshlarSecurityEventTypes.RememberedMfaDeviceRevoked);
        var revokeAllEvent = fixture.Events.Events.Single(e => e.EventType == AshlarSecurityEventTypes.RememberedMfaDevicesRevoked);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revoked, Is.True);
            Assert.That(count, Is.EqualTo(1));
            Assert.That(summaries, Has.Count.EqualTo(2));
            Assert.That(summaries.Select(s => s.DisplayName), Is.EquivalentTo(ExpectedDisplayNames));
            Assert.That(summaries.Select(s => s.ToString()), Has.None.Contains("verifier"));
            Assert.That(summaries.Select(s => s.ToString()), Has.None.Contains("selector"));
            Assert.That(fixture.Repository.Devices.Single(d => d.Id == first.Value!.Device.Id).RevocationReason, Is.EqualTo("user"));
            Assert.That(fixture.Repository.Devices.Single(d => d.Id == second.Value!.Device.Id).RevocationReason, Is.Null);
            Assert.That(revokedEvent.Properties?["reason"], Is.EqualTo("user"));
            Assert.That(revokeAllEvent.Properties?.ContainsKey("reason"), Is.False);
            Assert.That(fixture.Events.Events.Select(e => e.EventType), Does.Contain(AshlarSecurityEventTypes.RememberedMfaDeviceRevoked));
            Assert.That(fixture.Events.Events.Select(e => e.EventType), Does.Contain(AshlarSecurityEventTypes.RememberedMfaDevicesRevoked));
        }
    }

    [Test]
    public async Task TenantValidationFailureAuditsSafely()
    {
        var fixture = CreateFixture();
        var user = fixture.Users.AddUser(Guid.NewGuid());

        var result = await fixture.Service.CreateAsync(user.Id, new CreateRememberedMfaDeviceRequest { Tenant = TenantContext.Global });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            Assert.That(fixture.Events.Events.Single().FailureReason, Is.EqualTo(AshlarFailureCodes.TenantMismatchValue));
            Assert.That(fixture.Repository.Devices, Is.Empty);
        }
    }

    [Test]
    public async Task RevokeAllAsyncNormalizesNonBlankReason()
    {
        var fixture = CreateFixture(generator: new SequenceTokenGenerator("selector", "verifier"));
        var user = fixture.Users.AddUser();
        var created = await fixture.Service.CreateAsync(user.Id, new CreateRememberedMfaDeviceRequest());
        fixture.Events.Events.Clear();

        var count = await fixture.Service.RevokeAllAsync(user.Id, new RevokeAllRememberedMfaDevicesRequest { Reason = " reset " });
        var revokeAllEvent = fixture.Events.Events.Single();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(count, Is.EqualTo(1));
            Assert.That(fixture.Repository.Devices.Single(d => d.Id == created.Value!.Device.Id).RevocationReason, Is.EqualTo("reset"));
            Assert.That(revokeAllEvent.Properties?["reason"], Is.EqualTo("reset"));
        }
    }

    [Test]
    public async Task CreateAsyncRejectsDeviceLimitAndInvalidLifetimeSafely()
    {
        var fixture = CreateFixture(
            generator: new SequenceTokenGenerator("selector", "verifier"),
            options: new RememberedMfaDeviceOptions { MaxActiveDevicesPerUser = 1 });
        var user = fixture.Users.AddUser();
        var overflowFixture = CreateFixture();
        var overflowUser = overflowFixture.Users.AddUser();
        overflowFixture.Time.SetUtcNow(DateTimeOffset.MaxValue.AddDays(-1));
        var first = await fixture.Service.CreateAsync(user.Id, new CreateRememberedMfaDeviceRequest());

        fixture.Events.Events.Clear();
        var limited = await fixture.Service.CreateAsync(user.Id, new CreateRememberedMfaDeviceRequest());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(first.Succeeded, Is.True);
            Assert.That(limited.Succeeded, Is.False);
            Assert.That(limited.FailureCode, Is.EqualTo(AshlarFailureCodes.RememberedMfaDeviceLimitExceeded));
            Assert.That(fixture.Repository.Devices, Has.Count.EqualTo(1));
            Assert.That(fixture.Events.Events.Single().FailureReason, Is.EqualTo(AshlarFailureCodes.RememberedMfaDeviceLimitExceededValue));
            Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => fixture.Service.CreateAsync(user.Id, new CreateRememberedMfaDeviceRequest { Lifetime = TimeSpan.FromDays(366) }));
            Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => fixture.Service.CreateAsync(user.Id, new CreateRememberedMfaDeviceRequest { Lifetime = TimeSpan.MaxValue }));
            Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => overflowFixture.Service.CreateAsync(overflowUser.Id, new CreateRememberedMfaDeviceRequest { Lifetime = TimeSpan.FromDays(2) }));
        }
    }

    [Test]
    public async Task InvalidInputsAndOptionsAreRejected()
    {
        var fixture = CreateFixture();
        var user = fixture.Users.AddUser();

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentException>(() => fixture.Service.CreateAsync(Guid.Empty, new CreateRememberedMfaDeviceRequest()));
            Assert.ThrowsAsync<ArgumentNullException>(() => fixture.Service.CreateAsync(user.Id, null!));
            Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => fixture.Service.CreateAsync(user.Id, new CreateRememberedMfaDeviceRequest { Lifetime = TimeSpan.Zero }));
            Assert.ThrowsAsync<ArgumentException>(() => fixture.Service.CreateAsync(user.Id, new CreateRememberedMfaDeviceRequest { DisplayName = new string('x', 129) }));
            Assert.ThrowsAsync<ArgumentException>(() => fixture.Service.RevokeAsync(user.Id, new RevokeRememberedMfaDeviceRequest(Guid.Empty)));
            Assert.ThrowsAsync<ArgumentException>(() => fixture.Service.RevokeAsync(user.Id, new RevokeRememberedMfaDeviceRequest(Guid.NewGuid()) { Reason = new string('x', 513) }));
            Assert.ThrowsAsync<ArgumentException>(() => fixture.Service.RevokeAllAsync(user.Id, new RevokeAllRememberedMfaDevicesRequest { Reason = new string('x', 513) }));
            Assert.Throws<ArgumentException>(() => CreateFixture(options: new RememberedMfaDeviceOptions { DefaultLifetime = TimeSpan.Zero }));
            Assert.Throws<ArgumentException>(() => CreateFixture(options: new RememberedMfaDeviceOptions { DefaultLifetime = TimeSpan.FromDays(2), MaxLifetime = TimeSpan.FromDays(1) }));
            Assert.Throws<ArgumentException>(() => CreateFixture(options: new RememberedMfaDeviceOptions { MaxActiveDevicesPerUser = 0 }));
        }
    }

    [Test]
    public async Task BlankDisplayNameInvalidTokensFailedRevocationAndLastUsedMissAreCovered()
    {
        var fixture = CreateFixture(generator: new SequenceTokenGenerator("selector", "verifier"));
        var user = fixture.Users.AddUser();
        var created = await fixture.Service.CreateAsync(user.Id, new CreateRememberedMfaDeviceRequest { DisplayName = " " });
        fixture.Repository.FailLastUsedUpdate = true;
        fixture.Events.Events.Clear();

        var nullToken = await fixture.Service.ValidateAsync(user.Id, new ValidateRememberedMfaDeviceRequest(null!));
        var emptySelector = await fixture.Service.ValidateAsync(user.Id, new ValidateRememberedMfaDeviceRequest(".verifier"));
        var whitespaceSelector = await fixture.Service.ValidateAsync(user.Id, new ValidateRememberedMfaDeviceRequest(" .verifier"));
        var overlongToken = $"{new string('s', 513)}.verifier";
        var overlongSelector = await fixture.Service.ValidateAsync(user.Id, new ValidateRememberedMfaDeviceRequest(overlongToken));
        var oversizedToken = await fixture.Service.ValidateAsync(user.Id, new ValidateRememberedMfaDeviceRequest(new string('t', 1026)));
        var emptyVerifier = await fixture.Service.ValidateAsync(user.Id, new ValidateRememberedMfaDeviceRequest("selector."));
        var tooManyParts = await fixture.Service.ValidateAsync(user.Id, new ValidateRememberedMfaDeviceRequest("a.b.c"));
        var failedLastUsedUpdate = await fixture.Service.ValidateAsync(user.Id, new ValidateRememberedMfaDeviceRequest(created.Value!.Token));
        var missingRevoke = await fixture.Service.RevokeAsync(user.Id, new RevokeRememberedMfaDeviceRequest(Guid.NewGuid()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(created.Value.Device.DisplayName, Is.Null);
            Assert.That(nullToken.Status, Is.EqualTo(RememberedMfaDeviceValidationStatus.Failed));
            Assert.That(emptySelector.Status, Is.EqualTo(RememberedMfaDeviceValidationStatus.Failed));
            Assert.That(whitespaceSelector.Status, Is.EqualTo(RememberedMfaDeviceValidationStatus.Failed));
            Assert.That(overlongSelector.Status, Is.EqualTo(RememberedMfaDeviceValidationStatus.Failed));
            Assert.That(oversizedToken.Status, Is.EqualTo(RememberedMfaDeviceValidationStatus.Failed));
            Assert.That(emptyVerifier.Status, Is.EqualTo(RememberedMfaDeviceValidationStatus.Failed));
            Assert.That(tooManyParts.Status, Is.EqualTo(RememberedMfaDeviceValidationStatus.Failed));
            Assert.That(failedLastUsedUpdate.Status, Is.EqualTo(RememberedMfaDeviceValidationStatus.Failed));
            Assert.That(missingRevoke, Is.False);
        }
    }

    [Test]
    public async Task ValidateAsyncAuditsKnownDeviceOnVerifierMismatchWithoutSecrets()
    {
        var fixture = CreateFixture(generator: new SequenceTokenGenerator("selector", "verifier"));
        var user = fixture.Users.AddUser();
        var created = await fixture.Service.CreateAsync(user.Id, new CreateRememberedMfaDeviceRequest());
        fixture.Events.Events.Clear();

        var mismatch = await fixture.Service.ValidateAsync(user.Id, new ValidateRememberedMfaDeviceRequest("selector.wrong-verifier"));
        fixture.Repository.Devices[0] = fixture.Repository.Devices[0] with { TokenHash = "short" };
        var malformedStoredHash = await fixture.Service.ValidateAsync(user.Id, new ValidateRememberedMfaDeviceRequest(created.Value!.Token));

        var events = fixture.Events.Events;
        using (Assert.EnterMultipleScope())
        {
            Assert.That(mismatch.Status, Is.EqualTo(RememberedMfaDeviceValidationStatus.Failed));
            Assert.That(malformedStoredHash.Status, Is.EqualTo(RememberedMfaDeviceValidationStatus.Failed));
            Assert.That(events, Has.Count.EqualTo(2));
            Assert.That(events, Has.All.Matches<AshlarSecurityEvent>(e => e.Properties?["remembered_device_id"] == created.Value.Device.Id.ToString("D")));
            Assert.That(events.SelectMany(e => e.Properties?.Values ?? []), Does.Not.Contain(created.Value.Token));
            Assert.That(events.SelectMany(e => e.Properties?.Values ?? []), Does.Not.Contain("selector"));
            Assert.That(events.SelectMany(e => e.Properties?.Values ?? []), Does.Not.Contain("wrong-verifier"));
            Assert.That(events.SelectMany(e => e.Properties?.Values ?? []), Does.Not.Contain(fixture.Hasher.HashToken("verifier")));
        }
    }

    [Test]
    public void ConstructorRejectsNullDependenciesAndSupportsDefaults()
    {
        var repository = new InMemoryRememberedMfaDeviceRepository();
        var users = new InMemoryUserRepository();
        var generator = new SequenceTokenGenerator("selector", "verifier");
        var hasher = new Sha256TokenHasher();
        var transactions = new NullTransactionProvider();

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => new RememberedMfaDeviceService(null!, users, generator, hasher, transactions, new RememberedMfaDeviceServiceDependencies()));
            Assert.Throws<ArgumentNullException>(() => new RememberedMfaDeviceService(repository, null!, generator, hasher, transactions, new RememberedMfaDeviceServiceDependencies()));
            Assert.Throws<ArgumentNullException>(() => new RememberedMfaDeviceService(repository, users, null!, hasher, transactions, new RememberedMfaDeviceServiceDependencies()));
            Assert.Throws<ArgumentNullException>(() => new RememberedMfaDeviceService(repository, users, generator, null!, transactions, new RememberedMfaDeviceServiceDependencies()));
            Assert.Throws<ArgumentNullException>(() => new RememberedMfaDeviceService(repository, users, generator, hasher, null!, new RememberedMfaDeviceServiceDependencies()));
            Assert.Throws<ArgumentNullException>(() => new RememberedMfaDeviceService(repository, users, generator, hasher, transactions, null!));
            Assert.DoesNotThrow(() => new RememberedMfaDeviceService(repository, users, generator, hasher, transactions, new RememberedMfaDeviceServiceDependencies(), Mock.Of<ILogger<RememberedMfaDeviceService>>()));
        }
    }

    [Test]
    public async Task EmptyUserIdsAndNullRequestsAreRejected()
    {
        var fixture = CreateFixture();
        var user = fixture.Users.AddUser();

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentException>(() => fixture.Service.ValidateAsync(Guid.Empty, new ValidateRememberedMfaDeviceRequest("token")));
            Assert.ThrowsAsync<ArgumentNullException>(() => fixture.Service.ValidateAsync(user.Id, null!));
            Assert.ThrowsAsync<ArgumentException>(() => fixture.Service.ListAsync(Guid.Empty, new ListRememberedMfaDevicesRequest()));
            Assert.ThrowsAsync<ArgumentNullException>(() => fixture.Service.ListAsync(user.Id, null!));
            Assert.ThrowsAsync<ArgumentException>(() => fixture.Service.RevokeAsync(Guid.Empty, new RevokeRememberedMfaDeviceRequest(Guid.NewGuid())));
            Assert.ThrowsAsync<ArgumentNullException>(() => fixture.Service.RevokeAsync(user.Id, null!));
            Assert.ThrowsAsync<ArgumentException>(() => fixture.Service.RevokeAllAsync(Guid.Empty, new RevokeAllRememberedMfaDevicesRequest()));
            Assert.ThrowsAsync<ArgumentNullException>(() => fixture.Service.RevokeAllAsync(user.Id, null!));
        }
    }

    [Test]
    public async Task TenantScopedValidationAndWhitespaceVerifierBranchesAreCovered()
    {
        var tenantId = Guid.NewGuid();
        var fixture = CreateFixture(generator: new SequenceTokenGenerator("tenant-selector", "tenant-verifier"));
        var user = fixture.Users.AddUser(tenantId);
        var created = await fixture.Service.CreateAsync(user.Id, new CreateRememberedMfaDeviceRequest { Tenant = new TenantContext(tenantId) });

        var valid = await fixture.Service.ValidateAsync(user.Id, new ValidateRememberedMfaDeviceRequest(created.Value!.Token) { Tenant = new TenantContext(tenantId) });
        var whitespaceVerifier = await fixture.Service.ValidateAsync(user.Id, new ValidateRememberedMfaDeviceRequest("tenant-selector. "));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(valid.Succeeded, Is.True);
            Assert.That(whitespaceVerifier.Status, Is.EqualTo(RememberedMfaDeviceValidationStatus.Failed));
        }
    }

    private static Fixture CreateFixture(SequenceTokenGenerator? generator = null, RememberedMfaDeviceOptions? options = null)
    {
        var repository = new InMemoryRememberedMfaDeviceRepository();
        var users = new InMemoryUserRepository();
        var events = new RecordingSecurityEventSink();
        var time = new FakeTimeProvider(Now);
        var hasher = new Sha256TokenHasher();
        var service = new RememberedMfaDeviceService(
            repository,
            users,
            generator ?? new SequenceTokenGenerator("selector", "verifier"),
            hasher,
            new NullTransactionProvider(),
            new RememberedMfaDeviceServiceDependencies(
                Options.Create(options ?? new RememberedMfaDeviceOptions()),
                time,
                events));
        return new Fixture(service, repository, users, events, time, hasher);
    }

    private sealed record Fixture(
        RememberedMfaDeviceService Service,
        InMemoryRememberedMfaDeviceRepository Repository,
        InMemoryUserRepository Users,
        RecordingSecurityEventSink Events,
        FakeTimeProvider Time,
        ISecureTokenHasher Hasher);

    private sealed class SequenceTokenGenerator(params string[] tokens) : ISecureTokenGenerator
    {
        private readonly Queue<string> _tokens = new(tokens);

        public string GenerateToken(int byteLength = ISecureTokenGenerator.DefaultByteLength)
        {
            return _tokens.Count == 0 ? Guid.NewGuid().ToString("N") : _tokens.Dequeue();
        }
    }

    private sealed class RecordingSecurityEventSink : ISecurityEventSink
    {
        public List<AshlarSecurityEvent> Events { get; } = [];

        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            Events.Add(securityEvent);
            return Task.CompletedTask;
        }
    }

    private sealed class InMemoryUserRepository : IUserRepository
    {
        private readonly List<User> _users = [];

        public User AddUser(Guid? tenantId = null)
        {
            var user = new User { Id = Guid.NewGuid(), Email = $"{Guid.NewGuid():N}@example.com", TenantId = tenantId };
            _users.Add(user);
            return user;
        }

        public Task CreateUserAsync(IUser user, CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<IUser?> GetUserByEmailAsync(string normalizedEmail, Guid? tenantId = null, CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<IUser?> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IUser?>(_users.SingleOrDefault(user => user.Id == userId));
        }

        public Task<IUser?> GetUserByProviderKeyAsync(ProviderType type, string providerName, string providerKey, CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task UpdateUserAsync(IUser user, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }

    private sealed class InMemoryRememberedMfaDeviceRepository : IRememberedMfaDeviceRepository
    {
        public List<RememberedMfaDevice> Devices { get; } = [];
        public bool FailLastUsedUpdate { get; set; }

        public Task CreateAsync(RememberedMfaDevice device, CancellationToken cancellationToken = default)
        {
            Devices.Add(device);
            return Task.CompletedTask;
        }

        public Task<RememberedMfaDevice?> GetByTokenSelectorAsync(string tokenSelector, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Devices.SingleOrDefault(device => device.TokenSelector == tokenSelector));
        }

        public Task<RememberedMfaDevice?> GetAsync(Guid deviceId, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Devices.SingleOrDefault(device => device.Id == deviceId));
        }

        public Task<bool> UpdateLastUsedAsync(Guid deviceId, DateTimeOffset lastUsedAt, CancellationToken cancellationToken = default)
        {
            if (FailLastUsedUpdate) return Task.FromResult(false);
            var device = Devices.SingleOrDefault(device => device.Id == deviceId && device.RevokedAt == null && device.ExpiresAt > lastUsedAt);
            if (device == null) return Task.FromResult(false);
            if (device.LastUsedAt == null || device.LastUsedAt < lastUsedAt)
            {
                device.LastUsedAt = lastUsedAt;
            }

            return Task.FromResult(true);
        }

        public Task<IReadOnlyList<RememberedMfaDevice>> ListForUserAsync(Guid userId, TenantContext? tenant, bool activeOnly, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            var query = Devices.Where(device => device.UserId == userId && (tenant == null || device.TenantId == tenant.TenantId));
            if (activeOnly)
            {
                query = query.Where(device => device.IsActive(now));
            }

            return Task.FromResult<IReadOnlyList<RememberedMfaDevice>>(query.OrderByDescending(device => device.CreatedAt).ToList());
        }

        public Task<int> CountForUserAsync(Guid userId, TenantContext? tenant, bool activeOnly, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            var query = Devices.Where(device => device.UserId == userId && (tenant == null || device.TenantId == tenant.TenantId));
            if (activeOnly)
            {
                query = query.Where(device => device.IsActive(now));
            }

            return Task.FromResult(query.Count());
        }

        public Task<bool> RevokeAsync(Guid deviceId, Guid userId, DateTimeOffset revokedAt, string? reason = null, TenantContext? tenant = null, CancellationToken cancellationToken = default)
        {
            var device = Devices.SingleOrDefault(device => device.Id == deviceId && device.UserId == userId && device.RevokedAt == null && (tenant == null || device.TenantId == tenant.TenantId));
            if (device == null) return Task.FromResult(false);
            device.RevokedAt = revokedAt;
            device.RevocationReason = reason;
            return Task.FromResult(true);
        }

        public Task<int> RevokeAllForUserAsync(Guid userId, DateTimeOffset revokedAt, string? reason = null, TenantContext? tenant = null, CancellationToken cancellationToken = default)
        {
            var devices = Devices.Where(device => device.UserId == userId && device.RevokedAt == null && (tenant == null || device.TenantId == tenant.TenantId)).ToList();
            foreach (var device in devices)
            {
                device.RevokedAt = revokedAt;
                device.RevocationReason = reason;
            }

            return Task.FromResult(devices.Count);
        }
    }
}
