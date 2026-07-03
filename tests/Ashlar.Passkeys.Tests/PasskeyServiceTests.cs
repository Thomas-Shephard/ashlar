using System.Text.Json;
using Ashlar.Auditing;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Passkeys.Tests;

internal sealed class PasskeyServiceTests
{
    [Test]
    public async Task StartRegistrationAsyncShouldCreateChallengeAndRecordAuditEvent()
    {
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Passkey,
            ProviderName = "PASSKEY",
            ProviderKey = "existing",
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active
        };
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var events = new RecordingSecurityEventSink();
        repo.Setup(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(r => r.ListCredentialsForUserAsync(user.Id, true, It.IsAny<CancellationToken>())).ReturnsAsync([credential]);
        validator.Setup(v => v.CreateRegistrationOptions(It.IsAny<PasskeyOptions>(), user, "Passkey", It.IsAny<string>(), It.Is<IReadOnlyList<UserCredential>>(c => c.Count == 1)))
            .Returns("{}");
        PasskeyChallenge? storedChallenge = null;
        challenges.Setup(r => r.CreateAsync(It.IsAny<PasskeyChallenge>(), It.IsAny<CancellationToken>()))
            .Callback<PasskeyChallenge, CancellationToken>((challenge, _) => storedChallenge = challenge)
            .Returns(Task.CompletedTask);
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(securityEventSink: events, authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));
        var audit = new AuditContext(user.Id, "127.0.0.1", "Unit Test", "trace-1");

        var result = await service.StartRegistrationAsync(new StartPasskeyRegistrationRequest(user.Id, " ", Audit: audit));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.OptionsJson, Is.EqualTo("{}"));
            Assert.That(events.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.PasskeyRegistrationStarted));
            Assert.That(events.Events.Single().ActorUserId, Is.EqualTo(user.Id));
            Assert.That(events.Events.Single().IpAddress, Is.EqualTo("127.0.0.1"));
            Assert.That(events.Events.Single().UserAgent, Is.EqualTo("Unit Test"));
            Assert.That(events.Events.Single().CorrelationId, Is.EqualTo("trace-1"));
            Assert.That(storedChallenge?.DisplayName, Is.EqualTo("Passkey"));
        }
    }

    [Test]
    public void StartRegistrationAsyncShouldThrowWhenUserIsMissing()
    {
        var service = new PasskeyService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        Assert.ThrowsAsync<InvalidOperationException>(() => service.StartRegistrationAsync(new StartPasskeyRegistrationRequest(Guid.NewGuid(), "Laptop")));
    }

    [TestCase(UserAccountState.Disabled)]
    [TestCase(UserAccountState.Locked)]
    [TestCase(UserAccountState.Suspended)]
    public void StartRegistrationAsyncShouldRejectUnavailableUsers(UserAccountState accountState)
    {
        var user = new TestUser(Guid.NewGuid(), "test@example.com", AccountState: accountState);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        repo.Setup(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies());

        Assert.ThrowsAsync<InvalidOperationException>(() => service.StartRegistrationAsync(new StartPasskeyRegistrationRequest(user.Id, "Laptop")));
        challenges.Verify(r => r.CreateAsync(It.IsAny<PasskeyChallenge>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task StartRegistrationAsyncShouldAllowTenantUserWithMatchingTenant()
    {
        var tenantId = Guid.NewGuid();
        var user = new TestUser(Guid.NewGuid(), "test@example.com", TenantId: tenantId);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        PasskeyChallenge? storedChallenge = null;
        repo.Setup(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(r => r.ListCredentialsForUserAsync(user.Id, true, It.IsAny<CancellationToken>())).ReturnsAsync([]);
        validator.Setup(v => v.CreateRegistrationOptions(It.IsAny<PasskeyOptions>(), user, "Laptop", It.IsAny<string>(), It.IsAny<IReadOnlyList<UserCredential>>()))
            .Returns("{}");
        challenges.Setup(r => r.CreateAsync(It.IsAny<PasskeyChallenge>(), It.IsAny<CancellationToken>()))
            .Callback<PasskeyChallenge, CancellationToken>((challenge, _) => storedChallenge = challenge)
            .Returns(Task.CompletedTask);
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies());

        var result = await service.StartRegistrationAsync(new StartPasskeyRegistrationRequest(user.Id, "Laptop", new TenantContext(tenantId)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.OptionsJson, Is.EqualTo("{}"));
            Assert.That(storedChallenge?.TenantId, Is.EqualTo(tenantId));
        }
    }

    [Test]
    public void StartRegistrationAsyncShouldRejectTenantUserWithOmittedTenant()
    {
        AssertStartRegistrationTenantFailure(new TestUser(Guid.NewGuid(), "test@example.com", TenantId: Guid.NewGuid()), null);
    }

    [Test]
    public void StartRegistrationAsyncShouldRejectTenantUserWithWrongTenant()
    {
        AssertStartRegistrationTenantFailure(new TestUser(Guid.NewGuid(), "test@example.com", TenantId: Guid.NewGuid()), new TenantContext(Guid.NewGuid()));
    }

    [Test]
    public async Task StartRegistrationAsyncShouldAllowGlobalUserWithOmittedTenant()
    {
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        repo.Setup(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(r => r.ListCredentialsForUserAsync(user.Id, true, It.IsAny<CancellationToken>())).ReturnsAsync([]);
        validator.Setup(v => v.CreateRegistrationOptions(It.IsAny<PasskeyOptions>(), user, "Laptop", It.IsAny<string>(), It.IsAny<IReadOnlyList<UserCredential>>()))
            .Returns("{}");
        challenges.Setup(r => r.CreateAsync(It.IsAny<PasskeyChallenge>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies());

        var result = await service.StartRegistrationAsync(new StartPasskeyRegistrationRequest(user.Id, "Laptop"));

        Assert.That(result.OptionsJson, Is.EqualTo("{}"));
    }

    [Test]
    public void StartRegistrationAsyncShouldRejectGlobalUserWithTenantContext()
    {
        AssertStartRegistrationTenantFailure(new TestUser(Guid.NewGuid(), "test@example.com"), new TenantContext(Guid.NewGuid()));
    }

    [Test]
    public void ConstructorShouldThrowWhenDependenciesAreNull()
    {
        Assert.Throws<ArgumentNullException>(() => _ = new PasskeyService(
            null!,
            new Mock<ICredentialRepository>().Object,
            new Mock<IPasskeyChallengeRepository>().Object,
            new Mock<IPasskeyCeremonyValidator>().Object,
            CreateDependencies()));

        Assert.Throws<ArgumentNullException>(() => _ = new PasskeyService(
            new Mock<IUserRepository>().Object,
            null!,
            new Mock<IPasskeyChallengeRepository>().Object,
            new Mock<IPasskeyCeremonyValidator>().Object,
            CreateDependencies()));

        Assert.Throws<ArgumentNullException>(() => _ = new PasskeyService(
            new Mock<IUserRepository>().Object,
            new Mock<ICredentialRepository>().Object,
            null!,
            new Mock<IPasskeyCeremonyValidator>().Object,
            CreateDependencies()));

        Assert.Throws<ArgumentNullException>(() => _ = new PasskeyService(
            new Mock<IUserRepository>().Object,
            new Mock<ICredentialRepository>().Object,
            new Mock<IPasskeyChallengeRepository>().Object,
            null!,
            CreateDependencies()));

        Assert.Throws<ArgumentNullException>(() => _ = new PasskeyService(
            new Mock<IUserRepository>().Object,
            new Mock<ICredentialRepository>().Object,
            new Mock<IPasskeyChallengeRepository>().Object,
            new Mock<IPasskeyCeremonyValidator>().Object,
            null!));

        Assert.Throws<ArgumentNullException>(() => _ = new PasskeyServiceDependencies(
            Options.Create(new PasskeyOptions { Origin = "https://example.com", RelyingPartyId = "example.com" }),
            null!,
            new Mock<IAuthenticationHandshakeService>().Object,
            new TestTokenHasher(),
            AllowRateLimiter.Instance));
        Assert.Throws<ArgumentNullException>(() => _ = new PasskeyServiceDependencies(
            Options.Create(new PasskeyOptions { Origin = "https://example.com", RelyingPartyId = "example.com" }),
            new Mock<IAuthenticationOrchestrator>().Object,
            null!,
            new TestTokenHasher(),
            AllowRateLimiter.Instance));
        Assert.Throws<ArgumentNullException>(() => _ = new PasskeyServiceDependencies(
            Options.Create(new PasskeyOptions { Origin = "https://example.com", RelyingPartyId = "example.com" }),
            new Mock<IAuthenticationOrchestrator>().Object,
            new Mock<IAuthenticationHandshakeService>().Object,
            null!,
            AllowRateLimiter.Instance));
        Assert.Throws<ArgumentNullException>(() => _ = new PasskeyServiceDependencies(
            Options.Create(new PasskeyOptions { Origin = "https://example.com", RelyingPartyId = "example.com" }),
            new Mock<IAuthenticationOrchestrator>().Object,
            new Mock<IAuthenticationHandshakeService>().Object,
            new TestTokenHasher(),
            null!));
    }

    [Test]
    public async Task CompleteRegistrationAsyncShouldConsumeChallengeAndStoreCredential()
    {
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var clock = new FakeTimeProvider(now);
        var challenge = new PasskeyChallenge
        {
            Id = Guid.NewGuid(),
            Version = "v1",
            Purpose = "passkey-registration",
            UserId = user.Id,
            Challenge = "challenge",
            OptionsJson = "{}",
            RelyingPartyId = "example.com",
            Origin = "https://example.com",
            CreatedAt = now,
            ExpiresAt = now.AddMinutes(5)
        };
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var pipeline = new Mock<IAuthenticationOrchestrator>();
        repo.Setup(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, "v1", It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);
        validator.Setup(v => v.VerifyRegistrationAsync(It.IsAny<PasskeyOptions>(), challenge, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyRegistrationVerificationResult("cred", "pk", 1, ["internal"]));

        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(clock, authenticationOrchestrator: pipeline.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));
        var result = await service.CompleteRegistrationAsync(new CompletePasskeyRegistrationRequest(challenge.Id, JsonDocument.Parse("{}").RootElement, "Laptop"));

        Assert.That(result.Succeeded, Is.True);
        credentials.Verify(r => r.CreateOrReplaceCredentialAsync(It.Is<UserCredential>(c => c.ProviderType == ProviderType.Passkey && c.ProviderKey == "cred"), It.IsAny<CancellationToken>()), Times.Once);
        challenges.Verify(r => r.ConsumeAsync(challenge.Id, "v1", It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [TestCase(UserAccountState.Disabled)]
    [TestCase(UserAccountState.Locked)]
    [TestCase(UserAccountState.Suspended)]
    public async Task CompleteRegistrationAsyncShouldRejectUnavailableUsers(UserAccountState accountState)
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var user = new TestUser(Guid.NewGuid(), "test@example.com", AccountState: accountState);
        var challenge = CreateRegistrationChallenge(now, user.Id);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        repo.Setup(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now)));

        var result = await service.CompleteRegistrationAsync(new CompletePasskeyRegistrationRequest(challenge.Id, JsonDocument.Parse("{}").RootElement));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFoundOrUnavailable));
        challenges.Verify(r => r.ConsumeAsync(It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Never);
        validator.Verify(v => v.VerifyRegistrationAsync(It.IsAny<PasskeyOptions>(), It.IsAny<PasskeyChallenge>(), It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()), Times.Never);
        credentials.Verify(r => r.CreateOrReplaceCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task CompleteRegistrationAsyncShouldRejectMissingChallengeUser()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateRegistrationChallenge(now);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now)));

        var result = await service.CompleteRegistrationAsync(new CompletePasskeyRegistrationRequest(challenge.Id, JsonDocument.Parse("{}").RootElement));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
        challenges.Verify(r => r.ConsumeAsync(It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Never);
        validator.Verify(v => v.VerifyRegistrationAsync(It.IsAny<PasskeyOptions>(), It.IsAny<PasskeyChallenge>(), It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()), Times.Never);
        credentials.Verify(r => r.CreateOrReplaceCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task CompleteRegistrationAsyncShouldAllowTenantUserWithMatchingTenant()
    {
        var tenantId = Guid.NewGuid();
        var result = await CompleteRegistrationForTenantAsync(challengeTenantId: tenantId, userTenantId: tenantId, requestTenant: new TenantContext(tenantId));

        Assert.That(result.Succeeded, Is.True);
    }

    [Test]
    public async Task CompleteRegistrationAsyncShouldRejectTenantUserWithOmittedTenant()
    {
        var tenantId = Guid.NewGuid();
        var result = await CompleteRegistrationForTenantAsync(challengeTenantId: tenantId, userTenantId: tenantId, requestTenant: null);

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
    }

    [Test]
    public async Task CompleteRegistrationAsyncShouldRejectTenantUserWithWrongTenant()
    {
        var tenantId = Guid.NewGuid();
        var result = await CompleteRegistrationForTenantAsync(challengeTenantId: tenantId, userTenantId: tenantId, requestTenant: new TenantContext(Guid.NewGuid()));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
    }

    [Test]
    public async Task CompleteRegistrationAsyncShouldAllowGlobalUserWithOmittedTenant()
    {
        var result = await CompleteRegistrationForTenantAsync(challengeTenantId: null, userTenantId: null, requestTenant: null);

        Assert.That(result.Succeeded, Is.True);
    }

    [Test]
    public async Task CompleteRegistrationAsyncShouldRejectGlobalUserWithTenantContext()
    {
        var result = await CompleteRegistrationForTenantAsync(challengeTenantId: null, userTenantId: null, requestTenant: new TenantContext(Guid.NewGuid()));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
    }

    [Test]
    public async Task CompleteRegistrationAsyncShouldRejectStoredUserTenantMismatch()
    {
        var tenantId = Guid.NewGuid();
        var result = await CompleteRegistrationForTenantAsync(challengeTenantId: tenantId, userTenantId: Guid.NewGuid(), requestTenant: new TenantContext(tenantId));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
    }

    [Test]
    public async Task CompleteRegistrationAsyncShouldRejectReplayedChallenge()
    {
        var now = DateTimeOffset.UtcNow;
        var challenge = new PasskeyChallenge
        {
            Id = Guid.NewGuid(),
            Version = "v1",
            Purpose = "passkey-registration",
            UserId = Guid.NewGuid(),
            Challenge = "challenge",
            OptionsJson = "{}",
            RelyingPartyId = "example.com",
            Origin = "https://example.com",
            CreatedAt = now,
            ExpiresAt = now.AddMinutes(5),
            ConsumedAt = now
        };
        var challenges = new Mock<IPasskeyChallengeRepository>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        var service = new PasskeyService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, challenges.Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteRegistrationAsync(new CompletePasskeyRegistrationRequest(challenge.Id, JsonDocument.Parse("{}").RootElement));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyChallengeInvalid));
    }

    [Test]
    public async Task CompleteRegistrationAsyncShouldRejectChallengeForDifferentUser()
    {
        var now = DateTimeOffset.UtcNow;
        var challenge = CreateRegistrationChallenge(now);
        var challenges = new Mock<IPasskeyChallengeRepository>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var service = new PasskeyService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, challenges.Object, validator.Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteRegistrationAsync(new CompletePasskeyRegistrationRequest(challenge.Id, JsonDocument.Parse("{}").RootElement, UserId: Guid.NewGuid()));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyChallengeInvalid));
        validator.Verify(v => v.VerifyRegistrationAsync(It.IsAny<PasskeyOptions>(), It.IsAny<PasskeyChallenge>(), It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task CompleteRegistrationAsyncShouldNotStoreCredentialWhenChallengeConsumeFails()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = new PasskeyChallenge
        {
            Id = Guid.NewGuid(),
            Version = "v1",
            Purpose = "passkey-registration",
            UserId = Guid.NewGuid(),
            Challenge = "challenge",
            OptionsJson = "{}",
            RelyingPartyId = "example.com",
            Origin = "https://example.com",
            CreatedAt = now,
            ExpiresAt = now.AddMinutes(5)
        };
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        SetupChallengeUser(repo, challenge);
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, "v1", It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(false);
        validator.Setup(v => v.VerifyRegistrationAsync(It.IsAny<PasskeyOptions>(), challenge, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyRegistrationVerificationResult("cred", "pk", 1, []));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteRegistrationAsync(new CompletePasskeyRegistrationRequest(challenge.Id, JsonDocument.Parse("{}").RootElement));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyChallengeInvalid));
        credentials.Verify(r => r.CreateOrReplaceCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task CompleteRegistrationAsyncShouldStoreCamelCaseMetadata()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateRegistrationChallenge(now);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        SetupChallengeUser(repo, challenge);
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);
        validator.Setup(v => v.VerifyRegistrationAsync(It.IsAny<PasskeyOptions>(), challenge, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyRegistrationVerificationResult("cred", "pk", 1, ["internal"]));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        await service.CompleteRegistrationAsync(new CompletePasskeyRegistrationRequest(challenge.Id, JsonDocument.Parse("{}").RootElement, "Laptop"));

        credentials.Verify(r => r.CreateOrReplaceCredentialAsync(It.Is<UserCredential>(c =>
            c.Metadata != null &&
            c.Metadata.Contains("\"displayName\"", StringComparison.Ordinal) &&
            !c.Metadata.Contains("\"DisplayName\"", StringComparison.Ordinal)), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task CompleteRegistrationAsyncShouldReturnFailureWhenCredentialAlreadyLinked()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateRegistrationChallenge(now);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        SetupChallengeUser(repo, challenge);
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);
        validator.Setup(v => v.VerifyRegistrationAsync(It.IsAny<PasskeyOptions>(), challenge, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyRegistrationVerificationResult("cred", "pk", 1, []));
        credentials.Setup(r => r.CreateOrReplaceCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new CredentialProviderKeyConflictException());
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteRegistrationAsync(new CompletePasskeyRegistrationRequest(challenge.Id, JsonDocument.Parse("{}").RootElement));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyValidationFailed));
    }

    [Test]
    public async Task CompleteRegistrationAsyncShouldReturnFailureWhenValidationThrows()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateRegistrationChallenge(now);
        var repo = new Mock<IUserRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var events = new RecordingSecurityEventSink();
        SetupChallengeUser(repo, challenge);
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);
        validator.Setup(v => v.VerifyRegistrationAsync(It.IsAny<PasskeyOptions>(), challenge, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("bad ceremony"));
        var service = new PasskeyService(repo.Object, new Mock<ICredentialRepository>().Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), events, authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteRegistrationAsync(new CompletePasskeyRegistrationRequest(challenge.Id, JsonDocument.Parse("{}").RootElement));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyValidationFailed));
            Assert.That(events.Events.Single().Outcome, Is.EqualTo(SecurityEventOutcomes.Failure));
        }
    }

    [Test]
    public async Task CompleteRegistrationAsyncShouldUseDefaultDisplayNameWhenRequestNameIsMissing()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateRegistrationChallenge(now);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        SetupChallengeUser(repo, challenge);
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);
        validator.Setup(v => v.VerifyRegistrationAsync(It.IsAny<PasskeyOptions>(), challenge, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyRegistrationVerificationResult("cred", "pk", 1, []));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        await service.CompleteRegistrationAsync(new CompletePasskeyRegistrationRequest(challenge.Id, JsonDocument.Parse("{}").RootElement));

        credentials.Verify(r => r.CreateOrReplaceCredentialAsync(It.Is<UserCredential>(c => c.Metadata != null && c.Metadata.Contains("\"displayName\":\"Passkey\"", StringComparison.Ordinal)), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task CompleteRegistrationAsyncShouldUseChallengeDisplayNameWhenRequestNameIsMissing()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateRegistrationChallenge(now);
        challenge = new PasskeyChallenge
        {
            Id = challenge.Id,
            Version = challenge.Version,
            Purpose = challenge.Purpose,
            UserId = challenge.UserId,
            TenantId = challenge.TenantId,
            DisplayName = "Work Laptop",
            Challenge = challenge.Challenge,
            OptionsJson = challenge.OptionsJson,
            RelyingPartyId = challenge.RelyingPartyId,
            Origin = challenge.Origin,
            CreatedAt = challenge.CreatedAt,
            ExpiresAt = challenge.ExpiresAt
        };
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        SetupChallengeUser(repo, challenge);
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);
        validator.Setup(v => v.VerifyRegistrationAsync(It.IsAny<PasskeyOptions>(), challenge, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyRegistrationVerificationResult("cred", "pk", 1, []));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        await service.CompleteRegistrationAsync(new CompletePasskeyRegistrationRequest(challenge.Id, JsonDocument.Parse("{}").RootElement));

        credentials.Verify(r => r.CreateOrReplaceCredentialAsync(It.Is<UserCredential>(c => c.Metadata != null && c.Metadata.Contains("\"displayName\":\"Work Laptop\"", StringComparison.Ordinal)), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task StartAuthenticationAsyncShouldUseTrustedUserIdForAllowedCredentials()
    {
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Passkey,
            ProviderName = "PASSKEY",
            ProviderKey = "cred",
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            Metadata = JsonSerializer.Serialize(new PasskeyCredentialMetadata { DisplayName = "Laptop", PublicKey = "pk" }, PasskeyJson.Options)
        };
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        credentials.Setup(r => r.ListCredentialsForUserAsync(user.Id, true, It.IsAny<CancellationToken>())).ReturnsAsync([credential]);
        validator.Setup(v => v.CreateAuthenticationOptions(It.IsAny<PasskeyOptions>(), It.IsAny<string>(), It.Is<IReadOnlyList<UserCredential>>(c => c.Count == 1 && c[0].ProviderKey == "cred"), It.IsAny<string>()))
            .Returns("{}");
        challenges.Setup(r => r.CreateAsync(It.IsAny<PasskeyChallenge>(), It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.StartAuthenticationAsync(new StartPasskeyAuthenticationRequest(UserId: user.Id));

        Assert.That(result.Value?.OptionsJson, Is.EqualTo("{}"));
        repo.Verify(r => r.GetUserByEmailAsync(It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()), Times.Never);
        challenges.Verify(r => r.CreateAsync(It.Is<PasskeyChallenge>(c => c.UserId == user.Id), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task StartAuthenticationAsyncShouldUsePrimaryAuthenticationUserVerificationOption()
    {
        var options = new PasskeyOptions
        {
            Origin = "https://example.com",
            RelyingPartyId = "example.com",
            AuthenticationUserVerification = PasskeyUserVerificationRequirement.Discouraged
        };
        var validator = new Mock<IPasskeyCeremonyValidator>();
        validator.Setup(v => v.CreateAuthenticationOptions(It.IsAny<PasskeyOptions>(), It.IsAny<string>(), It.IsAny<IReadOnlyList<UserCredential>>(), It.IsAny<string>()))
            .Returns("{}");
        var service = new PasskeyService(
            new Mock<IUserRepository>().Object,
            new Mock<ICredentialRepository>().Object,
            new Mock<IPasskeyChallengeRepository>().Object,
            validator.Object,
            CreateDependencies(
                authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object,
                handshakeService: new Mock<IAuthenticationHandshakeService>().Object,
                tokenHasher: new TestTokenHasher(),
                options: options));

        await service.StartAuthenticationAsync(new StartPasskeyAuthenticationRequest());

        validator.Verify(v => v.CreateAuthenticationOptions(
            It.Is<PasskeyOptions>(value => value.AuthenticationUserVerification == PasskeyUserVerificationRequirement.Discouraged),
            It.IsAny<string>(),
            It.IsAny<IReadOnlyList<UserCredential>>(),
            PasskeyUserVerificationRequirement.Discouraged), Times.Once);
    }

    [Test]
    public async Task StartAuthenticationAsyncShouldCreateUserlessChallenge()
    {
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        validator.Setup(v => v.CreateAuthenticationOptions(It.IsAny<PasskeyOptions>(), It.IsAny<string>(), It.Is<IReadOnlyList<UserCredential>>(c => c.Count == 0), It.IsAny<string>()))
            .Returns("{}");
        var service = new PasskeyService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, challenges.Object, validator.Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.StartAuthenticationAsync(new StartPasskeyAuthenticationRequest());

        Assert.That(result.Value?.OptionsJson, Is.EqualTo("{}"));
        challenges.Verify(r => r.CreateAsync(It.Is<PasskeyChallenge>(c => c.UserId == null), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task StartAuthenticationAsyncShouldRateLimitByAuditSource()
    {
        var rateLimiter = new CaptureRateLimiter(allowed: false);
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var events = new RecordingSecurityEventSink();
        var service = new PasskeyService(
            new Mock<IUserRepository>().Object,
            new Mock<ICredentialRepository>().Object,
            challenges.Object,
            validator.Object,
            CreateDependencies(securityEventSink: events, authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher(), rateLimiter: rateLimiter));
        var audit = new AuditContext(null, "2001:0db8::1", "Unit Test", "corr-passkey-start");

        var result = await service.StartAuthenticationAsync(new StartPasskeyAuthenticationRequest(Audit: audit));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.RateLimited));
            Assert.That(rateLimiter.Attempts.Single().Purpose, Is.EqualTo("passkey-authentication-start"));
            Assert.That(rateLimiter.Attempts.Single().IpAddress, Is.EqualTo("2001:db8::1"));
            Assert.That(rateLimiter.Attempts.Single().CorrelationId, Is.EqualTo("corr-passkey-start"));
            Assert.That(events.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.AuthenticationRateLimited));
        }

        validator.Verify(v => v.CreateAuthenticationOptions(It.IsAny<PasskeyOptions>(), It.IsAny<string>(), It.IsAny<IReadOnlyList<UserCredential>>(), It.IsAny<string>()), Times.Never);
        challenges.Verify(r => r.CreateAsync(It.IsAny<PasskeyChallenge>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task CompleteAuthenticationAsyncShouldBuildSummaryWithoutListingCredentials()
    {
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = new PasskeyChallenge
        {
            Id = Guid.NewGuid(),
            Version = "v1",
            Purpose = "passkey-authentication",
            Challenge = "challenge",
            OptionsJson = "{}",
            RelyingPartyId = "example.com",
            Origin = "https://example.com",
            CreatedAt = now,
            ExpiresAt = now.AddMinutes(5)
        };
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Passkey,
            ProviderName = "PASSKEY",
            ProviderKey = "cred",
            Version = "v1",
            CreatedAt = now,
            Status = CredentialStatus.Active,
            Metadata = JsonSerializer.Serialize(new PasskeyCredentialMetadata { DisplayName = "Laptop", PublicKey = "pk", SignCount = 1 }, PasskeyJson.Options)
        };
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var pipeline = new Mock<IAuthenticationOrchestrator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);
        repo.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>())).ReturnsAsync(credential);
        credentials.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), credential.Version, It.IsAny<CancellationToken>())).ReturnsAsync(true);
        validator.Setup(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), challenge, credential, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyAuthenticationVerificationResult("cred", 2, true));
        pipeline.Setup(p => p.AuthenticateAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<MfaOrchestrationOptions?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, user));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: pipeline.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteAuthenticationAsync(new CompletePasskeyAuthenticationRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Credential?.CredentialId, Is.EqualTo("cred"));
            Assert.That(result.Credential?.LastUsedAt, Is.EqualTo(now));
            Assert.That(result.Credential?.SignCount, Is.EqualTo(2));
        }

        credentials.Verify(r => r.ListCredentialsForUserAsync(It.IsAny<Guid>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
        credentials.Verify(r => r.UpdateCredentialAsync(It.Is<UserCredential>(c =>
            c.LastUsedAt == now &&
            c.Metadata != null &&
            c.Metadata.Contains("\"signCount\":2", StringComparison.Ordinal)), credential.Version, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task CompleteAuthenticationAsyncShouldPreserveMetadataFieldsWhenPersistingCounter()
    {
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now);
        var credential = CreatePasskeyCredential(user.Id, "cred", now);
        credential.Metadata = JsonSerializer.Serialize(new PasskeyCredentialMetadata
        {
            DisplayName = "Security key",
            PublicKey = "pk",
            SignCount = 1,
            Transports = ["usb", "nfc"],
            Aaguid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            AuthenticatorAttachment = "cross-platform",
            Discoverable = false
        }, PasskeyJson.Options);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var orchestrator = new Mock<IAuthenticationOrchestrator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, now, It.IsAny<CancellationToken>())).ReturnsAsync(true);
        repo.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>())).ReturnsAsync(credential);
        UserCredential? persisted = null;
        credentials.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), credential.Version, It.IsAny<CancellationToken>()))
            .Callback<UserCredential, string, CancellationToken>((updated, _, _) => persisted = updated)
            .ReturnsAsync(true);
        validator.Setup(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), challenge, credential, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyAuthenticationVerificationResult("cred", 3, true));
        orchestrator.Setup(p => p.AuthenticateAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<MfaOrchestrationOptions?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, user));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteAuthenticationAsync(new CompletePasskeyAuthenticationRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred","response":{"clientDataJSON":"raw","authenticatorData":"raw"}}""").RootElement));

        var metadata = JsonSerializer.Deserialize<PasskeyCredentialMetadata>(persisted!.Metadata!, PasskeyJson.Options)!;
        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(metadata.DisplayName, Is.EqualTo("Security key"));
            Assert.That(metadata.PublicKey, Is.EqualTo("pk"));
            Assert.That(metadata.SignCount, Is.EqualTo(3));
            Assert.That(string.Join(",", metadata.Transports), Is.EqualTo("usb,nfc"));
            Assert.That(metadata.Aaguid, Is.EqualTo("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"));
            Assert.That(metadata.AuthenticatorAttachment, Is.EqualTo("cross-platform"));
            Assert.That(metadata.Discoverable, Is.False);
            Assert.That(persisted.Metadata, Does.Not.Contain("clientDataJSON"));
            Assert.That(persisted.Metadata, Does.Not.Contain("authenticatorData"));
        }
    }

    [Test]
    public async Task CompleteAuthenticationAsyncShouldNotRewriteWhenOrchestratorPersistedCounter()
    {
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now);
        var credential = CreatePasskeyCredential(user.Id, "cred", now);
        var persistedCredential = credential.Clone();
        persistedCredential.Version = "v2";
        persistedCredential.Metadata = JsonSerializer.Serialize(new PasskeyCredentialMetadata { DisplayName = "Laptop", PublicKey = "pk", SignCount = 2, Transports = ["internal"] }, PasskeyJson.Options);
        persistedCredential.LastUsedAt = now.AddSeconds(-1);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var orchestrator = new Mock<IAuthenticationOrchestrator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, now, It.IsAny<CancellationToken>())).ReturnsAsync(true);
        repo.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.SetupSequence(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential)
            .ReturnsAsync(persistedCredential);
        validator.Setup(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), challenge, credential, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyAuthenticationVerificationResult("cred", 2, true));
        orchestrator.Setup(p => p.AuthenticateAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<MfaOrchestrationOptions?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, user, CredentialUpdatePersisted: true));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteAuthenticationAsync(new CompletePasskeyAuthenticationRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Credential?.SignCount, Is.EqualTo(2));
            Assert.That(result.Credential?.LastUsedAt, Is.EqualTo(now.AddSeconds(-1)));
        }

        credentials.Verify(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task CompleteAuthenticationAsyncShouldFailClosedWhenCounterUpdateIsStale()
    {
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now);
        var credential = CreatePasskeyCredential(user.Id, "cred", now);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var orchestrator = new Mock<IAuthenticationOrchestrator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, now, It.IsAny<CancellationToken>())).ReturnsAsync(true);
        repo.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>())).ReturnsAsync(credential);
        credentials.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), credential.Version, It.IsAny<CancellationToken>())).ReturnsAsync(false);
        validator.Setup(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), challenge, credential, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyAuthenticationVerificationResult("cred", 2, true));
        orchestrator.Setup(p => p.AuthenticateAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<MfaOrchestrationOptions?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, user));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteAuthenticationAsync(new CompletePasskeyAuthenticationRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyValidationFailed));
    }

    [TestCase("missing")]
    [TestCase("malformed")]
    [TestCase("stale-counter")]
    [TestCase("future-counter")]
    [TestCase("missing-last-used")]
    [TestCase("same-version")]
    public async Task CompleteAuthenticationAsyncShouldFailClosedWhenPersistedCredentialIsNotCurrent(string persistedState)
    {
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now);
        var credential = CreatePasskeyCredential(user.Id, "cred", now);
        UserCredential? persistedCredential = persistedState == "missing" ? null : credential.Clone();
        if (persistedCredential != null)
        {
            persistedCredential.Version = persistedState == "same-version" ? credential.Version : "v2";
            persistedCredential.Metadata = persistedState == "malformed"
                ? "{"
                : JsonSerializer.Serialize(new PasskeyCredentialMetadata
                {
                    DisplayName = "Laptop",
                    PublicKey = "pk",
                    SignCount = persistedState switch
                    {
                        "stale-counter" => 1,
                        "future-counter" => 3,
                        _ => 2
                    },
                    Transports = ["internal"]
                }, PasskeyJson.Options);
            persistedCredential.LastUsedAt = persistedState switch
            {
                "missing-last-used" => null,
                _ => now
            };
        }

        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var orchestrator = new Mock<IAuthenticationOrchestrator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, now, It.IsAny<CancellationToken>())).ReturnsAsync(true);
        repo.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.SetupSequence(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential)
            .ReturnsAsync(persistedCredential);
        validator.Setup(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), challenge, credential, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyAuthenticationVerificationResult("cred", 2, true));
        orchestrator.Setup(p => p.AuthenticateAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<MfaOrchestrationOptions?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, user, CredentialUpdatePersisted: true));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteAuthenticationAsync(new CompletePasskeyAuthenticationRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyValidationFailed));
        credentials.Verify(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [TestCase(1, 1, false)]
    [TestCase(2, 1, false)]
    [TestCase(-1, 1, false)]
    [TestCase(0, -1, false)]
    [TestCase(0, 0, true)]
    public async Task CompleteAuthenticationAsyncShouldEnforceCounterRules(long storedSignCount, long verifiedSignCount, bool succeeds)
    {
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now);
        var credential = CreatePasskeyCredential(user.Id, "cred", now);
        credential.Metadata = JsonSerializer.Serialize(new PasskeyCredentialMetadata { DisplayName = "Laptop", PublicKey = "pk", SignCount = storedSignCount }, PasskeyJson.Options);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var orchestrator = new Mock<IAuthenticationOrchestrator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, now, It.IsAny<CancellationToken>())).ReturnsAsync(true);
        repo.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>())).ReturnsAsync(credential);
        credentials.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), credential.Version, It.IsAny<CancellationToken>())).ReturnsAsync(true);
        validator.Setup(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), challenge, credential, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyAuthenticationVerificationResult("cred", verifiedSignCount, true));
        orchestrator.Setup(p => p.AuthenticateAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<MfaOrchestrationOptions?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, user));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteAuthenticationAsync(new CompletePasskeyAuthenticationRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement));

        Assert.That(result.Succeeded, Is.EqualTo(succeeds));
        credentials.Verify(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), succeeds ? Times.Once() : Times.Never());
    }

    [TestCase(null)]
    [TestCase(" ")]
    [TestCase("null")]
    [TestCase("{")]
    public async Task CompleteAuthenticationAsyncShouldRejectMalformedMetadata(string? metadata)
    {
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now);
        var credential = CreatePasskeyCredential(user.Id, "cred", now);
        credential.Metadata = metadata;
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var orchestrator = new Mock<IAuthenticationOrchestrator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, now, It.IsAny<CancellationToken>())).ReturnsAsync(true);
        repo.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>())).ReturnsAsync(credential);
        validator.Setup(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), challenge, credential, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyAuthenticationVerificationResult("cred", 2, true));
        orchestrator.Setup(p => p.AuthenticateAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<MfaOrchestrationOptions?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, user));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteAuthenticationAsync(new CompletePasskeyAuthenticationRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyValidationFailed));
        credentials.Verify(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task CompleteAuthenticationAsyncShouldPassTenantContextToOrchestrator()
    {
        var tenantId = Guid.NewGuid();
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now);
        var credential = CreatePasskeyCredential(user.Id, "cred", now);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var orchestrator = new Mock<IAuthenticationOrchestrator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);
        repo.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>())).ReturnsAsync(credential);
        credentials.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), credential.Version, It.IsAny<CancellationToken>())).ReturnsAsync(true);
        validator.Setup(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), challenge, credential, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyAuthenticationVerificationResult("cred", 2, true));
        orchestrator.Setup(p => p.AuthenticateAsync(It.Is<AuthenticationContext>(c => c.UserId == user.Id && c.TenantId == tenantId), It.IsAny<IAuthenticationAssertion>(), It.IsAny<MfaOrchestrationOptions?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, user));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteAuthenticationAsync(new CompletePasskeyAuthenticationRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement, tenantId));

        Assert.That(result.Succeeded, Is.True);
        orchestrator.Verify(p => p.AuthenticateAsync(It.Is<AuthenticationContext>(c => c.UserId == user.Id && c.TenantId == tenantId), It.IsAny<PasskeyAssertion>(), It.IsAny<MfaOrchestrationOptions?>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task CompleteAuthenticationAsyncShouldRejectMissingUserVerificationWhenPrimaryPolicyRequiresIt()
    {
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now);
        var credential = CreatePasskeyCredential(user.Id, "cred", now);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var orchestrator = new Mock<IAuthenticationOrchestrator>();
        var options = new PasskeyOptions
        {
            Origin = "https://example.com",
            RelyingPartyId = "example.com",
            AuthenticationUserVerification = PasskeyUserVerificationRequirement.Required
        };
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, now, It.IsAny<CancellationToken>())).ReturnsAsync(true);
        repo.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>())).ReturnsAsync(credential);
        credentials.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), credential.Version, It.IsAny<CancellationToken>())).ReturnsAsync(true);
        validator.Setup(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), challenge, credential, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyAuthenticationVerificationResult("cred", 2, false));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher(), options: options));

        var result = await service.CompleteAuthenticationAsync(new CompletePasskeyAuthenticationRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyValidationFailed));
        challenges.Verify(r => r.ConsumeAsync(challenge.Id, challenge.Version, now, It.IsAny<CancellationToken>()), Times.Once);
        orchestrator.Verify(p => p.AuthenticateAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<MfaOrchestrationOptions?>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task CompleteAuthenticationAsyncShouldTreatNullPrimaryUserVerificationAsNotRequired()
    {
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now);
        var credential = CreatePasskeyCredential(user.Id, "cred", now);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var orchestrator = new Mock<IAuthenticationOrchestrator>();
        var options = new PasskeyOptions
        {
            Origin = "https://example.com",
            RelyingPartyId = "example.com",
            AuthenticationUserVerification = null!
        };
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, now, It.IsAny<CancellationToken>())).ReturnsAsync(true);
        repo.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>())).ReturnsAsync(credential);
        credentials.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), credential.Version, It.IsAny<CancellationToken>())).ReturnsAsync(true);
        validator.Setup(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), challenge, credential, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyAuthenticationVerificationResult("cred", 2, false));
        orchestrator.Setup(p => p.AuthenticateAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<MfaOrchestrationOptions?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, user));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher(), options: options));

        var result = await service.CompleteAuthenticationAsync(new CompletePasskeyAuthenticationRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement));

        Assert.That(result.Succeeded, Is.True);
        orchestrator.Verify(p => p.AuthenticateAsync(It.IsAny<AuthenticationContext>(), It.IsAny<PasskeyAssertion>(), It.IsAny<MfaOrchestrationOptions?>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task CompleteAuthenticationAsyncShouldPassAuditSourceToOrchestrator()
    {
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now, user.Id);
        var credential = CreatePasskeyCredential(user.Id, "cred", now);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var orchestrator = new Mock<IAuthenticationOrchestrator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);
        repo.Setup(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>())).ReturnsAsync(credential);
        credentials.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), credential.Version, It.IsAny<CancellationToken>())).ReturnsAsync(true);
        validator.Setup(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), challenge, credential, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyAuthenticationVerificationResult("cred", 2, true));
        orchestrator.Setup(p => p.AuthenticateAsync(
                It.IsAny<AuthenticationContext>(),
                It.IsAny<IAuthenticationAssertion>(),
                It.IsAny<MfaOrchestrationOptions?>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, user));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));
        var audit = new AuditContext(null, "203.0.113.44", "Browser", "corr-passkey-complete");

        var result = await service.CompleteAuthenticationAsync(new CompletePasskeyAuthenticationRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement, Audit: audit));

        Assert.That(result.Succeeded, Is.True);
        orchestrator.Verify(p => p.AuthenticateAsync(
            It.Is<AuthenticationContext>(c => c.UserId == user.Id && c.IpAddress == "203.0.113.44" && c.UserAgent == "Browser" && c.CorrelationId == "corr-passkey-complete"),
            It.IsAny<IAuthenticationAssertion>(),
            It.IsAny<MfaOrchestrationOptions?>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task CompleteAuthenticationAsyncShouldRejectChallengeForDifferentOrigin()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = new PasskeyChallenge
        {
            Id = Guid.NewGuid(),
            Version = "v1",
            Purpose = "passkey-authentication",
            Challenge = "challenge",
            OptionsJson = "{}",
            RelyingPartyId = "example.com",
            Origin = "https://other.example.com",
            CreatedAt = now,
            ExpiresAt = now.AddMinutes(5)
        };
        var challenges = new Mock<IPasskeyChallengeRepository>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var service = new PasskeyService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteAuthenticationAsync(new CompletePasskeyAuthenticationRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyChallengeInvalid));
        validator.Verify(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), It.IsAny<PasskeyChallenge>(), It.IsAny<UserCredential>(), It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task CompleteAuthenticationAsyncShouldRejectFailedConsume()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now);
        var challenges = new Mock<IPasskeyChallengeRepository>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(false);
        var service = new PasskeyService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, challenges.Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteAuthenticationAsync(new CompletePasskeyAuthenticationRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyChallengeInvalid));
    }

    [Test]
    public async Task CompleteAuthenticationAsyncShouldConsumeChallengeBeforeRejectingMalformedAssertion()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now);
        var challenges = new Mock<IPasskeyChallengeRepository>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteAuthenticationAsync(new CompletePasskeyAuthenticationRequest(challenge.Id, JsonDocument.Parse("{}").RootElement));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyValidationFailed));
        challenges.Verify(r => r.ConsumeAsync(challenge.Id, challenge.Version, now, It.IsAny<CancellationToken>()), Times.Once);
        repo.Verify(r => r.GetUserByProviderKeyAsync(It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        validator.Verify(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), It.IsAny<PasskeyChallenge>(), It.IsAny<UserCredential>(), It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task CompleteAuthenticationAsyncShouldHandleLookupAndValidationFailures()
    {
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now, user.Id);
        var credential = CreatePasskeyCredential(user.Id, "cred", now);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);
        repo.SetupSequence(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync((IUser?)null)
            .ReturnsAsync(user)
            .ReturnsAsync(user);
        credentials.SetupSequence(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>()))
            .ReturnsAsync((UserCredential?)null)
            .ReturnsAsync(credential);
        validator.Setup(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), challenge, credential, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("bad assertion"));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var missingUser = await service.CompleteAuthenticationAsync(new CompletePasskeyAuthenticationRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement));
        var missingCredential = await service.CompleteAuthenticationAsync(new CompletePasskeyAuthenticationRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement));
        var validationFailed = await service.CompleteAuthenticationAsync(new CompletePasskeyAuthenticationRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missingUser.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyCredentialNotFound));
            Assert.That(missingCredential.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyCredentialNotFound));
            Assert.That(validationFailed.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyValidationFailed));
        }
    }

    [Test]
    public async Task CompleteAuthenticationAsyncShouldReturnMfaRequiredAndHandleOrchestratorFailures()
    {
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now);
        var credential = CreatePasskeyCredential(user.Id, "cred", now);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var orchestrator = new Mock<IAuthenticationOrchestrator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);
        repo.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>())).ReturnsAsync(credential);
        credentials.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), credential.Version, It.IsAny<CancellationToken>())).ReturnsAsync(true);
        validator.Setup(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), challenge, credential, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyAuthenticationVerificationResult("cred", 2));
        orchestrator.SetupSequence(o => o.AuthenticateAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<MfaOrchestrationOptions?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaAuthenticationResult(MfaAuthenticationStatus.MfaRequired, user, "handshake", ["totp"]))
            .ReturnsAsync(new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, user, ErrorMessage: "failed"))
            .ThrowsAsync(new InvalidOperationException("pipeline failure"));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var mfa = await service.CompleteAuthenticationAsync(new CompletePasskeyAuthenticationRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement));
        var failed = await service.CompleteAuthenticationAsync(new CompletePasskeyAuthenticationRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement));
        var thrown = await service.CompleteAuthenticationAsync(new CompletePasskeyAuthenticationRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(mfa.Succeeded, Is.False);
            Assert.That(mfa.AuthenticationStatus, Is.EqualTo(MfaAuthenticationStatus.MfaRequired));
            Assert.That(mfa.HandshakeToken, Is.EqualTo("handshake"));
            Assert.That(failed.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyValidationFailed));
            Assert.That(thrown.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyValidationFailed));
        }
    }

    [Test]
    public async Task StartFactorAsyncShouldScopeChallengeToHandshakeUser()
    {
        var userId = Guid.NewGuid();
        var handshake = CreateHandshake(userId);
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Passkey,
            ProviderName = "PASSKEY",
            ProviderKey = "cred",
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            Metadata = JsonSerializer.Serialize(new PasskeyCredentialMetadata { DisplayName = "Laptop", PublicKey = "pk" }, PasskeyJson.Options)
        };
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var handshakes = new Mock<IAuthenticationHandshakeService>();
        handshakes.Setup(h => h.BeginFactorChallengeAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(handshake));
        credentials.Setup(r => r.ListCredentialsForUserAsync(userId, true, It.IsAny<CancellationToken>())).ReturnsAsync([credential]);
        validator.Setup(v => v.CreateAuthenticationOptions(It.IsAny<PasskeyOptions>(), It.IsAny<string>(), It.Is<IReadOnlyList<UserCredential>>(c => c.Count == 1), PasskeyUserVerificationRequirement.Required))
            .Returns("{}");
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: handshakes.Object, tokenHasher: new TestTokenHasher()));

        var audit = new AuditContext(null, "198.51.100.1", "Browser", "corr-factor-start");

        var result = await service.StartFactorAsync(new StartPasskeyFactorRequest("token", Audit: audit));

        Assert.That(result.Succeeded, Is.True);
        handshakes.Verify(h => h.BeginFactorChallengeAsync(
            It.Is<VerifyAuthenticationHandshakeRequest>(request => request.Context != null && request.Context.IpAddress == "198.51.100.1" && request.Context.UserAgent == "Browser" && request.Context.CorrelationId == "corr-factor-start"),
            It.IsAny<CancellationToken>()));
        challenges.Verify(r => r.CreateAsync(It.Is<PasskeyChallenge>(c => c.UserId == userId && c.HandshakeTokenHash == "hashed:token" && c.FactorType == "passkey"), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task StartFactorAsyncShouldRequestRequiredUserVerification()
    {
        var userId = Guid.NewGuid();
        var handshake = CreateHandshake(userId);
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Passkey,
            ProviderName = "PASSKEY",
            ProviderKey = "cred",
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            Metadata = JsonSerializer.Serialize(new PasskeyCredentialMetadata { DisplayName = "Laptop", PublicKey = "pk" }, PasskeyJson.Options)
        };
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var handshakes = new Mock<IAuthenticationHandshakeService>();
        handshakes.Setup(h => h.BeginFactorChallengeAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(handshake));
        credentials.Setup(r => r.ListCredentialsForUserAsync(userId, true, It.IsAny<CancellationToken>())).ReturnsAsync([credential]);
        validator.Setup(v => v.CreateAuthenticationOptions(It.IsAny<PasskeyOptions>(), It.IsAny<string>(), It.IsAny<IReadOnlyList<UserCredential>>(), PasskeyUserVerificationRequirement.Required))
            .Returns("{}");
        var service = new PasskeyService(
            new Mock<IUserRepository>().Object,
            credentials.Object,
            challenges.Object,
            validator.Object,
            CreateDependencies(
                authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object,
                handshakeService: handshakes.Object,
                tokenHasher: new TestTokenHasher()));

        var result = await service.StartFactorAsync(new StartPasskeyFactorRequest("token"));

        Assert.That(result.Succeeded, Is.True);
        validator.VerifyAll();
    }

    [TestCase("token", "")]
    [TestCase("token", "totp")]
    public async Task StartFactorAsyncShouldRejectInvalidRequestShape(string token, string factorType)
    {
        var service = new PasskeyService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.StartFactorAsync(new StartPasskeyFactorRequest(token, factorType));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyChallengeInvalid));
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase(" ")]
    public async Task StartFactorAsyncShouldDelegateMissingHandshakeTokenNormalizationWithoutCreatingChallenge(string? token)
    {
        var handshakes = new Mock<IAuthenticationHandshakeService>();
        handshakes.Setup(h => h.BeginFactorChallengeAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure<AuthenticationHandshake>(AshlarFailureCodes.HandshakeNotFound));
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var service = new PasskeyService(
            new Mock<IUserRepository>().Object,
            credentials.Object,
            challenges.Object,
            new Mock<IPasskeyCeremonyValidator>().Object,
            CreateDependencies(
                authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object,
                handshakeService: handshakes.Object,
                tokenHasher: new TestTokenHasher()));

        var result = await service.StartFactorAsync(new StartPasskeyFactorRequest(token));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyChallengeInvalid));
        handshakes.Verify(h => h.BeginFactorChallengeAsync(It.Is<VerifyAuthenticationHandshakeRequest>(request =>
            request.HandshakeToken == token &&
            request.FactorType == "passkey"), It.IsAny<CancellationToken>()), Times.Once);
        credentials.Verify(r => r.ListCredentialsForUserAsync(It.IsAny<Guid>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
        challenges.Verify(r => r.CreateAsync(It.IsAny<PasskeyChallenge>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task StartFactorAsyncShouldRejectOverlongHandshakeTokenWithoutCreatingChallenge()
    {
        var overlongToken = new string('a', 257);
        var handshakes = new Mock<IAuthenticationHandshakeService>();
        handshakes.Setup(h => h.BeginFactorChallengeAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure<AuthenticationHandshake>(AshlarFailureCodes.HandshakeNotFound));
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var service = new PasskeyService(new Mock<IUserRepository>().Object, credentials.Object, challenges.Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: handshakes.Object, tokenHasher: new TestTokenHasher()));

        var result = await service.StartFactorAsync(new StartPasskeyFactorRequest(overlongToken));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyChallengeInvalid));
        handshakes.Verify(h => h.BeginFactorChallengeAsync(It.Is<VerifyAuthenticationHandshakeRequest>(request => request.HandshakeToken == overlongToken), It.IsAny<CancellationToken>()), Times.Once);
        credentials.Verify(r => r.ListCredentialsForUserAsync(It.IsAny<Guid>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
        challenges.Verify(r => r.CreateAsync(It.IsAny<PasskeyChallenge>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task StartFactorAsyncShouldRejectTokenHashFailureAfterHandshakeChallengeAllows()
    {
        var overlongToken = new string('a', 257);
        var handshakes = new Mock<IAuthenticationHandshakeService>();
        handshakes.Setup(h => h.BeginFactorChallengeAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(CreateHandshake(Guid.NewGuid())));
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var service = new PasskeyService(new Mock<IUserRepository>().Object, credentials.Object, challenges.Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: handshakes.Object, tokenHasher: new TestTokenHasher()));

        var result = await service.StartFactorAsync(new StartPasskeyFactorRequest(overlongToken));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyChallengeInvalid));
        credentials.Verify(r => r.ListCredentialsForUserAsync(It.IsAny<Guid>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
        challenges.Verify(r => r.CreateAsync(It.IsAny<PasskeyChallenge>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task StartFactorAsyncShouldRejectHandshakeChallengeFailures()
    {
        var failureCodes = new[]
        {
            AshlarFailureCodes.HandshakeNotFound,
            AshlarFailureCodes.HandshakeRevoked,
            AshlarFailureCodes.HandshakeAlreadyCompleted,
            AshlarFailureCodes.HandshakeExpired,
            AshlarFailureCodes.InvalidFactorType,
            AshlarFailureCodes.FactorAlreadyVerified
        };
        var handshakes = new Mock<IAuthenticationHandshakeService>();
        var setup = handshakes.SetupSequence(h => h.BeginFactorChallengeAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()));
        foreach (var failureCode in failureCodes)
        {
            setup.ReturnsAsync(Result.Failure<AuthenticationHandshake>(failureCode));
        }

        var service = new PasskeyService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: handshakes.Object, tokenHasher: new TestTokenHasher()));

        foreach (var failureCode in failureCodes)
        {
            var result = await service.StartFactorAsync(new StartPasskeyFactorRequest("token"));
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyChallengeInvalid));
        }
    }

    [Test]
    public async Task StartFactorAsyncShouldPreserveRateLimitedHandshakeChallengeFailure()
    {
        var handshakes = new Mock<IAuthenticationHandshakeService>();
        handshakes.Setup(h => h.BeginFactorChallengeAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure<AuthenticationHandshake>(AshlarFailureCodes.RateLimitExceeded));
        var service = new PasskeyService(
            new Mock<IUserRepository>().Object,
            new Mock<ICredentialRepository>().Object,
            new Mock<IPasskeyChallengeRepository>().Object,
            new Mock<IPasskeyCeremonyValidator>().Object,
            CreateDependencies(
                authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object,
                handshakeService: handshakes.Object,
                tokenHasher: new TestTokenHasher()));

        var result = await service.StartFactorAsync(new StartPasskeyFactorRequest("token"));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.RateLimitExceeded));
    }

    [Test]
    public async Task StartFactorAsyncShouldRejectEmptyHandshakeChallengeSuccess()
    {
        var handshakes = new Mock<IAuthenticationHandshakeService>();
        handshakes.Setup(h => h.BeginFactorChallengeAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success<AuthenticationHandshake>(null!));
        var service = new PasskeyService(
            new Mock<IUserRepository>().Object,
            new Mock<ICredentialRepository>().Object,
            new Mock<IPasskeyChallengeRepository>().Object,
            new Mock<IPasskeyCeremonyValidator>().Object,
            CreateDependencies(
                authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object,
                handshakeService: handshakes.Object,
                tokenHasher: new TestTokenHasher()));

        var result = await service.StartFactorAsync(new StartPasskeyFactorRequest("token"));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyChallengeInvalid));
    }

    [Test]
    public async Task StartFactorAsyncShouldExcludePrimaryPasskeyCredential()
    {
        var userId = Guid.NewGuid();
        var metadata = new Dictionary<string, string>
        {
            ["primary_provider_type"] = ProviderType.Passkey.Value,
            ["primary_provider_name"] = "PASSKEY",
            ["primary_credential_key"] = "primary"
        };
        var handshake = CreateHandshake(userId) with { Metadata = metadata };
        var credentialList = new[]
        {
            new UserCredential
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                ProviderType = ProviderType.Passkey,
                ProviderName = "PASSKEY",
                ProviderKey = "primary",
                Version = "v1",
                CreatedAt = DateTimeOffset.UtcNow,
                Status = CredentialStatus.Active,
                Metadata = JsonSerializer.Serialize(new PasskeyCredentialMetadata { DisplayName = "Primary", PublicKey = "pk" }, PasskeyJson.Options)
            },
            new UserCredential
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                ProviderType = ProviderType.Passkey,
                ProviderName = "PASSKEY",
                ProviderKey = "secondary",
                Version = "v2",
                CreatedAt = DateTimeOffset.UtcNow,
                Status = CredentialStatus.Active,
                Metadata = JsonSerializer.Serialize(new PasskeyCredentialMetadata { DisplayName = "Secondary", PublicKey = "pk" }, PasskeyJson.Options)
            }
        };
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var handshakes = new Mock<IAuthenticationHandshakeService>();
        handshakes.Setup(h => h.BeginFactorChallengeAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(handshake));
        credentials.Setup(r => r.ListCredentialsForUserAsync(userId, true, It.IsAny<CancellationToken>())).ReturnsAsync(credentialList);
        validator.Setup(v => v.CreateAuthenticationOptions(It.IsAny<PasskeyOptions>(), It.IsAny<string>(), It.Is<IReadOnlyList<UserCredential>>(c => c.Count == 1 && c[0].ProviderKey == "secondary"), It.IsAny<string>()))
            .Returns("{}");
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: handshakes.Object, tokenHasher: new TestTokenHasher()));

        var result = await service.StartFactorAsync(new StartPasskeyFactorRequest("token"));

        Assert.That(result.Succeeded, Is.True);
        validator.VerifyAll();
    }

    [Test]
    public async Task StartFactorAsyncShouldFailWhenOnlyPrimaryPasskeyCredentialExists()
    {
        var userId = Guid.NewGuid();
        var metadata = new Dictionary<string, string>
        {
            ["primary_provider_type"] = ProviderType.Passkey.Value,
            ["primary_provider_name"] = "PASSKEY",
            ["primary_credential_key"] = "primary"
        };
        var handshake = CreateHandshake(userId) with { Metadata = metadata };
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Passkey,
            ProviderName = "PASSKEY",
            ProviderKey = "primary",
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            Metadata = JsonSerializer.Serialize(new PasskeyCredentialMetadata { DisplayName = "Primary", PublicKey = "pk" }, PasskeyJson.Options)
        };
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var handshakes = new Mock<IAuthenticationHandshakeService>();
        handshakes.Setup(h => h.BeginFactorChallengeAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(handshake));
        credentials.Setup(r => r.ListCredentialsForUserAsync(userId, true, It.IsAny<CancellationToken>())).ReturnsAsync([credential]);
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: handshakes.Object, tokenHasher: new TestTokenHasher()));

        var result = await service.StartFactorAsync(new StartPasskeyFactorRequest("token"));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyCredentialNotFound));
        validator.Verify(v => v.CreateAuthenticationOptions(It.IsAny<PasskeyOptions>(), It.IsAny<string>(), It.IsAny<IReadOnlyList<UserCredential>>(), It.IsAny<string>()), Times.Never);
        challenges.Verify(r => r.CreateAsync(It.IsAny<PasskeyChallenge>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task CompleteFactorAsyncShouldVerifyMfaFactor()
    {
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = new PasskeyChallenge
        {
            Id = Guid.NewGuid(),
            Version = "v1",
            Purpose = "passkey-authentication",
            UserId = user.Id,
            HandshakeTokenHash = "hashed:token",
            FactorType = "passkey",
            Challenge = "challenge",
            OptionsJson = "{}",
            RelyingPartyId = "example.com",
            Origin = "https://example.com",
            CreatedAt = now,
            ExpiresAt = now.AddMinutes(5)
        };
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Passkey,
            ProviderName = "PASSKEY",
            ProviderKey = "cred",
            Version = "v1",
            CreatedAt = now,
            Status = CredentialStatus.Active,
            Metadata = JsonSerializer.Serialize(new PasskeyCredentialMetadata { DisplayName = "Laptop", PublicKey = "pk", SignCount = 1 }, PasskeyJson.Options)
        };
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var orchestrator = new Mock<IAuthenticationOrchestrator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);
        repo.Setup(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>())).ReturnsAsync(credential);
        credentials.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), credential.Version, It.IsAny<CancellationToken>())).ReturnsAsync(true);
        validator.Setup(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), challenge, credential, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyAuthenticationVerificationResult("cred", 2, true));
        orchestrator.Setup(o => o.VerifyFactorAsync(
                "token",
                "passkey",
                It.Is<AuthenticationContext>(context => context.IpAddress == "198.51.100.2" && context.UserAgent == "Browser" && context.CorrelationId == "corr-factor-complete"),
                It.IsAny<IAuthenticationAssertion>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, user));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));
        var audit = new AuditContext(null, "198.51.100.2", "Browser", "corr-factor-complete");

        var result = await service.CompleteFactorAsync(new CompletePasskeyFactorRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement, "token", Audit: audit));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Credential?.SignCount, Is.EqualTo(2));
        }
        orchestrator.Verify(o => o.VerifyFactorAsync(
            "token",
            "passkey",
            It.Is<AuthenticationContext>(context => context.IpAddress == "198.51.100.2" && context.UserAgent == "Browser" && context.CorrelationId == "corr-factor-complete"),
            It.Is<PasskeyAssertion>(assertion => assertion.UserVerified),
            It.IsAny<CancellationToken>()), Times.Once);
        credentials.Verify(r => r.UpdateCredentialAsync(It.Is<UserCredential>(c =>
            c.LastUsedAt == now &&
            c.Metadata != null &&
            c.Metadata.Contains("\"signCount\":2", StringComparison.Ordinal)), credential.Version, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task CompleteFactorAsyncShouldFailClosedWhenCounterUpdateIsStale()
    {
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now, user.Id, "hashed:token", "passkey");
        var credential = CreatePasskeyCredential(user.Id, "cred", now);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var orchestrator = new Mock<IAuthenticationOrchestrator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, now, It.IsAny<CancellationToken>())).ReturnsAsync(true);
        repo.Setup(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>())).ReturnsAsync(credential);
        credentials.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), credential.Version, It.IsAny<CancellationToken>())).ReturnsAsync(false);
        validator.Setup(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), challenge, credential, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyAuthenticationVerificationResult("cred", 2, true));
        orchestrator.Setup(o => o.VerifyFactorAsync("token", "passkey", It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, user));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteFactorAsync(new CompletePasskeyFactorRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement, "token"));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyValidationFailed));
    }

    [Test]
    public async Task CompleteFactorAsyncShouldNotRewriteWhenOrchestratorPersistedCounter()
    {
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now, user.Id, "hashed:token", "passkey");
        var credential = CreatePasskeyCredential(user.Id, "cred", now);
        var persistedCredential = credential.Clone();
        persistedCredential.Version = "v2";
        persistedCredential.Metadata = JsonSerializer.Serialize(new PasskeyCredentialMetadata { DisplayName = "Laptop", PublicKey = "pk", SignCount = 2, Transports = ["internal"] }, PasskeyJson.Options);
        persistedCredential.LastUsedAt = now.AddSeconds(-1);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var orchestrator = new Mock<IAuthenticationOrchestrator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, now, It.IsAny<CancellationToken>())).ReturnsAsync(true);
        repo.Setup(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.SetupSequence(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential)
            .ReturnsAsync(persistedCredential);
        validator.Setup(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), challenge, credential, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyAuthenticationVerificationResult("cred", 2, true));
        orchestrator.Setup(o => o.VerifyFactorAsync("token", "passkey", It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, user, CredentialUpdatePersisted: true));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteFactorAsync(new CompletePasskeyFactorRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement, "token"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Credential?.SignCount, Is.EqualTo(2));
            Assert.That(result.Credential?.LastUsedAt, Is.EqualTo(now.AddSeconds(-1)));
        }

        credentials.Verify(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [TestCase("missing")]
    [TestCase("malformed")]
    [TestCase("stale-counter")]
    [TestCase("future-counter")]
    [TestCase("missing-last-used")]
    [TestCase("same-version")]
    public async Task CompleteFactorAsyncShouldFailClosedWhenPersistedCredentialIsNotCurrent(string persistedState)
    {
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now, user.Id, "hashed:token", "passkey");
        var credential = CreatePasskeyCredential(user.Id, "cred", now);
        UserCredential? persistedCredential = persistedState == "missing" ? null : credential.Clone();
        if (persistedCredential != null)
        {
            persistedCredential.Version = persistedState == "same-version" ? credential.Version : "v2";
            persistedCredential.Metadata = persistedState == "malformed"
                ? "{"
                : JsonSerializer.Serialize(new PasskeyCredentialMetadata
                {
                    DisplayName = "Laptop",
                    PublicKey = "pk",
                    SignCount = persistedState switch
                    {
                        "stale-counter" => 1,
                        "future-counter" => 3,
                        _ => 2
                    },
                    Transports = ["internal"]
                }, PasskeyJson.Options);
            persistedCredential.LastUsedAt = persistedState switch
            {
                "missing-last-used" => null,
                _ => now
            };
        }

        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var orchestrator = new Mock<IAuthenticationOrchestrator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, now, It.IsAny<CancellationToken>())).ReturnsAsync(true);
        repo.Setup(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.SetupSequence(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential)
            .ReturnsAsync(persistedCredential);
        validator.Setup(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), challenge, credential, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyAuthenticationVerificationResult("cred", 2, true));
        orchestrator.Setup(o => o.VerifyFactorAsync("token", "passkey", It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, user, CredentialUpdatePersisted: true));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteFactorAsync(new CompletePasskeyFactorRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement, "token"));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyValidationFailed));
        credentials.Verify(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task CompleteFactorAsyncShouldRejectAssertionWithoutUserVerificationAfterConsumingChallenge()
    {
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now, user.Id, "hashed:token", "passkey");
        var credential = CreatePasskeyCredential(user.Id, "cred", now);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var orchestrator = new Mock<IAuthenticationOrchestrator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, now, It.IsAny<CancellationToken>())).ReturnsAsync(true);
        repo.Setup(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>())).ReturnsAsync(credential);
        validator.Setup(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), challenge, credential, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyAuthenticationVerificationResult("cred", 2, false));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteFactorAsync(new CompletePasskeyFactorRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement, "token"));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyValidationFailed));
        challenges.Verify(r => r.ConsumeAsync(challenge.Id, challenge.Version, now, It.IsAny<CancellationToken>()), Times.Once);
        orchestrator.Verify(o => o.VerifyFactorAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task CompleteFactorAsyncShouldPassTenantContextToOrchestrator()
    {
        var tenantId = Guid.NewGuid();
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now, user.Id, "hashed:token", "passkey");
        var credential = CreatePasskeyCredential(user.Id, "cred", now);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var orchestrator = new Mock<IAuthenticationOrchestrator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);
        repo.Setup(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>())).ReturnsAsync(credential);
        credentials.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), credential.Version, It.IsAny<CancellationToken>())).ReturnsAsync(true);
        validator.Setup(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), challenge, credential, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyAuthenticationVerificationResult("cred", 2, true));
        orchestrator.Setup(o => o.VerifyFactorAsync("token", "passkey", It.Is<AuthenticationContext>(c => c.UserId == user.Id && c.TenantId == tenantId), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, user));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteFactorAsync(new CompletePasskeyFactorRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement, "token", TenantId: tenantId));

        Assert.That(result.Succeeded, Is.True);
        orchestrator.Verify(o => o.VerifyFactorAsync("token", "passkey", It.Is<AuthenticationContext>(c => c.UserId == user.Id && c.TenantId == tenantId), It.IsAny<PasskeyAssertion>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task CompleteFactorAsyncShouldReturnHandshakeIncomplete()
    {
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now, user.Id, "hashed:token", "passkey");
        var credential = CreatePasskeyCredential(user.Id, "cred", now);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var orchestrator = new Mock<IAuthenticationOrchestrator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);
        repo.Setup(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>())).ReturnsAsync(credential);
        credentials.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), credential.Version, It.IsAny<CancellationToken>())).ReturnsAsync(true);
        validator.Setup(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), challenge, credential, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyAuthenticationVerificationResult("cred", 2, true));
        orchestrator.Setup(o => o.VerifyFactorAsync("token", "passkey", It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaAuthenticationResult(MfaAuthenticationStatus.HandshakeIncomplete, user, "token", ["totp"]));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteFactorAsync(new CompletePasskeyFactorRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement, "token"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.AuthenticationStatus, Is.EqualTo(MfaAuthenticationStatus.HandshakeIncomplete));
            Assert.That(result.HandshakeToken, Is.EqualTo("token"));
        }
    }

    [Test]
    public async Task CompleteFactorAsyncShouldRejectChallengeBoundToDifferentHandshake()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = new PasskeyChallenge
        {
            Id = Guid.NewGuid(),
            Version = "v1",
            Purpose = "passkey-authentication",
            UserId = Guid.NewGuid(),
            HandshakeTokenHash = "hashed:other-token",
            FactorType = "passkey",
            Challenge = "challenge",
            OptionsJson = "{}",
            RelyingPartyId = "example.com",
            Origin = "https://example.com",
            CreatedAt = now,
            ExpiresAt = now.AddMinutes(5)
        };
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var orchestrator = new Mock<IAuthenticationOrchestrator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        var service = new PasskeyService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteFactorAsync(new CompletePasskeyFactorRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement, "token"));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyChallengeInvalid));
        validator.Verify(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), It.IsAny<PasskeyChallenge>(), It.IsAny<UserCredential>(), It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()), Times.Never);
        orchestrator.Verify(o => o.VerifyFactorAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task CompleteFactorAsyncShouldRejectOverlongHandshakeTokenWithoutReadingChallenge()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now, Guid.NewGuid(), "hashed:token", "passkey");
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var orchestrator = new Mock<IAuthenticationOrchestrator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        var service = new PasskeyService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteFactorAsync(new CompletePasskeyFactorRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement, new string('a', 257)));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyChallengeInvalid));
        challenges.Verify(r => r.GetAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()), Times.Never);
        challenges.Verify(r => r.ConsumeAsync(It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Never);
        validator.Verify(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), It.IsAny<PasskeyChallenge>(), It.IsAny<UserCredential>(), It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()), Times.Never);
        orchestrator.Verify(o => o.VerifyFactorAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task CompleteFactorAsyncShouldConsumeChallengeBeforeRejectingMalformedAssertion()
    {
        var userId = Guid.NewGuid();
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now, userId, "hashed:token", "passkey");
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var orchestrator = new Mock<IAuthenticationOrchestrator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteFactorAsync(new CompletePasskeyFactorRequest(challenge.Id, JsonDocument.Parse("{}").RootElement, "token"));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyValidationFailed));
        challenges.Verify(r => r.ConsumeAsync(challenge.Id, challenge.Version, now, It.IsAny<CancellationToken>()), Times.Once);
        repo.Verify(r => r.GetUserByIdAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()), Times.Never);
        validator.Verify(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), It.IsAny<PasskeyChallenge>(), It.IsAny<UserCredential>(), It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()), Times.Never);
        orchestrator.Verify(o => o.VerifyFactorAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [TestCase("token", "")]
    [TestCase("token", "totp")]
    public async Task CompleteFactorAsyncShouldRejectInvalidRequestShape(string token, string factorType)
    {
        var service = new PasskeyService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteFactorAsync(new CompletePasskeyFactorRequest(Guid.NewGuid(), JsonDocument.Parse("{}").RootElement, token, factorType));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyChallengeInvalid));
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase(" ")]
    public async Task CompleteFactorAsyncShouldRejectMissingHandshakeTokenWithoutReadingChallenge(string? token)
    {
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var orchestrator = new Mock<IAuthenticationOrchestrator>();
        var service = new PasskeyService(
            new Mock<IUserRepository>().Object,
            new Mock<ICredentialRepository>().Object,
            challenges.Object,
            validator.Object,
            CreateDependencies(
                authenticationOrchestrator: orchestrator.Object,
                handshakeService: new Mock<IAuthenticationHandshakeService>().Object,
                tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteFactorAsync(new CompletePasskeyFactorRequest(Guid.NewGuid(), JsonDocument.Parse("""{"id":"cred"}""").RootElement, token));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyChallengeInvalid));
        challenges.Verify(r => r.GetAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()), Times.Never);
        challenges.Verify(r => r.ConsumeAsync(It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Never);
        validator.Verify(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), It.IsAny<PasskeyChallenge>(), It.IsAny<UserCredential>(), It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()), Times.Never);
        orchestrator.Verify(o => o.VerifyFactorAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task CompleteFactorAsyncShouldHandleLookupValidationAndOrchestratorFailures()
    {
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now, user.Id, "hashed:token", "passkey");
        var credential = CreatePasskeyCredential(user.Id, "cred", now);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var orchestrator = new Mock<IAuthenticationOrchestrator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.SetupSequence(r => r.ConsumeAsync(challenge.Id, challenge.Version, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(false)
            .ReturnsAsync(true)
            .ReturnsAsync(true)
            .ReturnsAsync(true)
            .ReturnsAsync(true)
            .ReturnsAsync(true);
        repo.SetupSequence(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync((IUser?)null)
            .ReturnsAsync(user)
            .ReturnsAsync(user)
            .ReturnsAsync(user)
            .ReturnsAsync(user);
        credentials.SetupSequence(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>()))
            .ReturnsAsync((UserCredential?)null)
            .ReturnsAsync(credential)
            .ReturnsAsync(credential)
            .ReturnsAsync(credential);
        validator.SetupSequence(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), challenge, credential, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("bad assertion"))
            .ReturnsAsync(new PasskeyAuthenticationVerificationResult("cred", 2, true))
            .ReturnsAsync(new PasskeyAuthenticationVerificationResult("cred", 2, true));
        orchestrator.SetupSequence(o => o.VerifyFactorAsync("token", "passkey", It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, user, ErrorMessage: "failed"))
            .ThrowsAsync(new InvalidOperationException("pipeline failure"));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var consumeFailed = await service.CompleteFactorAsync(new CompletePasskeyFactorRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement, "token"));
        var missingUser = await service.CompleteFactorAsync(new CompletePasskeyFactorRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement, "token"));
        var missingCredential = await service.CompleteFactorAsync(new CompletePasskeyFactorRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement, "token"));
        var validationFailed = await service.CompleteFactorAsync(new CompletePasskeyFactorRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement, "token"));
        var orchestratorFailed = await service.CompleteFactorAsync(new CompletePasskeyFactorRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement, "token"));
        var orchestratorThrown = await service.CompleteFactorAsync(new CompletePasskeyFactorRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement, "token"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(consumeFailed.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyChallengeInvalid));
            Assert.That(missingUser.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyCredentialNotFound));
            Assert.That(missingCredential.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyCredentialNotFound));
            Assert.That(validationFailed.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyValidationFailed));
            Assert.That(orchestratorFailed.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyValidationFailed));
            Assert.That(orchestratorThrown.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyValidationFailed));
        }
    }

    [Test]
    public async Task RenameAsyncShouldDefaultBlankDisplayName()
    {
        var userId = Guid.NewGuid();
        var credentialId = Guid.NewGuid();
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        credentials.Setup(r => r.ListCredentialsForUserAsync(userId, true, It.IsAny<CancellationToken>()))
            .ReturnsAsync([
                new UserCredential
                {
                    Id = credentialId,
                    UserId = userId,
                    ProviderType = ProviderType.Passkey,
                    ProviderName = "PASSKEY",
                    ProviderKey = "cred",
                    Version = "v1",
                    CreatedAt = DateTimeOffset.UtcNow,
                    Status = CredentialStatus.Active,
                    Metadata = JsonSerializer.Serialize(new PasskeyCredentialMetadata { DisplayName = "Old", PublicKey = "pk" })
                }
            ]);
        credentials.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), "v1", It.IsAny<CancellationToken>())).ReturnsAsync(true);
        var service = new PasskeyService(repo.Object, credentials.Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.RenameAsync(new RenamePasskeyRequest(userId, credentialId, ""));

        Assert.That(result.Succeeded, Is.True);
        credentials.Verify(r => r.UpdateCredentialAsync(It.Is<UserCredential>(c => c.Metadata != null && c.Metadata.Contains("Passkey", StringComparison.Ordinal)), "v1", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task RenameAsyncShouldRejectMalformedMetadataWithoutRewriting()
    {
        var userId = Guid.NewGuid();
        var credentialId = Guid.NewGuid();
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        credentials.Setup(r => r.ListCredentialsForUserAsync(userId, true, It.IsAny<CancellationToken>()))
            .ReturnsAsync([
                new UserCredential
                {
                    Id = credentialId,
                    UserId = userId,
                    ProviderType = ProviderType.Passkey,
                    ProviderName = "PASSKEY",
                    ProviderKey = "cred",
                    Version = "v1",
                    CreatedAt = DateTimeOffset.UtcNow,
                    Status = CredentialStatus.Active,
                    Metadata = "{"
                }
            ]);
        var service = new PasskeyService(repo.Object, credentials.Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.RenameAsync(new RenamePasskeyRequest(userId, credentialId, "Name"));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyValidationFailed));
        credentials.Verify(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task ListRenameAndRevokeShouldHandleMissingAndConcurrencyBranches()
    {
        var userId = Guid.NewGuid();
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var passkey = CreatePasskeyCredential(userId, "cred", now);
        var nullMetadataPasskey = CreatePasskeyCredential(userId, "null-metadata", now);
        nullMetadataPasskey.Metadata = "null";
        var malformedMetadataPasskey = CreatePasskeyCredential(userId, "malformed-metadata", now);
        malformedMetadataPasskey.Metadata = "{";
        var other = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Local,
            ProviderName = "PASSKEY",
            ProviderKey = "other",
            Version = "v1",
            CreatedAt = now,
            Status = CredentialStatus.Active
        };
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        credentials.Setup(r => r.ListCredentialsForUserAsync(userId, true, It.IsAny<CancellationToken>()))
            .ReturnsAsync([passkey, nullMetadataPasskey, malformedMetadataPasskey, other]);
        credentials.SetupSequence(r => r.UpdateCredentialAsync(passkey, passkey.Version, It.IsAny<CancellationToken>()))
            .ReturnsAsync(false)
            .ReturnsAsync(true)
            .ReturnsAsync(false)
            .ReturnsAsync(true);
        var service = new PasskeyService(repo.Object, credentials.Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var list = await service.ListAsync(userId);
        var renameMissing = await service.RenameAsync(new RenamePasskeyRequest(userId, Guid.NewGuid(), "Name"));
        var renameConflict = await service.RenameAsync(new RenamePasskeyRequest(userId, passkey.Id, "Name"));
        var renameSuccess = await service.RenameAsync(new RenamePasskeyRequest(userId, passkey.Id, new string('x', 120)));
        var revokeMissing = await service.RevokeAsync(new RevokePasskeyRequest(userId, Guid.NewGuid()));
        var revokeConflict = await service.RevokeAsync(new RevokePasskeyRequest(userId, passkey.Id));
        var revokeSuccess = await service.RevokeAsync(new RevokePasskeyRequest(userId, passkey.Id));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(list, Has.Count.EqualTo(3));
            Assert.That(renameMissing.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyCredentialNotFound));
            Assert.That(renameConflict.FailureCode, Is.EqualTo(AshlarFailureCodes.ConcurrencyConflict));
            Assert.That(renameSuccess.Succeeded, Is.True);
            Assert.That(revokeMissing.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyCredentialNotFound));
            Assert.That(revokeConflict.FailureCode, Is.EqualTo(AshlarFailureCodes.ConcurrencyConflict));
            Assert.That(revokeSuccess.Succeeded, Is.True);
        }
    }

    private static void AssertStartRegistrationTenantFailure(TestUser user, TenantContext? tenant)
    {
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        repo.Setup(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies());

        Assert.ThrowsAsync<InvalidOperationException>(() => service.StartRegistrationAsync(new StartPasskeyRegistrationRequest(user.Id, "Laptop", tenant)));
        challenges.Verify(r => r.CreateAsync(It.IsAny<PasskeyChallenge>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    private static void SetupChallengeUser(Mock<IUserRepository> repository, PasskeyChallenge challenge, UserAccountState accountState = UserAccountState.Active)
    {
        var userId = challenge.UserId ?? throw new ArgumentException("Challenge must be user-bound.", nameof(challenge));
        repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new TestUser(userId, "test@example.com", accountState, challenge.TenantId));
    }

    private static async Task<Result> CompleteRegistrationForTenantAsync(Guid? challengeTenantId, Guid? userTenantId, TenantContext? requestTenant)
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var userId = Guid.NewGuid();
        var challenge = CreateRegistrationChallenge(now, userId, challengeTenantId);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        repo.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new TestUser(userId, "test@example.com", TenantId: userTenantId));
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);
        validator.Setup(v => v.VerifyRegistrationAsync(It.IsAny<PasskeyOptions>(), challenge, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyRegistrationVerificationResult("cred", "pk", 1, []));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now)));

        var result = await service.CompleteRegistrationAsync(new CompletePasskeyRegistrationRequest(challenge.Id, JsonDocument.Parse("{}").RootElement, Tenant: requestTenant));

        var shouldPersist = result.Succeeded;
        credentials.Verify(r => r.CreateOrReplaceCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()), shouldPersist ? Times.Once : Times.Never);
        return result;
    }

    private static PasskeyChallenge CreateRegistrationChallenge(DateTimeOffset now, Guid? userId = null, Guid? tenantId = null)
    {
        return new PasskeyChallenge
        {
            Id = Guid.NewGuid(),
            Version = "v1",
            Purpose = "passkey-registration",
            UserId = userId ?? Guid.NewGuid(),
            TenantId = tenantId,
            Challenge = "challenge",
            OptionsJson = "{}",
            RelyingPartyId = "example.com",
            Origin = "https://example.com",
            CreatedAt = now,
            ExpiresAt = now.AddMinutes(5)
        };
    }

    private static PasskeyChallenge CreateAuthenticationChallenge(
        DateTimeOffset now,
        Guid? userId = null,
        string? handshakeTokenHash = null,
        string? factorType = null)
    {
        return new PasskeyChallenge
        {
            Id = Guid.NewGuid(),
            Version = "v1",
            Purpose = "passkey-authentication",
            UserId = userId,
            HandshakeTokenHash = handshakeTokenHash,
            FactorType = factorType,
            Challenge = "challenge",
            OptionsJson = "{}",
            RelyingPartyId = "example.com",
            Origin = "https://example.com",
            CreatedAt = now,
            ExpiresAt = now.AddMinutes(5)
        };
    }

    private static AuthenticationHandshake CreateHandshake(Guid userId)
    {
        return new AuthenticationHandshake(
            Guid.NewGuid(),
            userId,
            "token-hash",
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddMinutes(5),
            false,
            false,
            new HashSet<string> { "passkey" },
            new HashSet<string>());
    }

    private static UserCredential CreatePasskeyCredential(Guid userId, string providerKey, DateTimeOffset now)
    {
        return new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Passkey,
            ProviderName = "PASSKEY",
            ProviderKey = providerKey,
            Version = "v1",
            CreatedAt = now,
            Status = CredentialStatus.Active,
            Metadata = JsonSerializer.Serialize(new PasskeyCredentialMetadata { DisplayName = "Laptop", PublicKey = "pk", SignCount = 1, Transports = ["internal"] }, PasskeyJson.Options)
        };
    }

    private static PasskeyServiceDependencies CreateDependencies(
        TimeProvider? timeProvider = null,
        ISecurityEventSink? securityEventSink = null,
        IAuthenticationOrchestrator? authenticationOrchestrator = null,
        IAuthenticationHandshakeService? handshakeService = null,
        ISecureTokenHasher? tokenHasher = null,
        IAuthenticationRateLimiter? rateLimiter = null,
        PasskeyOptions? options = null)
    {
        return new PasskeyServiceDependencies(
            Options.Create(options ?? new PasskeyOptions { Origin = "https://example.com", RelyingPartyId = "example.com" }),
            authenticationOrchestrator ?? new Mock<IAuthenticationOrchestrator>().Object,
            handshakeService ?? new Mock<IAuthenticationHandshakeService>().Object,
            tokenHasher ?? new TestTokenHasher(),
            rateLimiter ?? AllowRateLimiter.Instance,
            timeProvider,
            securityEventSink);
    }
}

internal sealed class CaptureRateLimiter(bool allowed) : IAuthenticationRateLimiter
{
    public List<RateLimitAttempt> Attempts { get; } = [];

    public Task<RateLimitDecision> CheckAsync(RateLimitAttempt attempt, RateLimitRule rule, CancellationToken cancellationToken = default)
    {
        Attempts.Add(attempt);
        return Task.FromResult(new RateLimitDecision
        {
            Status = allowed ? RateLimitStatus.Allowed : RateLimitStatus.Blocked,
            Remaining = allowed ? rule.PermitLimit : 0,
            WindowResetAt = DateTimeOffset.UtcNow.Add(rule.Window)
        });
    }
}

internal sealed class AllowRateLimiter : IAuthenticationRateLimiter
{
    public static readonly AllowRateLimiter Instance = new();

    private AllowRateLimiter()
    {
    }

    public Task<RateLimitDecision> CheckAsync(RateLimitAttempt attempt, RateLimitRule rule, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(new RateLimitDecision { Status = RateLimitStatus.Allowed, Remaining = rule.PermitLimit, WindowResetAt = DateTimeOffset.UtcNow.Add(rule.Window) });
    }
}

internal sealed record TestUser(Guid Id, string DisplayEmail, UserAccountState AccountState = UserAccountState.Active, Guid? TenantId = null) : ITenantUser
{
    public string? Name => null;
    public DateTimeOffset? EmailVerifiedAt => null;
}

internal sealed class TestTokenHasher : ISecureTokenHasher
{
    public string HashToken(string token)
    {
        if (token.Length > 256)
        {
            throw new ArgumentException("Token exceeds maximum allowed length.", nameof(token));
        }

        return $"hashed:{token}";
    }
}

internal sealed class RecordingSecurityEventSink : ISecurityEventSink
{
    public List<AshlarSecurityEvent> Events { get; } = [];

    public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
    {
        Events.Add(securityEvent);
        return Task.CompletedTask;
    }
}
