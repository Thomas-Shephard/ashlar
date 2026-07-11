using System.Text.Json;
using Ashlar.Auditing;
using Ashlar.Identity.Features.Mfa;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Identity.Models.Sessions;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Passkeys.Tests;

internal sealed class PasskeyServiceTests
{
    private static readonly Guid RegistrationSessionId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly TimeSpan RegistrationFreshnessWindow = TimeSpan.FromMinutes(10);
    private const string RegistrationPurpose = "passkey-registration";
    private const string ManagementPurpose = "passkey-management";

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

        var result = await service.StartRegistrationAsync(CreateStartRegistrationRequest(user.Id, " ", audit: audit));

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

    [Test]
    public void CompleteRegistrationAsyncShouldRejectNullRequest()
    {
        var service = new PasskeyService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies());

        Assert.ThrowsAsync<ArgumentNullException>(() => service.CompleteRegistrationAsync(null!));
    }

    [Test]
    public void ConstructorShouldRejectNullAuthenticationProviders()
    {
        Assert.Throws<ArgumentNullException>(() => _ = new PasskeyService(
            new Mock<IUserRepository>().Object,
            new Mock<ICredentialRepository>().Object,
            new Mock<IPasskeyChallengeRepository>().Object,
            new Mock<IPasskeyCeremonyValidator>().Object,
            null!,
            CreateDependencies()));
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
    public void StartRegistrationAsyncShouldRejectMissingProof()
    {
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        repo.Setup(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(r => r.ListCredentialsForUserAsync(user.Id, true, It.IsAny<CancellationToken>())).ReturnsAsync([]);
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies());

        var ex = Assert.ThrowsAsync<AshlarOperationException>(() => service.StartRegistrationAsync(new StartPasskeyRegistrationRequest(user.Id, "Laptop") { CurrentSessionId = RegistrationSessionId }));

        Assert.That(ex!.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
        challenges.Verify(r => r.CreateAsync(It.IsAny<PasskeyChallenge>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public void StartRegistrationAsyncShouldRejectProofForAnotherUser()
    {
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        repo.Setup(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(r => r.ListCredentialsForUserAsync(user.Id, true, It.IsAny<CancellationToken>())).ReturnsAsync([]);
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies());
        var request = new StartPasskeyRegistrationRequest(user.Id, "Laptop")
        {
            CurrentSessionId = RegistrationSessionId,
            FreshPrimaryAuthenticationProof = CreatePrimaryProof(Guid.NewGuid(), null, DateTimeOffset.UtcNow, RegistrationSessionId)
        };

        var ex = Assert.ThrowsAsync<AshlarOperationException>(() => service.StartRegistrationAsync(request));

        Assert.That(ex!.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
        challenges.Verify(r => r.CreateAsync(It.IsAny<PasskeyChallenge>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public void StartRegistrationAsyncShouldRejectProofForAnotherTenant()
    {
        var tenantId = Guid.NewGuid();
        var user = new TestUser(Guid.NewGuid(), "test@example.com", TenantId: tenantId);
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        repo.Setup(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(r => r.ListCredentialsForUserAsync(user.Id, true, It.IsAny<CancellationToken>())).ReturnsAsync([]);
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now)));
        var request = new StartPasskeyRegistrationRequest(user.Id, "Laptop")
        {
            Tenant = new TenantContext(tenantId),
            CurrentSessionId = RegistrationSessionId,
            FreshPrimaryAuthenticationProof = CreatePrimaryProof(user.Id, Guid.NewGuid(), now, RegistrationSessionId)
        };

        var ex = Assert.ThrowsAsync<AshlarOperationException>(() => service.StartRegistrationAsync(request));

        Assert.That(ex!.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
        challenges.Verify(r => r.CreateAsync(It.IsAny<PasskeyChallenge>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public void StartRegistrationAsyncShouldRejectProofForAnotherPurpose()
    {
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        repo.Setup(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(r => r.ListCredentialsForUserAsync(user.Id, true, It.IsAny<CancellationToken>())).ReturnsAsync([]);
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now)));
        var request = new StartPasskeyRegistrationRequest(user.Id, "Laptop")
        {
            CurrentSessionId = RegistrationSessionId,
            FreshPrimaryAuthenticationProof = CreatePrimaryProof(user.Id, null, now, RegistrationSessionId, "totp-enrollment")
        };

        var ex = Assert.ThrowsAsync<AshlarOperationException>(() => service.StartRegistrationAsync(request));

        Assert.That(ex!.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
        challenges.Verify(r => r.CreateAsync(It.IsAny<PasskeyChallenge>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task StartRegistrationAsyncShouldRequireMfaProofWhenUsableAdditionalFactorExists()
    {
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var existing = CreatePasskeyCredential(user.Id, "existing", DateTimeOffset.UtcNow);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        repo.Setup(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(r => r.ListCredentialsForUserAsync(user.Id, true, It.IsAny<CancellationToken>())).ReturnsAsync([existing]);
        var provider = new PasskeyAuthenticationProvider(Options.Create(new PasskeyOptions { Origin = "https://example.com", RelyingPartyId = "example.com" }));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, [provider], CreateDependencies());

        var ex = Assert.ThrowsAsync<AshlarOperationException>(() => service.StartRegistrationAsync(CreateStartRegistrationRequest(user.Id, "Laptop")));

        Assert.That(ex!.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
        await Task.CompletedTask;
    }

    [Test]
    public async Task StartRegistrationAsyncShouldStoreMfaProofBindingWhenUsableAdditionalFactorExists()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var existing = CreatePasskeyCredential(user.Id, "existing", now);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        PasskeyChallenge? storedChallenge = null;
        repo.Setup(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(r => r.ListCredentialsForUserAsync(user.Id, true, It.IsAny<CancellationToken>())).ReturnsAsync([existing]);
        validator.Setup(v => v.CreateRegistrationOptions(It.IsAny<PasskeyOptions>(), user, "Laptop", It.IsAny<string>(), It.IsAny<IReadOnlyList<UserCredential>>()))
            .Returns("{}");
        challenges.Setup(r => r.CreateAsync(It.IsAny<PasskeyChallenge>(), It.IsAny<CancellationToken>()))
            .Callback<PasskeyChallenge, CancellationToken>((challenge, _) => storedChallenge = challenge)
            .Returns(Task.CompletedTask);
        var provider = new PasskeyAuthenticationProvider(Options.Create(new PasskeyOptions { Origin = "https://example.com", RelyingPartyId = "example.com" }));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, [provider], CreateDependencies(new FakeTimeProvider(now)));
        var request = new StartPasskeyRegistrationRequest(user.Id, "Laptop")
        {
            CurrentSessionId = RegistrationSessionId,
            FreshMfaProof = CreateMfaProof(user.Id, null, now, RegistrationSessionId)
        };

        await service.StartRegistrationAsync(request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(storedChallenge!.RegistrationProofType, Is.EqualTo("fresh-mfa"));
            Assert.That(storedChallenge.RegistrationProofSessionId, Is.EqualTo(RegistrationSessionId));
            Assert.That(storedChallenge.RegistrationProofExpiresAt, Is.EqualTo(now.Add(RegistrationFreshnessWindow)));
        }
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

        var result = await service.StartRegistrationAsync(CreateStartRegistrationRequest(user.Id, "Laptop", new TenantContext(tenantId)));

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

        var result = await service.StartRegistrationAsync(CreateStartRegistrationRequest(user.Id, "Laptop"));

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
            AllowRateLimiter.Instance,
            ActiveSessionRepository()));
        Assert.Throws<ArgumentNullException>(() => _ = new PasskeyServiceDependencies(
            Options.Create(new PasskeyOptions { Origin = "https://example.com", RelyingPartyId = "example.com" }),
            new Mock<IAuthenticationOrchestrator>().Object,
            null!,
            new TestTokenHasher(),
            AllowRateLimiter.Instance,
            ActiveSessionRepository()));
        Assert.Throws<ArgumentNullException>(() => _ = new PasskeyServiceDependencies(
            Options.Create(new PasskeyOptions { Origin = "https://example.com", RelyingPartyId = "example.com" }),
            new Mock<IAuthenticationOrchestrator>().Object,
            new Mock<IAuthenticationHandshakeService>().Object,
            null!,
            AllowRateLimiter.Instance,
            ActiveSessionRepository()));
        Assert.Throws<ArgumentNullException>(() => _ = new PasskeyServiceDependencies(
            Options.Create(new PasskeyOptions { Origin = "https://example.com", RelyingPartyId = "example.com" }),
            new Mock<IAuthenticationOrchestrator>().Object,
            new Mock<IAuthenticationHandshakeService>().Object,
            new TestTokenHasher(),
            null!,
            ActiveSessionRepository()));
        Assert.Throws<ArgumentNullException>(() => _ = new PasskeyServiceDependencies(
            Options.Create(new PasskeyOptions { Origin = "https://example.com", RelyingPartyId = "example.com" }),
            new Mock<IAuthenticationOrchestrator>().Object,
            new Mock<IAuthenticationHandshakeService>().Object,
            new TestTokenHasher(),
            AllowRateLimiter.Instance,
            null!));
    }

    [Test]
    public async Task CompleteRegistrationAsyncShouldConsumeChallengeAndStoreCredential()
    {
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var clock = new FakeTimeProvider(now);
        var challenge = CreateRegistrationChallenge(now, user.Id);
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
        var result = await service.CompleteRegistrationAsync(CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement, "Laptop"));

        Assert.That(result.Succeeded, Is.True);
        credentials.Verify(r => r.CreateOrReplaceCredentialAsync(It.Is<UserCredential>(c => c.ProviderType == ProviderType.Passkey && c.ProviderKey == "cred"), It.IsAny<CancellationToken>()), Times.Once);
        challenges.Verify(r => r.ConsumeAsync(challenge.Id, "v1", It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public void CompleteRegistrationAsyncShouldPropagateRequiredAuditFailure()
    {
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateRegistrationChallenge(now, user.Id);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var transactionProvider = new RecordingTransactionProvider();
        repo.Setup(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, "v1", It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);
        validator.Setup(v => v.VerifyRegistrationAsync(It.IsAny<PasskeyOptions>(), challenge, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyRegistrationVerificationResult("cred", "pk", 1, ["internal"]));
        var service = new PasskeyService(
            repo.Object,
            credentials.Object,
            challenges.Object,
            validator.Object,
            CreateDependencies(new FakeTimeProvider(now), new ThrowingSecurityEventSink(), transactionProvider: transactionProvider));

        Assert.ThrowsAsync<InvalidOperationException>(() => service.CompleteRegistrationAsync(CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement, "Laptop")));
        Assert.That(transactionProvider.Transaction.Committed, Is.False);
    }

    [Test]
    public async Task RevokeAsyncShouldCommitCredentialMutationAndAuditTogether()
    {
        var userId = Guid.NewGuid();
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var credential = CreatePasskeyCredential(userId, "cred", now);
        var credentials = new Mock<ICredentialRepository>();
        var repo = new Mock<IUserRepository>();
        var events = new RecordingSecurityEventSink();
        var transactionProvider = new RecordingTransactionProvider();
        repo.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>())).ReturnsAsync(new TestUser(userId, "test@example.com"));
        credentials.Setup(r => r.ListCredentialsForUserAsync(userId, It.IsAny<bool>(), It.IsAny<CancellationToken>())).ReturnsAsync([credential]);
        credentials.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), credential.Version, It.IsAny<CancellationToken>())).ReturnsAsync(true);
        var service = new PasskeyService(
            repo.Object,
            credentials.Object,
            new Mock<IPasskeyChallengeRepository>().Object,
            new Mock<IPasskeyCeremonyValidator>().Object,
            CreateDependencies(new FakeTimeProvider(now), events, sessionRepository: ActiveSessionRepository(userId), transactionProvider: transactionProvider));

        var result = await service.RevokeAsync(CreateRevokeRequest(userId, credential.Id, now));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(transactionProvider.Transaction.Committed, Is.True);
            Assert.That(events.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.PasskeyRevoked));
        }
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

        var result = await service.CompleteRegistrationAsync(CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement));

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

        var result = await service.CompleteRegistrationAsync(CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement));

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

        var result = await service.CompleteRegistrationAsync(CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement));

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

        var result = await service.CompleteRegistrationAsync(CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement, userId: Guid.NewGuid()));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyChallengeInvalid));
        validator.Verify(v => v.VerifyRegistrationAsync(It.IsAny<PasskeyOptions>(), It.IsAny<PasskeyChallenge>(), It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task CompleteRegistrationAsyncShouldNotStoreCredentialWhenChallengeConsumeFails()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateRegistrationChallenge(now);
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

        var result = await service.CompleteRegistrationAsync(CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement));

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

        await service.CompleteRegistrationAsync(CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement, "Laptop"));

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

        var result = await service.CompleteRegistrationAsync(CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyValidationFailed));
    }

    [Test]
    public async Task CompleteRegistrationAsyncShouldRejectMissingProof()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateRegistrationChallenge(now);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now)));

        var result = await service.CompleteRegistrationAsync(new CompletePasskeyRegistrationRequest(challenge.Id, JsonDocument.Parse("{}").RootElement, null, challenge.UserId!.Value)
        {
            CurrentSessionId = RegistrationSessionId
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            challenges.Verify(r => r.ConsumeAsync(It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Never);
            credentials.Verify(r => r.CreateOrReplaceCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task CompleteRegistrationAsyncShouldRejectProofForAnotherPurpose()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateRegistrationChallenge(now);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now)));
        var request = new CompletePasskeyRegistrationRequest(challenge.Id, JsonDocument.Parse("{}").RootElement, null, challenge.UserId!.Value)
        {
            CurrentSessionId = RegistrationSessionId,
            FreshPrimaryAuthenticationProof = CreatePrimaryProof(challenge.UserId.Value, challenge.TenantId, now, RegistrationSessionId, "totp-enrollment")
        };

        var result = await service.CompleteRegistrationAsync(request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            challenges.Verify(r => r.ConsumeAsync(It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Never);
            credentials.Verify(r => r.CreateOrReplaceCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task CompleteRegistrationAsyncShouldRejectProofForAnotherTenant()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var tenantId = Guid.NewGuid();
        var challenge = CreateRegistrationChallenge(now, tenantId: tenantId);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now)));
        var request = new CompletePasskeyRegistrationRequest(challenge.Id, JsonDocument.Parse("{}").RootElement, null, challenge.UserId!.Value)
        {
            Tenant = new TenantContext(tenantId),
            CurrentSessionId = RegistrationSessionId,
            FreshPrimaryAuthenticationProof = CreatePrimaryProof(challenge.UserId.Value, Guid.NewGuid(), now, RegistrationSessionId)
        };

        var result = await service.CompleteRegistrationAsync(request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            challenges.Verify(r => r.ConsumeAsync(It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Never);
            credentials.Verify(r => r.CreateOrReplaceCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task CompleteRegistrationAsyncShouldAcceptPersistedProofExpiryPrecisionDrift()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var originalChallenge = CreateRegistrationChallenge(now);
        var challenge = new PasskeyChallenge
        {
            Id = originalChallenge.Id,
            Version = originalChallenge.Version,
            Purpose = originalChallenge.Purpose,
            UserId = originalChallenge.UserId,
            TenantId = originalChallenge.TenantId,
            RegistrationProofType = originalChallenge.RegistrationProofType,
            RegistrationProofSessionId = originalChallenge.RegistrationProofSessionId,
            RegistrationProofExpiresAt = now.Add(RegistrationFreshnessWindow).AddTicks(-5),
            Challenge = originalChallenge.Challenge,
            OptionsJson = originalChallenge.OptionsJson,
            RelyingPartyId = originalChallenge.RelyingPartyId,
            Origin = originalChallenge.Origin,
            CreatedAt = originalChallenge.CreatedAt,
            ExpiresAt = originalChallenge.ExpiresAt
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
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now)));

        var result = await service.CompleteRegistrationAsync(CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            credentials.Verify(r => r.CreateOrReplaceCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [Test]
    public async Task CompleteRegistrationAsyncShouldAcceptMfaProofBinding()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateRegistrationChallenge(now);
        challenge = CopyRegistrationChallenge(challenge, proofType: "fresh-mfa");
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        SetupChallengeUser(repo, challenge);
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);
        validator.Setup(v => v.VerifyRegistrationAsync(It.IsAny<PasskeyOptions>(), challenge, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyRegistrationVerificationResult("cred", "pk", 1, []));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now)));
        var request = new CompletePasskeyRegistrationRequest(challenge.Id, JsonDocument.Parse("{}").RootElement, null, challenge.UserId!.Value)
        {
            CurrentSessionId = RegistrationSessionId,
            FreshMfaProof = CreateMfaProof(challenge.UserId.Value, challenge.TenantId, now, RegistrationSessionId)
        };

        var result = await service.CompleteRegistrationAsync(request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            credentials.Verify(r => r.CreateOrReplaceCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [TestCase("fresh-other")]
    [TestCase("fresh-primary")]
    public async Task CompleteRegistrationAsyncShouldRejectStoredProofBindingMismatch(string proofType)
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateRegistrationChallenge(now);
        challenge = proofType == "fresh-other"
            ? CopyRegistrationChallenge(challenge, proofType: proofType)
            : CopyRegistrationChallenge(challenge, sessionId: Guid.NewGuid());
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now)));

        var request = proofType == "fresh-other"
            ? CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement)
            : new CompletePasskeyRegistrationRequest(challenge.Id, JsonDocument.Parse("{}").RootElement, null, challenge.UserId!.Value)
            {
                CurrentSessionId = RegistrationSessionId,
                FreshPrimaryAuthenticationProof = CreatePrimaryProof(challenge.UserId.Value, challenge.TenantId, now, RegistrationSessionId)
            };

        var result = await service.CompleteRegistrationAsync(request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            challenges.Verify(r => r.ConsumeAsync(It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Never);
            credentials.Verify(r => r.CreateOrReplaceCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task CompleteRegistrationAsyncShouldRejectStoredProofWithoutExpiry()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CopyRegistrationChallenge(CreateRegistrationChallenge(now), clearExpiresAt: true);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now)));

        var result = await service.CompleteRegistrationAsync(CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
    }

    [Test]
    public async Task CompleteRegistrationAsyncShouldRejectStoredProofWithoutSession()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CopyRegistrationChallenge(CreateRegistrationChallenge(now), clearSessionId: true);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now)));

        var result = await service.CompleteRegistrationAsync(CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement, sessionId: RegistrationSessionId));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
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

        var result = await service.CompleteRegistrationAsync(CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement));

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

        await service.CompleteRegistrationAsync(CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement));

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
            RegistrationProofType = challenge.RegistrationProofType,
            RegistrationProofSessionId = challenge.RegistrationProofSessionId,
            RegistrationProofExpiresAt = challenge.RegistrationProofExpiresAt,
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

        await service.CompleteRegistrationAsync(CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement));

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
        repo.Setup(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(user);
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
    public async Task StartAuthenticationAsyncShouldAllowTenantUserWithMatchingTenant()
    {
        var tenantId = Guid.NewGuid();
        var user = new TestUser(Guid.NewGuid(), "test@example.com", TenantId: tenantId);
        PasskeyChallenge? storedChallenge = null;
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var events = new RecordingSecurityEventSink();
        repo.Setup(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(r => r.ListCredentialsForUserAsync(user.Id, true, It.IsAny<CancellationToken>())).ReturnsAsync([]);
        challenges.Setup(r => r.CreateAsync(It.IsAny<PasskeyChallenge>(), It.IsAny<CancellationToken>()))
            .Callback<PasskeyChallenge, CancellationToken>((challenge, _) => storedChallenge = challenge)
            .Returns(Task.CompletedTask);
        validator.Setup(v => v.CreateAuthenticationOptions(It.IsAny<PasskeyOptions>(), It.IsAny<string>(), It.IsAny<IReadOnlyList<UserCredential>>(), It.IsAny<string>()))
            .Returns("{}");
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(securityEventSink: events, authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.StartAuthenticationAsync(new StartPasskeyAuthenticationRequest(user.Id) { Tenant = new TenantContext(tenantId) });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(storedChallenge?.TenantId, Is.EqualTo(tenantId));
            Assert.That(events.Events.Single().TenantId, Is.EqualTo(tenantId));
        }
    }

    [TestCaseSource(nameof(StartAuthenticationTenantFailures))]
    public async Task StartAuthenticationAsyncShouldRejectTenantMismatch(TestUser user, TenantContext? tenant)
    {
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        repo.Setup(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.StartAuthenticationAsync(new StartPasskeyAuthenticationRequest(user.Id) { Tenant = tenant });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFoundOrUnavailable));
            credentials.Verify(r => r.ListCredentialsForUserAsync(It.IsAny<Guid>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
            challenges.Verify(r => r.CreateAsync(It.IsAny<PasskeyChallenge>(), It.IsAny<CancellationToken>()), Times.Never);
            validator.Verify(v => v.CreateAuthenticationOptions(It.IsAny<PasskeyOptions>(), It.IsAny<string>(), It.IsAny<IReadOnlyList<UserCredential>>(), It.IsAny<string>()), Times.Never);
        }
    }

    [Test]
    public async Task StartAuthenticationAsyncShouldAllowGlobalUserWithOmittedTenant()
    {
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        PasskeyChallenge? storedChallenge = null;
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        repo.Setup(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(r => r.ListCredentialsForUserAsync(user.Id, true, It.IsAny<CancellationToken>())).ReturnsAsync([]);
        challenges.Setup(r => r.CreateAsync(It.IsAny<PasskeyChallenge>(), It.IsAny<CancellationToken>()))
            .Callback<PasskeyChallenge, CancellationToken>((challenge, _) => storedChallenge = challenge)
            .Returns(Task.CompletedTask);
        validator.Setup(v => v.CreateAuthenticationOptions(It.IsAny<PasskeyOptions>(), It.IsAny<string>(), It.IsAny<IReadOnlyList<UserCredential>>(), It.IsAny<string>()))
            .Returns("{}");
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.StartAuthenticationAsync(new StartPasskeyAuthenticationRequest(user.Id));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(storedChallenge?.TenantId, Is.Null);
        }
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
        var tenantId = Guid.NewGuid();
        var audit = new AuditContext(null, "2001:0db8::1", "Unit Test", "corr-passkey-start");

        var result = await service.StartAuthenticationAsync(new StartPasskeyAuthenticationRequest(Audit: audit) { Tenant = new TenantContext(tenantId) });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.RateLimited));
            Assert.That(rateLimiter.Attempts.Single().Purpose, Is.EqualTo("passkey-authentication-start"));
            Assert.That(rateLimiter.Attempts.Single().IpAddress, Is.EqualTo("2001:db8::1"));
            Assert.That(rateLimiter.Attempts.Single().CorrelationId, Is.EqualTo("corr-passkey-start"));
            Assert.That(events.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.AuthenticationRateLimited));
            Assert.That(events.Events.Single().TenantId, Is.EqualTo(tenantId));
        }

        validator.Verify(v => v.CreateAuthenticationOptions(It.IsAny<PasskeyOptions>(), It.IsAny<string>(), It.IsAny<IReadOnlyList<UserCredential>>(), It.IsAny<string>()), Times.Never);
        challenges.Verify(r => r.CreateAsync(It.IsAny<PasskeyChallenge>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task StartAuthenticationAsyncShouldScopeRateLimitByTenant()
    {
        var rateLimiter = new CaptureRateLimiter(allowed: false);
        var service = new PasskeyService(
            new Mock<IUserRepository>().Object,
            new Mock<ICredentialRepository>().Object,
            new Mock<IPasskeyChallengeRepository>().Object,
            new Mock<IPasskeyCeremonyValidator>().Object,
            CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher(), rateLimiter: rateLimiter));
        var audit = new AuditContext(null, "2001:0db8::1", "Unit Test", "corr-passkey-start");

        await service.StartAuthenticationAsync(new StartPasskeyAuthenticationRequest(Audit: audit) { Tenant = new TenantContext(Guid.NewGuid()) });
        await service.StartAuthenticationAsync(new StartPasskeyAuthenticationRequest(Audit: audit));

        Assert.That(rateLimiter.Attempts.Select(a => a.Key).Distinct().Count(), Is.EqualTo(2));
    }

    [Test]
    public async Task CompleteAuthenticationAsyncShouldRejectMismatchedTenantBeforeConsumingChallenge()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now, tenantId: Guid.NewGuid());
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var orchestrator = new Mock<IAuthenticationOrchestrator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        var service = new PasskeyService(
            new Mock<IUserRepository>().Object,
            new Mock<ICredentialRepository>().Object,
            challenges.Object,
            validator.Object,
            CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteAuthenticationAsync(new CompletePasskeyAuthenticationRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement, Guid.NewGuid()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyChallengeInvalid));
            challenges.Verify(r => r.ConsumeAsync(It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Never);
            validator.Verify(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), It.IsAny<PasskeyChallenge>(), It.IsAny<UserCredential>(), It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()), Times.Never);
            orchestrator.Verify(o => o.AuthenticateAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<MfaOrchestrationOptions?>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task CompleteAuthenticationAsyncShouldRejectOmittedTenantForTenantChallenge()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now, tenantId: Guid.NewGuid());
        var challenges = new Mock<IPasskeyChallengeRepository>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        var service = new PasskeyService(
            new Mock<IUserRepository>().Object,
            new Mock<ICredentialRepository>().Object,
            challenges.Object,
            new Mock<IPasskeyCeremonyValidator>().Object,
            CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteAuthenticationAsync(new CompletePasskeyAuthenticationRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyChallengeInvalid));
        challenges.Verify(r => r.ConsumeAsync(It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task CompleteAuthenticationAsyncShouldRejectUsernamelessCredentialOwnerOutsideChallengeTenant()
    {
        var tenantId = Guid.NewGuid();
        var user = new TestUser(Guid.NewGuid(), "test@example.com", TenantId: Guid.NewGuid());
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now, tenantId: tenantId);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var orchestrator = new Mock<IAuthenticationOrchestrator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);
        repo.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>())).ReturnsAsync(user);
        var service = new PasskeyService(
            repo.Object,
            credentials.Object,
            challenges.Object,
            validator.Object,
            CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteAuthenticationAsync(new CompletePasskeyAuthenticationRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement, tenantId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyCredentialNotFound));
            credentials.Verify(r => r.GetCredentialForUserAsync(It.IsAny<Guid>(), It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
            validator.Verify(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), It.IsAny<PasskeyChallenge>(), It.IsAny<UserCredential>(), It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()), Times.Never);
            orchestrator.Verify(o => o.AuthenticateAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<MfaOrchestrationOptions?>(), It.IsAny<CancellationToken>()), Times.Never);
        }
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
        var providerKey = new AuthenticationProviderKey(ProviderType.Passkey, "custom-passkey");
        var tenantId = Guid.NewGuid();
        var user = new TestUser(Guid.NewGuid(), "test@example.com", TenantId: tenantId);
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now, tenantId: tenantId);
        var credential = CreatePasskeyCredential(user.Id, "cred", now, providerKey);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var orchestrator = new Mock<IAuthenticationOrchestrator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);
        repo.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Passkey, providerKey.Name, "cred", It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Passkey, providerKey.Name, "cred", It.IsAny<CancellationToken>())).ReturnsAsync(credential);
        credentials.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), credential.Version, It.IsAny<CancellationToken>())).ReturnsAsync(true);
        validator.Setup(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), challenge, credential, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyAuthenticationVerificationResult("cred", 2, true));
        orchestrator.Setup(p => p.AuthenticateAsync(It.Is<AuthenticationContext>(c => c.UserId == user.Id && c.TenantId == tenantId), It.IsAny<IAuthenticationAssertion>(), It.IsAny<MfaOrchestrationOptions?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, user));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher(), options: new PasskeyOptions { Origin = "https://example.com", RelyingPartyId = "example.com", ProviderKey = providerKey }));

        var result = await service.CompleteAuthenticationAsync(new CompletePasskeyAuthenticationRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement, tenantId));

        Assert.That(result.Succeeded, Is.True);

        orchestrator.Verify(p => p.AuthenticateAsync(It.Is<AuthenticationContext>(c => c.UserId == user.Id && c.TenantId == tenantId), It.Is<IAuthenticationAssertion>(a => IsCapability(a, providerKey)), It.IsAny<MfaOrchestrationOptions?>(), It.IsAny<CancellationToken>()), Times.Once);
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
        orchestrator.Verify(p => p.AuthenticateAsync(It.IsAny<AuthenticationContext>(), It.Is<IAuthenticationAssertion>(a => IsCapability(a)), It.IsAny<MfaOrchestrationOptions?>(), It.IsAny<CancellationToken>()), Times.Once);
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
    public async Task StartFactorAsyncShouldPassTenantToHandshakeChallengeAndStoredChallenge()
    {
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var handshake = CreateHandshake(userId, tenantId);
        var credential = CreatePasskeyCredential(userId, "cred", DateTimeOffset.UtcNow);
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var handshakes = new Mock<IAuthenticationHandshakeService>();
        handshakes.Setup(h => h.BeginFactorChallengeAsync(It.Is<VerifyAuthenticationHandshakeRequest>(request => request.Context != null && request.Context.TenantId == tenantId), It.IsAny<CancellationToken>()))
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

        var result = await service.StartFactorAsync(new StartPasskeyFactorRequest("token") { Tenant = new TenantContext(tenantId) });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            challenges.Verify(r => r.CreateAsync(It.Is<PasskeyChallenge>(c => c.UserId == userId && c.TenantId == tenantId), It.IsAny<CancellationToken>()), Times.Once);
        }
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
            It.Is<IAuthenticationAssertion>(assertion => IsCapability(assertion) && ((IUserVerifiedAuthenticationAssertion)assertion).UserVerified),
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
        var providerKey = new AuthenticationProviderKey(ProviderType.Passkey, "custom-passkey");
        var tenantId = Guid.NewGuid();
        var user = new TestUser(Guid.NewGuid(), "test@example.com", TenantId: tenantId);
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now, user.Id, "hashed:token", "passkey", tenantId);
        var credential = CreatePasskeyCredential(user.Id, "cred", now, providerKey);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var orchestrator = new Mock<IAuthenticationOrchestrator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);
        repo.Setup(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Passkey, providerKey.Name, "cred", It.IsAny<CancellationToken>())).ReturnsAsync(credential);
        credentials.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), credential.Version, It.IsAny<CancellationToken>())).ReturnsAsync(true);
        validator.Setup(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), challenge, credential, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyAuthenticationVerificationResult("cred", 2, true));
        orchestrator.Setup(o => o.VerifyFactorAsync("token", "passkey", It.Is<AuthenticationContext>(c => c.UserId == user.Id && c.TenantId == tenantId), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, user));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher(), options: new PasskeyOptions { Origin = "https://example.com", RelyingPartyId = "example.com", ProviderKey = providerKey }));

        var result = await service.CompleteFactorAsync(new CompletePasskeyFactorRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement, "token", TenantId: tenantId));

        Assert.That(result.Succeeded, Is.True);
        orchestrator.Verify(o => o.VerifyFactorAsync("token", "passkey", It.Is<AuthenticationContext>(c => c.UserId == user.Id && c.TenantId == tenantId), It.Is<IAuthenticationAssertion>(a => IsCapability(a, providerKey)), It.IsAny<CancellationToken>()), Times.Once);
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

    [Test]
    public async Task CompleteFactorAsyncShouldRejectMismatchedTenantBeforeConsumingChallenge()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now, Guid.NewGuid(), "hashed:token", "passkey", Guid.NewGuid());
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var orchestrator = new Mock<IAuthenticationOrchestrator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        var service = new PasskeyService(
            new Mock<IUserRepository>().Object,
            new Mock<ICredentialRepository>().Object,
            challenges.Object,
            validator.Object,
            CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteFactorAsync(new CompletePasskeyFactorRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement, "token", TenantId: Guid.NewGuid()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyChallengeInvalid));
            challenges.Verify(r => r.ConsumeAsync(It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Never);
            validator.Verify(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), It.IsAny<PasskeyChallenge>(), It.IsAny<UserCredential>(), It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()), Times.Never);
            orchestrator.Verify(o => o.VerifyFactorAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task CompleteFactorAsyncShouldRejectOmittedTenantForTenantChallenge()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now, Guid.NewGuid(), "hashed:token", "passkey", Guid.NewGuid());
        var challenges = new Mock<IPasskeyChallengeRepository>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        var service = new PasskeyService(
            new Mock<IUserRepository>().Object,
            new Mock<ICredentialRepository>().Object,
            challenges.Object,
            new Mock<IPasskeyCeremonyValidator>().Object,
            CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteFactorAsync(new CompletePasskeyFactorRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement, "token"));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyChallengeInvalid));
        challenges.Verify(r => r.ConsumeAsync(It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Never);
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
        repo.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>())).ReturnsAsync(new TestUser(userId, "test@example.com"));
        var now = DateTimeOffset.UtcNow;
        var service = new PasskeyService(repo.Object, credentials.Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher(), sessionRepository: ActiveSessionRepository(userId)));

        var result = await service.RenameAsync(CreateRenameRequest(userId, credentialId, "", now));

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
        repo.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>())).ReturnsAsync(new TestUser(userId, "test@example.com"));
        var now = DateTimeOffset.UtcNow;
        var service = new PasskeyService(repo.Object, credentials.Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher(), sessionRepository: ActiveSessionRepository(userId)));

        var result = await service.RenameAsync(CreateRenameRequest(userId, credentialId, "Name", now));

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
        repo.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>())).ReturnsAsync(new TestUser(userId, "test@example.com"));
        credentials.Setup(r => r.ListCredentialsForUserAsync(userId, true, It.IsAny<CancellationToken>()))
            .ReturnsAsync([passkey, nullMetadataPasskey, malformedMetadataPasskey, other]);
        credentials.SetupSequence(r => r.UpdateCredentialAsync(passkey, passkey.Version, It.IsAny<CancellationToken>()))
            .ReturnsAsync(false)
            .ReturnsAsync(true)
            .ReturnsAsync(false)
            .ReturnsAsync(true);
        var service = new PasskeyService(repo.Object, credentials.Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher(), sessionRepository: ActiveSessionRepository(userId)));

        var list = await service.ListAsync(new ListPasskeysRequest(userId, TenantContext.Global));
        var renameMissing = await service.RenameAsync(CreateRenameRequest(userId, Guid.NewGuid(), "Name", now));
        var renameConflict = await service.RenameAsync(CreateRenameRequest(userId, passkey.Id, "Name", now));
        var renameSuccess = await service.RenameAsync(CreateRenameRequest(userId, passkey.Id, new string('x', 120), now));
        var revokeMissing = await service.RevokeAsync(CreateRevokeRequest(userId, Guid.NewGuid(), now));
        var revokeConflict = await service.RevokeAsync(CreateRevokeRequest(userId, passkey.Id, now));
        var revokeSuccess = await service.RevokeAsync(CreateRevokeRequest(userId, passkey.Id, now));

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

    [Test]
    public async Task ManagementMethodsShouldValidateActorTenantSessionProofAndAuditBeforeMutation()
    {
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var credential = CreatePasskeyCredential(userId, "cred", now);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        repo.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>())).ReturnsAsync(new TestUser(userId, "test@example.com", TenantId: tenantId));
        credentials.Setup(r => r.ListCredentialsForUserAsync(userId, true, It.IsAny<CancellationToken>())).ReturnsAsync([credential]);
        credentials.Setup(r => r.UpdateCredentialAsync(credential, credential.Version, It.IsAny<CancellationToken>())).ReturnsAsync(true);
        var service = new PasskeyService(repo.Object, credentials.Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(new FakeTimeProvider(now), sessionRepository: ActiveSessionRepository(userId, tenantId)));

        var wrongActor = await service.RenameAsync(CreateRenameRequest(Guid.NewGuid(), credential.Id, "Name", now, tenantId: tenantId));
        var wrongTenant = await service.RenameAsync(CreateRenameRequest(userId, credential.Id, "Name", now, tenantId: Guid.NewGuid()));
        var wrongSession = await service.RenameAsync(CreateRenameRequest(userId, credential.Id, "Name", now, tenantId: tenantId, currentSessionId: Guid.NewGuid(), proof: CreateMfaProof(userId, tenantId, now, RegistrationSessionId, ManagementPurpose)));
        var missingProof = await service.RenameAsync(CreateRenameRequest(userId, credential.Id, "Name", now, tenantId: tenantId, omitProof: true));
        var expiredProof = await service.RenameAsync(CreateRenameRequest(userId, credential.Id, "Name", now, tenantId: tenantId, proof: CreateMfaProof(userId, tenantId, now.Subtract(RegistrationFreshnessWindow).AddTicks(-1), RegistrationSessionId, ManagementPurpose)));
        var wrongPurpose = await service.RenameAsync(CreateRenameRequest(userId, credential.Id, "Name", now, tenantId: tenantId, proof: CreateMfaProof(userId, tenantId, now, RegistrationSessionId, RegistrationPurpose)));
        var missingAudit = await service.RenameAsync(CreateRenameRequest(userId, credential.Id, "Name", now, tenantId: tenantId, omitAudit: true));
        var revoke = await service.RevokeAsync(CreateRevokeRequest(userId, credential.Id, now, tenantId: tenantId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(wrongActor.Succeeded, Is.False);
            Assert.That(wrongTenant.Succeeded, Is.False);
            Assert.That(wrongSession.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            Assert.That(missingProof.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            Assert.That(expiredProof.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpExpired));
            Assert.That(wrongPurpose.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            Assert.That(missingAudit.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(revoke.Succeeded, Is.True);
        }

        credentials.Verify(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task ListAsyncShouldReturnEmptyForInvalidActorBoundary()
    {
        var credentials = new Mock<ICredentialRepository>();
        var service = new PasskeyService(new Mock<IUserRepository>().Object, credentials.Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies());

        var result = await service.ListAsync(new ListPasskeysRequest(Guid.Empty, TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result, Is.Empty);
            credentials.Verify(r => r.ListCredentialsForUserAsync(It.IsAny<Guid>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public void ListAsyncShouldRejectNullTenant()
    {
        var service = new PasskeyService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies());

        Assert.ThrowsAsync<ArgumentNullException>(() => service.ListAsync(new ListPasskeysRequest(Guid.NewGuid(), null!)));
    }

    [Test]
    public async Task RevokeAsyncShouldRejectBoundaryFailureBeforeCredentialLookup()
    {
        var userId = Guid.NewGuid();
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var credentials = new Mock<ICredentialRepository>();
        var service = new PasskeyService(new Mock<IUserRepository>().Object, credentials.Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(new FakeTimeProvider(now)));

        var result = await service.RevokeAsync(CreateRevokeRequest(userId, Guid.NewGuid(), now, proof: CreateMfaProof(userId, null, now, RegistrationSessionId, RegistrationPurpose)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            credentials.Verify(r => r.ListCredentialsForUserAsync(It.IsAny<Guid>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
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

        Assert.ThrowsAsync<InvalidOperationException>(() => service.StartRegistrationAsync(new StartPasskeyRegistrationRequest(user.Id, "Laptop") { Tenant = tenant }));
        challenges.Verify(r => r.CreateAsync(It.IsAny<PasskeyChallenge>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    private static IEnumerable<TestCaseData> StartAuthenticationTenantFailures()
    {
        yield return new TestCaseData(new TestUser(Guid.NewGuid(), "tenant@example.com", TenantId: Guid.NewGuid()), null).SetName("tenant user with omitted tenant");
        yield return new TestCaseData(new TestUser(Guid.NewGuid(), "tenant@example.com", TenantId: Guid.NewGuid()), new TenantContext(Guid.NewGuid())).SetName("tenant user with wrong tenant");
        yield return new TestCaseData(new TestUser(Guid.NewGuid(), "global@example.com"), new TenantContext(Guid.NewGuid())).SetName("global user with tenant context");
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

        var result = await service.CompleteRegistrationAsync(CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement, tenant: requestTenant));

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
            RegistrationProofType = "fresh-primary",
            RegistrationProofSessionId = RegistrationSessionId,
            RegistrationProofExpiresAt = now.Add(RegistrationFreshnessWindow),
            Challenge = "challenge",
            OptionsJson = "{}",
            RelyingPartyId = "example.com",
            Origin = "https://example.com",
            CreatedAt = now,
            ExpiresAt = now.AddMinutes(5)
        };
    }

    private static PasskeyChallenge CopyRegistrationChallenge(PasskeyChallenge challenge, string? proofType = null, Guid? sessionId = null, DateTimeOffset? proofExpiresAt = null, bool clearSessionId = false, bool clearExpiresAt = false)
    {
        return new PasskeyChallenge
        {
            Id = challenge.Id,
            Version = challenge.Version,
            Purpose = challenge.Purpose,
            UserId = challenge.UserId,
            TenantId = challenge.TenantId,
            HandshakeTokenHash = challenge.HandshakeTokenHash,
            FactorType = challenge.FactorType,
            DisplayName = challenge.DisplayName,
            RegistrationProofType = proofType ?? challenge.RegistrationProofType,
            RegistrationProofSessionId = clearSessionId ? null : sessionId ?? challenge.RegistrationProofSessionId,
            RegistrationProofExpiresAt = clearExpiresAt ? null : proofExpiresAt ?? challenge.RegistrationProofExpiresAt,
            Challenge = challenge.Challenge,
            OptionsJson = challenge.OptionsJson,
            RelyingPartyId = challenge.RelyingPartyId,
            Origin = challenge.Origin,
            CreatedAt = challenge.CreatedAt,
            ExpiresAt = challenge.ExpiresAt,
            ConsumedAt = challenge.ConsumedAt
        };
    }

    private static StartPasskeyRegistrationRequest CreateStartRegistrationRequest(Guid userId, string displayName, TenantContext? tenant = null, AuditContext? audit = null, DateTimeOffset? now = null, Guid? sessionId = null)
    {
        var resolvedNow = now ?? DateTimeOffset.UtcNow;
        return new StartPasskeyRegistrationRequest(userId, displayName)
        {
            Tenant = tenant,
            Audit = audit,
            CurrentSessionId = sessionId ?? RegistrationSessionId,
            FreshPrimaryAuthenticationProof = CreatePrimaryProof(userId, tenant?.TenantId, resolvedNow, sessionId ?? RegistrationSessionId)
        };
    }

    private static CompletePasskeyRegistrationRequest CreateCompleteRegistrationRequest(PasskeyChallenge challenge, JsonElement credentialResponse, string? displayName = null, TenantContext? tenant = null, Guid? userId = null, DateTimeOffset? now = null, Guid? sessionId = null)
    {
        var resolvedUserId = userId ?? challenge.UserId.GetValueOrDefault();
        var resolvedTenant = tenant ?? TenantContext.Global;
        var resolvedNow = now ?? challenge.CreatedAt;
        var resolvedSessionId = sessionId ?? challenge.RegistrationProofSessionId ?? RegistrationSessionId;
        return new CompletePasskeyRegistrationRequest(challenge.Id, credentialResponse, displayName, resolvedUserId)
        {
            Tenant = resolvedTenant,
            CurrentSessionId = resolvedSessionId,
            FreshPrimaryAuthenticationProof = CreatePrimaryProof(resolvedUserId, resolvedTenant.TenantId, resolvedNow, resolvedSessionId)
        };
    }

    private static FreshPrimaryAuthenticationProof CreatePrimaryProof(Guid userId, Guid? tenantId, DateTimeOffset now, Guid sessionId, string? purpose = RegistrationPurpose)
    {
        var stepUp = new StepUpAuthenticationService(new FakeTimeProvider(now));
        var session = new AuthenticationSession
        {
            Id = sessionId,
            UserId = userId,
            TenantId = tenantId,
            TokenHash = "hash",
            CreatedAt = now.AddMinutes(-1),
            AuthenticatedAt = now,
            ExpiresAt = now.AddHours(1)
        };
        var result = stepUp.CreateFreshPrimaryAuthenticationProof(CreateValidatedSession(session), RegistrationFreshnessWindow, purpose);
        return result.Value!;
    }

    private static FreshMfaVerificationProof CreateMfaProof(Guid userId, Guid? tenantId, DateTimeOffset now, Guid sessionId, string? purpose = RegistrationPurpose)
    {
        var stepUp = new StepUpAuthenticationService(new FakeTimeProvider(now));
        var session = new AuthenticationSession
        {
            Id = sessionId,
            UserId = userId,
            TenantId = tenantId,
            TokenHash = "hash",
            CreatedAt = now.AddMinutes(-1),
            AuthenticatedAt = now.AddMinutes(-1),
            AdditionalVerificationAt = now,
            AdditionalVerificationProvider = AuthenticationProviderKey.Passkey,
            AdditionalVerificationFactor = AuthenticationFactorTypes.Passkey,
            ExpiresAt = now.AddHours(1)
        };
        var result = stepUp.CreateFreshMfaProof(CreateValidatedSession(session), new StepUpRequirement(RegistrationFreshnessWindow, Purpose: purpose));
        return result.Value!;
    }

    private static ValidatedAuthenticationSession CreateValidatedSession(AuthenticationSession session) =>
        (ValidatedAuthenticationSession)Activator.CreateInstance(typeof(ValidatedAuthenticationSession),
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic, null, [session], null)!;

    private static RenamePasskeyRequest CreateRenameRequest(
        Guid userId,
        Guid credentialId,
        string displayName,
        DateTimeOffset now,
        Guid? tenantId = null,
        Guid? currentSessionId = null,
        FreshMfaVerificationProof? proof = null,
        AuditContext? audit = null,
        bool omitProof = false,
        bool omitAudit = false)
    {
        var sessionId = currentSessionId ?? RegistrationSessionId;
        return new RenamePasskeyRequest(
            userId,
            tenantId.HasValue ? new TenantContext(tenantId.Value) : TenantContext.Global,
            sessionId,
            omitProof ? null : proof ?? CreateMfaProof(userId, tenantId, now, sessionId, ManagementPurpose),
            credentialId,
            displayName,
            omitAudit ? null : audit ?? new AuditContext(userId, "127.0.0.1", "NUnit", "corr"));
    }

    private static RevokePasskeyRequest CreateRevokeRequest(
        Guid userId,
        Guid credentialId,
        DateTimeOffset now,
        Guid? tenantId = null,
        Guid? currentSessionId = null,
        FreshMfaVerificationProof? proof = null,
        AuditContext? audit = null)
    {
        var sessionId = currentSessionId ?? RegistrationSessionId;
        return new RevokePasskeyRequest(
            userId,
            tenantId.HasValue ? new TenantContext(tenantId.Value) : TenantContext.Global,
            sessionId,
            proof ?? CreateMfaProof(userId, tenantId, now, sessionId, ManagementPurpose),
            credentialId,
            audit ?? new AuditContext(userId, "127.0.0.1", "NUnit", "corr"));
    }

    private static PasskeyChallenge CreateAuthenticationChallenge(
        DateTimeOffset now,
        Guid? userId = null,
        string? handshakeTokenHash = null,
        string? factorType = null,
        Guid? tenantId = null)
    {
        return new PasskeyChallenge
        {
            Id = Guid.NewGuid(),
            Version = "v1",
            Purpose = "passkey-authentication",
            UserId = userId,
            TenantId = tenantId,
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

    private static AuthenticationHandshake CreateHandshake(Guid userId, Guid? tenantId = null)
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
            new HashSet<string>())
        {
            TenantId = tenantId
        };
    }

    private static UserCredential CreatePasskeyCredential(Guid userId, string providerKey, DateTimeOffset now, AuthenticationProviderKey? authenticationProvider = null)
    {
        var provider = authenticationProvider ?? AuthenticationProviderKey.Passkey;
        return new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = provider.Type,
            ProviderName = provider.Name,
            ProviderKey = providerKey,
            Version = "v1",
            CreatedAt = now,
            Status = CredentialStatus.Active,
            Metadata = JsonSerializer.Serialize(new PasskeyCredentialMetadata { DisplayName = "Laptop", PublicKey = "pk", SignCount = 1, Transports = ["internal"] }, PasskeyJson.Options)
        };
    }

    private static bool IsCapability(IAuthenticationAssertion assertion, AuthenticationProviderKey? providerKey = null) =>
        PasskeyService.TryReadCapability(assertion, providerKey ?? AuthenticationProviderKey.Passkey, out _, out _);

    private static PasskeyServiceDependencies CreateDependencies(
        TimeProvider? timeProvider = null,
        ISecurityEventSink? securityEventSink = null,
        IAuthenticationOrchestrator? authenticationOrchestrator = null,
        IAuthenticationHandshakeService? handshakeService = null,
        ISecureTokenHasher? tokenHasher = null,
        IAuthenticationRateLimiter? rateLimiter = null,
        IAuthenticationSessionRepository? sessionRepository = null,
        PasskeyOptions? options = null,
        IAshlarTransactionProvider? transactionProvider = null)
    {
        return new PasskeyServiceDependencies(
            Options.Create(options ?? new PasskeyOptions { Origin = "https://example.com", RelyingPartyId = "example.com" }),
            authenticationOrchestrator ?? new Mock<IAuthenticationOrchestrator>().Object,
            handshakeService ?? new Mock<IAuthenticationHandshakeService>().Object,
            tokenHasher ?? new TestTokenHasher(),
            rateLimiter ?? AllowRateLimiter.Instance,
            sessionRepository ?? ActiveSessionRepository(),
            new PasskeyServiceInfrastructure(timeProvider, securityEventSink, transactionProvider));
    }

    [Test]
    public async Task RenameAndRevokeShouldRejectRevokedSourceSession()
    {
        var userId = Guid.NewGuid();
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var sessions = new Mock<IAuthenticationSessionRepository>();
        sessions.Setup(x => x.GetSessionAsync(RegistrationSessionId, It.IsAny<CancellationToken>())).ReturnsAsync(new AuthenticationSession
        {
            Id = RegistrationSessionId,
            UserId = userId,
            TokenHash = "hash",
            CreatedAt = now.AddMinutes(-1),
            ExpiresAt = now.AddHours(1),
            RevokedAt = now
        });
        var credentials = new Mock<ICredentialRepository>();
        var service = new PasskeyService(new Mock<IUserRepository>().Object, credentials.Object,
            new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object,
            CreateDependencies(new FakeTimeProvider(now), sessionRepository: sessions.Object));

        var rename = await service.RenameAsync(CreateRenameRequest(userId, Guid.NewGuid(), "Name", now));
        var revoke = await service.RevokeAsync(CreateRevokeRequest(userId, Guid.NewGuid(), now));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(rename.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            Assert.That(revoke.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
        }
        credentials.VerifyNoOtherCalls();
    }

    [Test]
    public async Task RenameShouldRejectSourceSessionOwnedByAnotherUser()
    {
        var userId = Guid.NewGuid();
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var credentials = new Mock<ICredentialRepository>();
        var service = new PasskeyService(new Mock<IUserRepository>().Object, credentials.Object,
            new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object,
            CreateDependencies(new FakeTimeProvider(now), sessionRepository: ActiveSessionRepository(Guid.NewGuid())));

        var result = await service.RenameAsync(CreateRenameRequest(userId, Guid.NewGuid(), "Name", now));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
        credentials.VerifyNoOtherCalls();
    }

    [Test]
    public async Task RenameShouldRejectSourceSessionWithoutActorTenant()
    {
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var credentials = new Mock<ICredentialRepository>();
        var service = new PasskeyService(new Mock<IUserRepository>().Object, credentials.Object,
            new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object,
            CreateDependencies(new FakeTimeProvider(now), sessionRepository: ActiveSessionRepository(userId)));

        var result = await service.RenameAsync(CreateRenameRequest(userId, Guid.NewGuid(), "Name", now, tenantId: tenantId));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
        credentials.VerifyNoOtherCalls();
    }

    [Test]
    public async Task RenameShouldRejectUnavailableActorAfterSessionValidation()
    {
        var userId = Guid.NewGuid();
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var credentials = new Mock<ICredentialRepository>();
        var service = new PasskeyService(new Mock<IUserRepository>().Object, credentials.Object,
            new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object,
            CreateDependencies(new FakeTimeProvider(now), sessionRepository: ActiveSessionRepository(userId)));

        var result = await service.RenameAsync(CreateRenameRequest(userId, Guid.NewGuid(), "Name", now));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFoundOrUnavailable));
        credentials.VerifyNoOtherCalls();
    }

    private static IAuthenticationSessionRepository ActiveSessionRepository(Guid userId = default, Guid? tenantId = null)
    {
        var repository = new Mock<IAuthenticationSessionRepository>();
        repository.Setup(x => x.GetSessionAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>())).ReturnsAsync((Guid id, CancellationToken _) => new AuthenticationSession
        {
            Id = id,
            UserId = userId,
            TenantId = tenantId,
            TokenHash = "hash",
            CreatedAt = DateTimeOffset.MinValue,
            ExpiresAt = DateTimeOffset.MaxValue
        });
        return repository.Object;
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

internal sealed class ThrowingSecurityEventSink : ISecurityEventSink
{
    public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
    {
        throw new InvalidOperationException("required audit failed");
    }
}

internal sealed class RecordingTransactionProvider : IAshlarTransactionProvider
{
    public RecordingTransaction Transaction { get; } = new();

    public Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult<IAshlarTransaction>(Transaction);
    }
}

internal sealed class RecordingTransaction : IAshlarTransaction
{
    private readonly List<Func<CancellationToken, Task>> _hooks = [];
    public bool Committed { get; private set; }

    public async Task CommitAsync(CancellationToken cancellationToken = default)
    {
        Committed = true;
        foreach (var hook in _hooks)
        {
            try
            {
                await hook(CancellationToken.None);
            }
            catch (Exception)
            {
            }
        }
    }

    public Task RollbackAsync(CancellationToken cancellationToken = default)
    {
        _hooks.Clear();
        return Task.CompletedTask;
    }

    public void OnCommitted(Func<CancellationToken, Task> callback)
    {
        _hooks.Add(callback ?? throw new ArgumentNullException(nameof(callback)));
    }

    public ValueTask DisposeAsync()
    {
        return ValueTask.CompletedTask;
    }
}

