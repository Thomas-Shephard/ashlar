using Ashlar.Testing;
using Ashlar.Passkeys;
using System.Text.Json;
using Ashlar.Auditing;
using Ashlar.Identity.Models.Passkeys;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Passkeys;

internal sealed class PasskeyServiceTests
{
    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<PasskeyServiceDependencies, TestStoreInfrastructure> StoreInfrastructure = [];
    private readonly Dictionary<Guid, AuthenticationSession> _proofSessions = [];
    internal static readonly Guid RegistrationSessionId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly TimeSpan RegistrationFreshnessWindow = TimeSpan.FromMinutes(10);
    private const string RegistrationPurpose = "passkey-registration";
    private const string ManagementPurpose = "passkey-management";

    [Test]
    public void RegistrationBoundaryModelsShouldKeepCapabilitySeparateAndValidateContext()
    {
        var userId = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        var primary = CreatePrimaryProof(userId, null, now, RegistrationSessionId);
        var mfa = CreateMfaProof(userId, null, now, RegistrationSessionId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(new StartPasskeyRegistrationRequest("Laptop").DisplayName, Is.EqualTo("Laptop"));
            Assert.That(new CompletePasskeyRegistrationRequest(Guid.NewGuid(), default, "Laptop").DisplayName, Is.EqualTo("Laptop"));
            Assert.Throws<ArgumentException>(() => _ = new PasskeyRegistrationVerificationContext(Guid.Empty, TenantContext.Global, RegistrationSessionId, new AuditContext(userId), freshPrimaryAuthenticationProof: primary));
            Assert.Throws<ArgumentException>(() => _ = new PasskeyRegistrationVerificationContext(userId, TenantContext.Global, Guid.Empty, new AuditContext(userId), freshPrimaryAuthenticationProof: primary));
            Assert.Throws<ArgumentNullException>(() => _ = new PasskeyRegistrationVerificationContext(userId, null!, RegistrationSessionId, new AuditContext(userId), freshPrimaryAuthenticationProof: primary));
            Assert.Throws<ArgumentNullException>(() => _ = new PasskeyRegistrationVerificationContext(userId, TenantContext.Global, RegistrationSessionId, null!, freshPrimaryAuthenticationProof: primary));
            Assert.Throws<ArgumentNullException>(() => _ = new PasskeyRegistrationVerificationContext(userId, null!, RegistrationSessionId, null!));
            Assert.Throws<ArgumentException>(() => _ = new PasskeyRegistrationVerificationContext(userId, TenantContext.Global, RegistrationSessionId, new AuditContext(userId)));
            Assert.Throws<ArgumentException>(() => _ = new PasskeyRegistrationVerificationContext(userId, TenantContext.Global, RegistrationSessionId, new AuditContext(userId), mfa, primary));
        }
    }

    [Test]
    public void RegistrationShouldGuardContextAndRequestBeforeProviderAccess()
    {
        var userId = Guid.NewGuid();
        var proof = FreshMfaVerificationProofFactory.Create(userId, null, RegistrationSessionId, DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddMinutes(5), RegistrationPurpose);
        var verification = new PasskeyRegistrationVerificationContext(userId, TenantContext.Global, RegistrationSessionId,
            new AuditContext(userId), freshMfaProof: proof);
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var service = CreateVerifiedPasskeyService(new Mock<IUserRepository>().Object, credentials.Object, challenges.Object,
            new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies());

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentNullException>(() => service.StartRegistrationAsync(null!, new StartPasskeyRegistrationRequest("Laptop")));
            Assert.ThrowsAsync<ArgumentNullException>(() => service.StartRegistrationAsync(verification, null!));
            Assert.ThrowsAsync<ArgumentNullException>(() => service.CompleteRegistrationAsync(null!, new CompletePasskeyRegistrationRequest(Guid.NewGuid(), default, null)));
            Assert.ThrowsAsync<ArgumentNullException>(() => service.CompleteRegistrationAsync(verification, null!));
        }
        credentials.VerifyNoOtherCalls();
        challenges.VerifyNoOtherCalls();
    }

    [Test]
    public async Task RegistrationShouldRejectProofAfterSourceSessionRevocation()
    {
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var sessions = new Mock<IAuthenticationSessionRepository>();
        sessions.Setup(r => r.GetSessionAsync(RegistrationSessionId, It.IsAny<CancellationToken>())).ReturnsAsync(new AuthenticationSession
        {
            Id = RegistrationSessionId,
            UserId = user.Id,
            TokenHash = "hash",
            CreatedAt = now.AddMinutes(-1),
            AuthenticatedAt = now,
            ExpiresAt = now.AddHours(1),
            RevokedAt = now
        });
        var users = new Mock<IUserRepository>();
        users.Setup(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        var credentials = new Mock<ICredentialRepository>();
        credentials.Setup(r => r.ListCredentialsForUserAsync(user.Id, true, It.IsAny<CancellationToken>())).ReturnsAsync([]);
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var challenge = CreateRegistrationChallenge(now, user.Id);
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        var service = CreateVerifiedPasskeyService(users.Object, credentials.Object, challenges.Object, new Mock<IPasskeyCeremonyValidator>().Object,
            CreateDependencies(new FakeTimeProvider(now), sessionRepository: sessions.Object));

        var (startVerification, startRequest) = CreateStartRegistrationRequest(user.Id, "Passkey", now: now);
        var start = Assert.ThrowsAsync<AshlarOperationException>(() => service.StartRegistrationAsync(startVerification, startRequest));
        using var response = JsonDocument.Parse("{}");
        var (completeVerification, completeRequest) = CreateCompleteRegistrationRequest(challenge, response.RootElement, now: now);
        var complete = await service.CompleteRegistrationAsync(completeVerification, completeRequest);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(start!.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            Assert.That(complete.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
        }
        challenges.Verify(r => r.CreateAsync(It.IsAny<PasskeyChallenge>(), It.IsAny<CancellationToken>()), Times.Never);
        credentials.Verify(r => r.CreateOrReplaceCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()), Times.Never);
    }

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(securityEventSink: events, authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));
        var audit = new AuditContext(user.Id, "127.0.0.1", "Unit Test", "trace-1");

        var (verification, request) = CreateStartRegistrationRequest(user.Id, " ", audit: audit);
        var result = await service.StartRegistrationAsync(verification, request);

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

    [TestCase(null)]
    [TestCase(false)]
    [TestCase(true)]
    public void StartRegistrationAsyncShouldRejectInvalidAuditActorBeforeChallengeOrAudit(bool? mismatched)
    {
        var actorUserId = Guid.NewGuid();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var events = new RecordingSecurityEventSink();
        var service = CreateVerifiedPasskeyService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object,
            challenges.Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(securityEventSink: events));
        var audit = mismatched.HasValue ? new AuditContext(mismatched.Value ? Guid.NewGuid() : null) : new AuditContext(null);
        var verification = new PasskeyRegistrationVerificationContext(actorUserId, TenantContext.Global, RegistrationSessionId, audit,
            freshMfaProof: CreateMfaProof(actorUserId, null, DateTimeOffset.UtcNow, RegistrationSessionId));

        var exception = Assert.ThrowsAsync<AshlarOperationException>(() => service.StartRegistrationAsync(verification, new StartPasskeyRegistrationRequest("Laptop")));

        Assert.That(exception!.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        challenges.Verify(r => r.CreateAsync(It.IsAny<PasskeyChallenge>(), It.IsAny<CancellationToken>()), Times.Never);
        Assert.That(events.Events, Is.Empty);
    }

    [Test]
    public void StartRegistrationAsyncShouldThrowWhenUserIsMissing()
    {
        var service = CreateVerifiedPasskeyService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));
        var userId = Guid.NewGuid();

        var verification = new PasskeyRegistrationVerificationContext(userId, TenantContext.Global, RegistrationSessionId, new AuditContext(userId),
            freshMfaProof: CreateMfaProof(userId, null, DateTimeOffset.UtcNow, RegistrationSessionId));

        Assert.ThrowsAsync<InvalidOperationException>(() => service.StartRegistrationAsync(verification, new StartPasskeyRegistrationRequest("Laptop")));
    }

    [Test]
    public void CompleteRegistrationAsyncShouldRejectNullRequest()
    {
        var service = CreateVerifiedPasskeyService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies());

        Assert.ThrowsAsync<ArgumentNullException>(() => service.CompleteRegistrationAsync(null!, new CompletePasskeyRegistrationRequest(Guid.NewGuid(), default, null)));
    }

    [TestCase(null)]
    [TestCase(false)]
    [TestCase(true)]
    public async Task CompleteRegistrationAsyncShouldRejectInvalidAuditActorBeforeMutationOrAudit(bool? mismatched)
    {
        var actorUserId = Guid.NewGuid();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var events = new RecordingSecurityEventSink();
        var service = CreateVerifiedPasskeyService(new Mock<IUserRepository>().Object, credentials.Object,
            challenges.Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(securityEventSink: events));
        var audit = mismatched.HasValue ? new AuditContext(mismatched.Value ? Guid.NewGuid() : null) : new AuditContext(null);
        var verification = new PasskeyRegistrationVerificationContext(actorUserId, TenantContext.Global, RegistrationSessionId, audit,
            freshMfaProof: CreateMfaProof(actorUserId, null, DateTimeOffset.UtcNow, RegistrationSessionId));
        var request = new CompletePasskeyRegistrationRequest(Guid.NewGuid(), JsonDocument.Parse("{}").RootElement, null);

        var result = await service.CompleteRegistrationAsync(verification, request);

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        challenges.Verify(r => r.ConsumeAsync(It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Never);
        credentials.Verify(r => r.CreateOrReplaceCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()), Times.Never);
        Assert.That(events.Events, Is.Empty);
    }

    [Test]
    public void ConstructorShouldRejectNullAuthenticationProviders()
    {
        Assert.Throws<ArgumentNullException>(() => _ = CreateVerifiedPasskeyService(
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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies());

        var verification = new PasskeyRegistrationVerificationContext(user.Id, TenantContext.Global, RegistrationSessionId, new AuditContext(user.Id),
            freshMfaProof: CreateMfaProof(user.Id, null, DateTimeOffset.UtcNow, RegistrationSessionId));

        Assert.ThrowsAsync<InvalidOperationException>(() => service.StartRegistrationAsync(verification, new StartPasskeyRegistrationRequest("Laptop")));
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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies());
        var verification = new PasskeyRegistrationVerificationContext(user.Id, TenantContext.Global, RegistrationSessionId, new AuditContext(user.Id),
            freshPrimaryAuthenticationProof: CreatePrimaryProof(Guid.NewGuid(), null, DateTimeOffset.UtcNow, RegistrationSessionId));

        var ex = Assert.ThrowsAsync<AshlarOperationException>(() => service.StartRegistrationAsync(verification, new StartPasskeyRegistrationRequest("Laptop")));

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now)));
        var verification = new PasskeyRegistrationVerificationContext(user.Id, new TenantContext(tenantId), RegistrationSessionId, new AuditContext(user.Id),
            freshPrimaryAuthenticationProof: CreatePrimaryProof(user.Id, Guid.NewGuid(), now, RegistrationSessionId));

        var ex = Assert.ThrowsAsync<AshlarOperationException>(() => service.StartRegistrationAsync(verification, new StartPasskeyRegistrationRequest("Laptop")));

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now)));
        var verification = new PasskeyRegistrationVerificationContext(user.Id, TenantContext.Global, RegistrationSessionId, new AuditContext(user.Id),
            freshPrimaryAuthenticationProof: CreatePrimaryProof(user.Id, null, now, RegistrationSessionId, "totp-enrollment"));

        var ex = Assert.ThrowsAsync<AshlarOperationException>(() => service.StartRegistrationAsync(verification, new StartPasskeyRegistrationRequest("Laptop")));

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, [provider], CreateDependencies());

        var (verification, request) = CreateStartRegistrationRequest(user.Id, "Laptop");
        var ex = Assert.ThrowsAsync<AshlarOperationException>(() => service.StartRegistrationAsync(verification, request));

        Assert.That(ex!.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
        await Task.CompletedTask;
    }

    [TestCase("totp", false)]
    [TestCase("RecoveryCode", true)]
    public void StartRegistrationAsyncShouldRequireMfaProofForNonPasskeyAdditionalFactor(string providerName, bool recoveryCode)
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var providerKey = new AuthenticationProviderKey(recoveryCode ? ProviderType.RecoveryCode : ProviderType.Mfa, providerName);
        var credential = CreatePasskeyCredential(user.Id, "secondary", now, providerKey);
        var users = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        users.Setup(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(r => r.ListCredentialsForUserAsync(user.Id, true, It.IsAny<CancellationToken>())).ReturnsAsync([credential]);
        var provider = new Mock<ISecondaryAuthenticationFactorProvider>();
        provider.SetupGet(p => p.Key).Returns(providerKey);
        var service = CreateVerifiedPasskeyService(users.Object, credentials.Object, new Mock<IPasskeyChallengeRepository>().Object,
            new Mock<IPasskeyCeremonyValidator>().Object, [provider.Object], CreateDependencies(new FakeTimeProvider(now)));

        var (verification, request) = CreateStartRegistrationRequest(user.Id, "Laptop", now: now);
        var exception = Assert.ThrowsAsync<AshlarOperationException>(() => service.StartRegistrationAsync(verification, request));

        Assert.That(exception!.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
    }

    [Test]
    public async Task StartRegistrationAsyncShouldIgnoreRevokedAdditionalFactorAndExcludeOnlyPasskeys()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var user = new TestUser(Guid.NewGuid(), "test@example.com");
        var providerKey = new AuthenticationProviderKey(ProviderType.Mfa, "totp");
        var revoked = CreatePasskeyCredential(user.Id, "secondary", now, providerKey);
        revoked.RevokedAt = now;
        var passkey = CreatePasskeyCredential(user.Id, "passkey", now);
        var users = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        users.Setup(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(r => r.ListCredentialsForUserAsync(user.Id, true, It.IsAny<CancellationToken>())).ReturnsAsync([revoked, passkey]);
        validator.Setup(v => v.CreateRegistrationOptions(It.IsAny<PasskeyOptions>(), user, "Laptop", It.IsAny<string>(),
                It.Is<IReadOnlyList<UserCredential>>(listed => listed.Count == 1 && listed[0] == passkey)))
            .Returns("{}");
        var provider = new Mock<ISecondaryAuthenticationFactorProvider>();
        provider.SetupGet(p => p.Key).Returns(providerKey);
        var service = CreateVerifiedPasskeyService(users.Object, credentials.Object, new Mock<IPasskeyChallengeRepository>().Object,
            validator.Object, [provider.Object], CreateDependencies(new FakeTimeProvider(now)));

        var (verification, request) = CreateStartRegistrationRequest(user.Id, "Laptop", now: now);
        await service.StartRegistrationAsync(verification, request);

        validator.VerifyAll();
        credentials.Verify(r => r.ListCredentialsForUserAsync(user.Id, true, It.IsAny<CancellationToken>()), Times.Once);
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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, [provider], CreateDependencies(new FakeTimeProvider(now)));
        var verification = new PasskeyRegistrationVerificationContext(user.Id, TenantContext.Global, RegistrationSessionId, new AuditContext(user.Id),
            freshMfaProof: CreateMfaProof(user.Id, null, now, RegistrationSessionId));

        await service.StartRegistrationAsync(verification, new StartPasskeyRegistrationRequest("Laptop"));

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies());

        var (verification, request) = CreateStartRegistrationRequest(user.Id, "Laptop", new TenantContext(tenantId));
        var result = await service.StartRegistrationAsync(verification, request);

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies());

        var (verification, request) = CreateStartRegistrationRequest(user.Id, "Laptop");
        var result = await service.StartRegistrationAsync(verification, request);

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
        var validator = new Mock<IPasskeyCeremonyValidator>().Object;
        var dependencies = CreateDependencies();
        var store = CreateStore(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, new Mock<IPasskeyChallengeRepository>().Object, dependencies);
        var proofValidator = StoreInfrastructure.GetValue(dependencies, _ => throw new InvalidOperationException()).ProofValidator;
        Assert.Throws<ArgumentNullException>(() => _ = new PasskeyService(null!, store, proofValidator, validator, [], dependencies));
        Assert.Throws<ArgumentNullException>(() => _ = new PasskeyService(store, null!, proofValidator, validator, [], dependencies));
        Assert.Throws<ArgumentNullException>(() => _ = new PasskeyService(store, store, null!, validator, [], dependencies));
        Assert.Throws<ArgumentNullException>(() => _ = new PasskeyService(store, store, proofValidator, null!, [], dependencies));
        Assert.Throws<ArgumentNullException>(() => _ = new PasskeyService(store, store, proofValidator, validator, null!, dependencies));
        Assert.Throws<ArgumentNullException>(() => _ = new PasskeyService(store, store, proofValidator, validator, [], null!));

        var valid = CreateDependencies();
        var infrastructure = new PasskeyServiceInfrastructure(valid.TimeProvider, valid.SecurityEventSink, valid.TransactionProvider);
        var options = Options.Create(new PasskeyOptions { Origin = "https://example.com", RelyingPartyId = "example.com" });
        var orchestrator = new Mock<IAuthenticationOrchestrator>().Object;
        var handshakes = new Mock<IAuthenticationHandshakeService>().Object;

        Assert.Throws<ArgumentNullException>(() => _ = new PasskeyServiceDependencies(
            options, null!, handshakes, new TestTokenHasher(), AllowRateLimiter.Instance, infrastructure));
        Assert.Throws<ArgumentNullException>(() => _ = new PasskeyServiceDependencies(
            options, orchestrator, null!, new TestTokenHasher(), AllowRateLimiter.Instance, infrastructure));
        Assert.Throws<ArgumentNullException>(() => _ = new PasskeyServiceDependencies(
            options, orchestrator, handshakes, null!, AllowRateLimiter.Instance, infrastructure));
        Assert.Throws<ArgumentNullException>(() => _ = new PasskeyServiceDependencies(
            options, orchestrator, handshakes, new TestTokenHasher(), null!, infrastructure));
        Assert.Throws<ArgumentNullException>(() => _ = new PasskeyServiceDependencies(
            options, orchestrator, handshakes, new TestTokenHasher(), AllowRateLimiter.Instance, null!));
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

        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(clock, authenticationOrchestrator: pipeline.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));
        var (verification, request) = CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement, "Laptop");
        var result = await service.CompleteRegistrationAsync(verification, request);

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
        var service = CreateVerifiedPasskeyService(
            repo.Object,
            credentials.Object,
            challenges.Object,
            validator.Object,
            CreateDependencies(new FakeTimeProvider(now), new ThrowingSecurityEventSink(), transactionProvider: transactionProvider));

        var (verification, request) = CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement, "Laptop");
        Assert.ThrowsAsync<InvalidOperationException>(() => service.CompleteRegistrationAsync(verification, request));
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
        var service = CreateVerifiedPasskeyService(
            repo.Object,
            credentials.Object,
            new Mock<IPasskeyChallengeRepository>().Object,
            new Mock<IPasskeyCeremonyValidator>().Object,
            CreateDependencies(new FakeTimeProvider(now), events, sessionRepository: ActiveSessionRepository(userId), transactionProvider: transactionProvider));

        var result = await RevokeAsync(service, CreateRevokeRequest(userId, credential.Id, now));

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now)));

        var (verification, request) = CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement);
        var result = await service.CompleteRegistrationAsync(verification, request);

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now)));

        var (verification, request) = CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement);
        var result = await service.CompleteRegistrationAsync(verification, request);

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
        var service = CreateVerifiedPasskeyService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, challenges.Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var (verification, request) = CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement);
        var result = await service.CompleteRegistrationAsync(verification, request);

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
        var service = CreateVerifiedPasskeyService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, challenges.Object, validator.Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var (verification, request) = CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement, userId: Guid.NewGuid());
        var result = await service.CompleteRegistrationAsync(verification, request);

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var (verification, request) = CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement);
        var result = await service.CompleteRegistrationAsync(verification, request);

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var (verification, request) = CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement, "Laptop");
        await service.CompleteRegistrationAsync(verification, request);

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var (verification, request) = CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement);
        var result = await service.CompleteRegistrationAsync(verification, request);

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyValidationFailed));
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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now)));
        var verification = new PasskeyRegistrationVerificationContext(challenge.UserId!.Value, TenantContext.Global, RegistrationSessionId, new AuditContext(challenge.UserId.Value),
            freshPrimaryAuthenticationProof: CreatePrimaryProof(challenge.UserId.Value, challenge.TenantId, now, RegistrationSessionId, "totp-enrollment"));
        var request = new CompletePasskeyRegistrationRequest(challenge.Id, JsonDocument.Parse("{}").RootElement, null);

        var result = await service.CompleteRegistrationAsync(verification, request);

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now)));
        var verification = new PasskeyRegistrationVerificationContext(challenge.UserId!.Value, new TenantContext(tenantId), RegistrationSessionId, new AuditContext(challenge.UserId.Value),
            freshPrimaryAuthenticationProof: CreatePrimaryProof(challenge.UserId.Value, Guid.NewGuid(), now, RegistrationSessionId));
        var request = new CompletePasskeyRegistrationRequest(challenge.Id, JsonDocument.Parse("{}").RootElement, null);

        var result = await service.CompleteRegistrationAsync(verification, request);

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now)));

        var (verification, request) = CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement);
        var result = await service.CompleteRegistrationAsync(verification, request);

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now)));
        var verification = new PasskeyRegistrationVerificationContext(challenge.UserId!.Value, TenantContext.Global, RegistrationSessionId, new AuditContext(challenge.UserId.Value),
            freshMfaProof: CreateMfaProof(challenge.UserId.Value, challenge.TenantId, now, RegistrationSessionId));
        var request = new CompletePasskeyRegistrationRequest(challenge.Id, JsonDocument.Parse("{}").RootElement, null);

        var result = await service.CompleteRegistrationAsync(verification, request);

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now)));

        var verification = new PasskeyRegistrationVerificationContext(challenge.UserId!.Value, TenantContext.Global, RegistrationSessionId, new AuditContext(challenge.UserId.Value),
            freshPrimaryAuthenticationProof: CreatePrimaryProof(challenge.UserId.Value, challenge.TenantId, now, RegistrationSessionId));
        var result = await service.CompleteRegistrationAsync(verification,
            new CompletePasskeyRegistrationRequest(challenge.Id, JsonDocument.Parse("{}").RootElement, null));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            challenges.Verify(r => r.ConsumeAsync(It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Never);
            credentials.Verify(r => r.CreateOrReplaceCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [TestCase("fresh-primary")]
    [TestCase("fresh-mfa")]
    public async Task CompleteRegistrationAsyncShouldRejectWrongProofType(string storedProofType)
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CopyRegistrationChallenge(CreateRegistrationChallenge(now), proofType: storedProofType);
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        var service = CreateVerifiedPasskeyService(new Mock<IUserRepository>().Object, credentials.Object, challenges.Object,
            new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(new FakeTimeProvider(now)));
        var verification = storedProofType == "fresh-primary"
            ? new PasskeyRegistrationVerificationContext(challenge.UserId!.Value, TenantContext.Global, RegistrationSessionId, new AuditContext(challenge.UserId.Value),
                freshMfaProof: CreateMfaProof(challenge.UserId.Value, challenge.TenantId, now, RegistrationSessionId))
            : new PasskeyRegistrationVerificationContext(challenge.UserId!.Value, TenantContext.Global, RegistrationSessionId, new AuditContext(challenge.UserId.Value),
                freshPrimaryAuthenticationProof: CreatePrimaryProof(challenge.UserId.Value, challenge.TenantId, now, RegistrationSessionId));
        var request = new CompletePasskeyRegistrationRequest(challenge.Id, JsonDocument.Parse("{}").RootElement, null);

        var result = await service.CompleteRegistrationAsync(verification, request);

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now)));

        var (verification, request) = CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement);
        var result = await service.CompleteRegistrationAsync(verification, request);

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now)));

        var (verification, request) = CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement, sessionId: RegistrationSessionId);
        var result = await service.CompleteRegistrationAsync(verification, request);

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
        var service = CreateVerifiedPasskeyService(repo.Object, new Mock<ICredentialRepository>().Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), events, authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var (verification, request) = CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement);
        var result = await service.CompleteRegistrationAsync(verification, request);

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var (verification, request) = CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement);
        await service.CompleteRegistrationAsync(verification, request);

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var (verification, request) = CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement);
        await service.CompleteRegistrationAsync(verification, request);

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(securityEventSink: events, authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

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
        var service = CreateVerifiedPasskeyService(
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
        var service = CreateVerifiedPasskeyService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, challenges.Object, validator.Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

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
        var service = CreateVerifiedPasskeyService(
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
        var service = CreateVerifiedPasskeyService(
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
        var transactionProvider = new RecordingTransactionProvider();
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now, tenantId: Guid.NewGuid());
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var orchestrator = new Mock<IAuthenticationOrchestrator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        var service = CreateVerifiedPasskeyService(
            new Mock<IUserRepository>().Object,
            new Mock<ICredentialRepository>().Object,
            challenges.Object,
            validator.Object,
            CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher(), transactionProvider: transactionProvider));

        var result = await service.CompleteAuthenticationAsync(new CompletePasskeyAuthenticationRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement, Guid.NewGuid()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyChallengeInvalid));
            Assert.That(transactionProvider.BeginCount, Is.Zero);
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
        var service = CreateVerifiedPasskeyService(
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
        var service = CreateVerifiedPasskeyService(
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
        var transactionProvider = new RecordingTransactionProvider();
        var consumeWithinTransaction = false;
        var counterWithinTransaction = false;
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
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Callback(() => consumeWithinTransaction = transactionProvider.BeginCount == 1 && !transactionProvider.Transaction.Committed)
            .ReturnsAsync(true);
        repo.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>())).ReturnsAsync(credential);
        credentials.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), credential.Version, It.IsAny<CancellationToken>()))
            .Callback(() => counterWithinTransaction = transactionProvider.BeginCount == 1 && !transactionProvider.Transaction.Committed)
            .ReturnsAsync(true);
        validator.Setup(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), challenge, credential, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyAuthenticationVerificationResult("cred", 2, true));
        pipeline.Setup(p => p.AuthenticateAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<MfaOrchestrationOptions?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, user));
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: pipeline.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher(), transactionProvider: transactionProvider));

        var result = await service.CompleteAuthenticationAsync(new CompletePasskeyAuthenticationRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Credential?.CredentialId, Is.EqualTo("cred"));
            Assert.That(result.Credential?.LastUsedAt, Is.EqualTo(now));
            Assert.That(result.Credential?.SignCount, Is.EqualTo(2));
            Assert.That(consumeWithinTransaction, Is.True);
            Assert.That(counterWithinTransaction, Is.True);
            Assert.That(transactionProvider.Transaction.Committed, Is.True);
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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

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
            .ReturnsAsync(new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, user) { CredentialUpdatePersisted = true });
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

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
            .ReturnsAsync(new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, user) { CredentialUpdatePersisted = true });
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher(), options: new PasskeyOptions { Origin = "https://example.com", RelyingPartyId = "example.com", ProviderName = providerKey.Name }));

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher(), options: options));

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher(), options: options));

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));
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
        var service = CreateVerifiedPasskeyService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

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
        var service = CreateVerifiedPasskeyService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, challenges.Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteAuthenticationAsync(new CompletePasskeyAuthenticationRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyChallengeInvalid));
    }

    [Test]
    public async Task CompleteAuthenticationAsyncShouldConsumeChallengeBeforeRejectingMalformedAssertion()
    {
        var transactionProvider = new RecordingTransactionProvider();
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now);
        var challenges = new Mock<IPasskeyChallengeRepository>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher(), transactionProvider: transactionProvider));

        var result = await service.CompleteAuthenticationAsync(new CompletePasskeyAuthenticationRequest(challenge.Id, JsonDocument.Parse("{}").RootElement));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyValidationFailed));
            Assert.That(transactionProvider.Transaction.Committed, Is.True);
        }
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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: handshakes.Object, tokenHasher: new TestTokenHasher()));

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
        var service = CreateVerifiedPasskeyService(
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
        var service = CreateVerifiedPasskeyService(
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
        var service = CreateVerifiedPasskeyService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

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
        var service = CreateVerifiedPasskeyService(
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
        var service = CreateVerifiedPasskeyService(new Mock<IUserRepository>().Object, credentials.Object, challenges.Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: handshakes.Object, tokenHasher: new TestTokenHasher()));

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
        var service = CreateVerifiedPasskeyService(new Mock<IUserRepository>().Object, credentials.Object, challenges.Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: handshakes.Object, tokenHasher: new TestTokenHasher()));

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

        var service = CreateVerifiedPasskeyService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: handshakes.Object, tokenHasher: new TestTokenHasher()));

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
        var service = CreateVerifiedPasskeyService(
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
            .ReturnsAsync(Result.Failure<AuthenticationHandshake>(AshlarFailureCodes.ValidationError));
        var service = CreateVerifiedPasskeyService(
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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: handshakes.Object, tokenHasher: new TestTokenHasher()));

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: handshakes.Object, tokenHasher: new TestTokenHasher()));

        var result = await service.StartFactorAsync(new StartPasskeyFactorRequest("token"));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyCredentialNotFound));
        validator.Verify(v => v.CreateAuthenticationOptions(It.IsAny<PasskeyOptions>(), It.IsAny<string>(), It.IsAny<IReadOnlyList<UserCredential>>(), It.IsAny<string>()), Times.Never);
        challenges.Verify(r => r.CreateAsync(It.IsAny<PasskeyChallenge>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task CompleteFactorAsyncShouldVerifyMfaFactor()
    {
        var transactionProvider = new RecordingTransactionProvider();
        var consumeWithinTransaction = false;
        var counterWithinTransaction = false;
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
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Callback(() => consumeWithinTransaction = transactionProvider.BeginCount == 1 && !transactionProvider.Transaction.Committed)
            .ReturnsAsync(true);
        repo.Setup(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        credentials.Setup(r => r.GetCredentialForUserAsync(user.Id, ProviderType.Passkey, "PASSKEY", "cred", It.IsAny<CancellationToken>())).ReturnsAsync(credential);
        credentials.Setup(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), credential.Version, It.IsAny<CancellationToken>()))
            .Callback(() => counterWithinTransaction = transactionProvider.BeginCount == 1 && !transactionProvider.Transaction.Committed)
            .ReturnsAsync(true);
        validator.Setup(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), challenge, credential, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyAuthenticationVerificationResult("cred", 2, true));
        orchestrator.Setup(o => o.VerifyFactorAsync(
                "token",
                "passkey",
                It.Is<AuthenticationContext>(context => context.IpAddress == "198.51.100.2" && context.UserAgent == "Browser" && context.CorrelationId == "corr-factor-complete"),
                It.IsAny<IAuthenticationAssertion>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, user));
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher(), transactionProvider: transactionProvider));
        var audit = new AuditContext(null, "198.51.100.2", "Browser", "corr-factor-complete");

        var result = await service.CompleteFactorAsync(new CompletePasskeyFactorRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement, "token", Audit: audit));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Credential?.SignCount, Is.EqualTo(2));
            Assert.That(consumeWithinTransaction, Is.True);
            Assert.That(counterWithinTransaction, Is.True);
            Assert.That(transactionProvider.Transaction.Committed, Is.True);
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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

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
            .ReturnsAsync(new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, user) { CredentialUpdatePersisted = true });
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

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
            .ReturnsAsync(new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, user) { CredentialUpdatePersisted = true });
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher(), options: new PasskeyOptions { Origin = "https://example.com", RelyingPartyId = "example.com", ProviderName = providerKey.Name }));

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

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
        var service = CreateVerifiedPasskeyService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

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
        var service = CreateVerifiedPasskeyService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

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
        var transactionProvider = new RecordingTransactionProvider();
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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher(), transactionProvider: transactionProvider));

        var result = await service.CompleteFactorAsync(new CompletePasskeyFactorRequest(challenge.Id, JsonDocument.Parse("{}").RootElement, "token"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyValidationFailed));
            Assert.That(transactionProvider.Transaction.Committed, Is.True);
        }
        challenges.Verify(r => r.ConsumeAsync(challenge.Id, challenge.Version, now, It.IsAny<CancellationToken>()), Times.Once);
        repo.Verify(r => r.GetUserByIdAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()), Times.Never);
        validator.Verify(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), It.IsAny<PasskeyChallenge>(), It.IsAny<UserCredential>(), It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()), Times.Never);
        orchestrator.Verify(o => o.VerifyFactorAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [TestCase("token", "")]
    [TestCase("token", "totp")]
    public async Task CompleteFactorAsyncShouldRejectInvalidRequestShape(string token, string factorType)
    {
        var service = CreateVerifiedPasskeyService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteFactorAsync(new CompletePasskeyFactorRequest(Guid.NewGuid(), JsonDocument.Parse("{}").RootElement, token, factorType));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyChallengeInvalid));
    }

    [Test]
    public async Task CompleteFactorAsyncShouldRejectMismatchedTenantBeforeConsumingChallenge()
    {
        var transactionProvider = new RecordingTransactionProvider();
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var challenge = CreateAuthenticationChallenge(now, Guid.NewGuid(), "hashed:token", "passkey", Guid.NewGuid());
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var orchestrator = new Mock<IAuthenticationOrchestrator>();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        var service = CreateVerifiedPasskeyService(
            new Mock<IUserRepository>().Object,
            new Mock<ICredentialRepository>().Object,
            challenges.Object,
            validator.Object,
            CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher(), transactionProvider: transactionProvider));

        var result = await service.CompleteFactorAsync(new CompletePasskeyFactorRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement, "token", TenantId: Guid.NewGuid()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyChallengeInvalid));
            Assert.That(transactionProvider.BeginCount, Is.Zero);
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
        var service = CreateVerifiedPasskeyService(
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
        var service = CreateVerifiedPasskeyService(
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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

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
        var events = new RecordingSecurityEventSink();
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(new FakeTimeProvider(now), events, authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher(), sessionRepository: ActiveSessionRepository(userId)));

        var result = await RenameAsync(service, CreateRenameRequest(userId, credentialId, "", now));

        using var _ = Assert.EnterMultipleScope();
        Assert.That(result.Succeeded, Is.True);
        Assert.That(events.Events.Single().SessionId, Is.EqualTo(RegistrationSessionId));
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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher(), sessionRepository: ActiveSessionRepository(userId)));

        var result = await RenameAsync(service, CreateRenameRequest(userId, credentialId, "Name", now));

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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher(), sessionRepository: ActiveSessionRepository(userId)));

        var list = await service.ListAsync(CreateManagementActor(userId, now));
        var renameMissing = await RenameAsync(service, CreateRenameRequest(userId, Guid.NewGuid(), "Name", now));
        var renameConflict = await RenameAsync(service, CreateRenameRequest(userId, passkey.Id, "Name", now));
        var renameSuccess = await RenameAsync(service, CreateRenameRequest(userId, passkey.Id, new string('x', 120), now));
        var revokeMissing = await RevokeAsync(service, CreateRevokeRequest(userId, Guid.NewGuid(), now));
        var revokeConflict = await RevokeAsync(service, CreateRevokeRequest(userId, passkey.Id, now));
        var revokeSuccess = await RevokeAsync(service, CreateRevokeRequest(userId, passkey.Id, now));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(list.Value, Has.Count.EqualTo(3));
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
        var events = new RecordingSecurityEventSink();
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(new FakeTimeProvider(now), events, sessionRepository: ActiveSessionRepository(userId, tenantId)));

        var wrongActor = await RenameAsync(service, CreateRenameRequest(Guid.NewGuid(), credential.Id, "Name", now, tenantId: tenantId));
        var wrongTenant = await RenameAsync(service, CreateRenameRequest(userId, credential.Id, "Name", now, tenantId: Guid.NewGuid()));
        var wrongSession = await RenameAsync(service, CreateRenameRequest(userId, credential.Id, "Name", now, tenantId: tenantId, currentSessionId: Guid.NewGuid(), proof: CreateMfaProof(userId, tenantId, now, RegistrationSessionId, ManagementPurpose)));
        var expiredProof = await RenameAsync(service, CreateRenameRequest(userId, credential.Id, "Name", now, tenantId: tenantId, proof: CreateMfaProof(userId, tenantId, now.Subtract(RegistrationFreshnessWindow).AddTicks(-1), RegistrationSessionId, ManagementPurpose)));
        var wrongPurpose = await RenameAsync(service, CreateRenameRequest(userId, credential.Id, "Name", now, tenantId: tenantId, proof: CreateMfaProof(userId, tenantId, now, RegistrationSessionId, RegistrationPurpose)));
        var renameAuditMismatch = await RenameAsync(service, CreateRenameRequest(userId, credential.Id, "Name", now, tenantId: tenantId, audit: new AuditContext(Guid.NewGuid())));
        var revokeAuditMismatch = await RevokeAsync(service, CreateRevokeRequest(userId, credential.Id, now, tenantId: tenantId, audit: new AuditContext(Guid.NewGuid())));
        var revoke = await RevokeAsync(service, CreateRevokeRequest(userId, credential.Id, now, tenantId: tenantId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(wrongActor.Succeeded, Is.False);
            Assert.That(wrongTenant.Succeeded, Is.False);
            Assert.That(wrongSession.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            Assert.That(expiredProof.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpExpired));
            Assert.That(wrongPurpose.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            Assert.That(renameAuditMismatch.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(revokeAuditMismatch.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(revoke.Succeeded, Is.True);
            Assert.That(events.Events.Select(e => (e.EventType, e.Outcome)), Is.EqualTo(new[] { (AshlarSecurityEventTypes.PasskeyRevoked, SecurityEventOutcomes.Success) }));
            Assert.That(events.Events.Single().SessionId, Is.EqualTo(RegistrationSessionId));
        }

        credentials.Verify(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task ListAsyncShouldRejectInvalidManagementBoundaryAndAuditReads()
    {
        var userId = Guid.NewGuid();
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var credentials = new Mock<ICredentialRepository>();
        var events = new RecordingSecurityEventSink();
        var sessions = new Mock<IAuthenticationSessionRepository>();
        sessions.Setup(r => r.GetSessionAsync(RegistrationSessionId, It.IsAny<CancellationToken>())).ReturnsAsync(new AuthenticationSession
        {
            Id = RegistrationSessionId,
            UserId = userId,
            TokenHash = "hash",
            CreatedAt = now.AddMinutes(-1),
            ExpiresAt = now.AddHours(1),
            RevokedAt = now
        });
        var service = CreateVerifiedPasskeyService(new Mock<IUserRepository>().Object, credentials.Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(new FakeTimeProvider(now), events, sessionRepository: sessions.Object));

        var wrongProof = await service.ListAsync(CreateManagementActor(userId, now, proof: CreateMfaProof(userId, null, now, RegistrationSessionId, RegistrationPurpose)));
        var wrongSession = await service.ListAsync(CreateManagementActor(userId, now, currentSessionId: Guid.NewGuid()));
        var revokedSession = await service.ListAsync(CreateManagementActor(userId, now));
        var missingAuditActor = await service.ListAsync(CreateManagementActor(userId, now, audit: new AuditContext()));
        var auditMismatch = await service.ListAsync(CreateManagementActor(userId, now, audit: new AuditContext(Guid.NewGuid())), new CancellationToken(true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(wrongProof.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            Assert.That(wrongSession.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            Assert.That(revokedSession.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            Assert.That(missingAuditActor.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(auditMismatch.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(events.Events, Has.Count.EqualTo(5));
            Assert.That(events.Events.All(e => e.EventType == AshlarSecurityEventTypes.PasskeyInventoryRead && e.Outcome == SecurityEventOutcomes.Failure), Is.True);
            Assert.That(events.Events.All(e => e.ActorUserId == null && e.UserId == null && e.TenantId == null && e.SessionId == null), Is.True);
            credentials.Verify(r => r.ListCredentialsForUserAsync(It.IsAny<Guid>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public void ManagementMethodsShouldRejectNullActorAndRequestBeforeRepositoryAccess()
    {
        var credentials = new Mock<ICredentialRepository>();
        var service = CreateVerifiedPasskeyService(new Mock<IUserRepository>().Object, credentials.Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies());
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var proof = CreateMfaProof(userId, null, DateTimeOffset.UtcNow, sessionId, ManagementPurpose);
        var audit = new AuditContext(userId);

        Assert.ThrowsAsync<ArgumentNullException>(() => service.ListAsync(null!));
        Assert.ThrowsAsync<ArgumentNullException>(() => service.RenameAsync(null!, new RenamePasskeyRequest(Guid.NewGuid(), "Name")));
        Assert.ThrowsAsync<ArgumentNullException>(() => service.RevokeAsync(null!, new RevokePasskeyRequest(Guid.NewGuid())));
        Assert.Throws<ArgumentNullException>(() => new AccountSecurityActorContext(userId, TenantContext.Global, sessionId, null!, audit));
        Assert.Throws<ArgumentNullException>(() => new AccountSecurityActorContext(userId, TenantContext.Global, sessionId, proof, null!));
        var actor = new AccountSecurityActorContext(userId, TenantContext.Global, sessionId, proof, audit);
        Assert.ThrowsAsync<ArgumentNullException>(() => service.RenameAsync(actor, null!));
        Assert.ThrowsAsync<ArgumentNullException>(() => service.RevokeAsync(actor, null!));
        credentials.VerifyNoOtherCalls();
    }

    [Test]
    public async Task ListAsyncShouldRejectUnavailableOwnerAfterValidProof()
    {
        var userId = Guid.NewGuid();
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var credentials = new Mock<ICredentialRepository>();
        var events = new RecordingSecurityEventSink();
        var service = CreateVerifiedPasskeyService(new Mock<IUserRepository>().Object, credentials.Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(new FakeTimeProvider(now), events, sessionRepository: ActiveSessionRepository(userId)));

        var result = await service.ListAsync(CreateManagementActor(userId, now));

        using var _ = Assert.EnterMultipleScope();
        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFoundOrUnavailable));
        Assert.That(events.Events.Single().UserId, Is.Null);
        credentials.Verify(r => r.ListCredentialsForUserAsync(It.IsAny<Guid>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public void ManagementApiShouldRequireSessionProofAndAuditProvenance()
    {
        using var _ = Assert.EnterMultipleScope();
        Assert.That(typeof(IPasskeyService).Assembly.GetType("Ashlar.Passkeys.ListPasskeysRequest"), Is.Null);
        Assert.That(
            typeof(RenamePasskeyRequest).GetConstructors().Single().GetParameters().Select(p => p.ParameterType),
            Is.EqualTo(new[] { typeof(Guid), typeof(string) }));
        Assert.That(
            typeof(RevokePasskeyRequest).GetConstructors().Single().GetParameters().Select(p => p.ParameterType),
            Is.EqualTo(new[] { typeof(Guid) }));
        Assert.That(
            typeof(IPasskeyService).GetMethod(nameof(IPasskeyService.ListAsync))!.GetParameters().Select(p => p.ParameterType),
            Is.EqualTo(new[] { typeof(AccountSecurityActorContext), typeof(CancellationToken) }));
        Assert.That(
            typeof(IPasskeyService).GetMethod(nameof(IPasskeyService.RenameAsync))!.GetParameters().Select(p => p.ParameterType),
            Is.EqualTo(new[] { typeof(AccountSecurityActorContext), typeof(RenamePasskeyRequest), typeof(CancellationToken) }));
        Assert.That(
            typeof(IPasskeyService).GetMethod(nameof(IPasskeyService.RevokeAsync))!.GetParameters().Select(p => p.ParameterType),
            Is.EqualTo(new[] { typeof(AccountSecurityActorContext), typeof(RevokePasskeyRequest), typeof(CancellationToken) }));
    }

    [Test]
    public async Task ListAsyncShouldAuditSuccessAndProviderFailureWithValidatedProvenance()
    {
        var userId = Guid.NewGuid();
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var passkey = CreatePasskeyCredential(userId, "cred", now);
        var users = new Mock<IUserRepository>();
        users.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>())).ReturnsAsync(new TestUser(userId, "test@example.com"));
        var credentials = new Mock<ICredentialRepository>();
        credentials.SetupSequence(r => r.ListCredentialsForUserAsync(userId, true, It.IsAny<CancellationToken>()))
            .ReturnsAsync([passkey])
            .ThrowsAsync(new InvalidOperationException("provider failed"));
        var events = new RecordingSecurityEventSink();
        var service = CreateVerifiedPasskeyService(users.Object, credentials.Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(new FakeTimeProvider(now), events, sessionRepository: ActiveSessionRepository(userId)));
        var request = CreateManagementActor(userId, now);

        var result = await service.ListAsync(request);
        Assert.ThrowsAsync<InvalidOperationException>(() => service.ListAsync(request));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(events.Events.Select(e => e.Outcome), Is.EqualTo(new[] { SecurityEventOutcomes.Success, SecurityEventOutcomes.Failure }));
            Assert.That(events.Events.All(e => e.ActorUserId == userId && e.SessionId == RegistrationSessionId), Is.True);
        }
    }

    [Test]
    public void ListAsyncShouldAuditBoundaryValidationExceptionWithoutUnvalidatedProvenance()
    {
        var userId = Guid.NewGuid();
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var request = CreateManagementActor(userId, now);
        var sessions = new Mock<IAuthenticationSessionRepository>();
        sessions.Setup(r => r.GetSessionAsync(RegistrationSessionId, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new OperationCanceledException());
        var events = new RecordingSecurityEventSink();
        var service = CreateVerifiedPasskeyService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(new FakeTimeProvider(now), events, sessionRepository: sessions.Object));

        Assert.ThrowsAsync<OperationCanceledException>(() => service.ListAsync(request, new CancellationToken(true)));

        var securityEvent = events.Events.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(securityEvent.Outcome, Is.EqualTo(SecurityEventOutcomes.Failure));
            Assert.That(securityEvent.ActorUserId, Is.Null);
            Assert.That(securityEvent.SessionId, Is.Null);
        }
    }

    [Test]
    public async Task RevokeAsyncShouldRejectBoundaryFailureBeforeCredentialLookup()
    {
        var userId = Guid.NewGuid();
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var credentials = new Mock<ICredentialRepository>();
        var service = CreateVerifiedPasskeyService(new Mock<IUserRepository>().Object, credentials.Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(new FakeTimeProvider(now)));

        var result = await RevokeAsync(service, CreateRevokeRequest(userId, Guid.NewGuid(), now, proof: CreateMfaProof(userId, null, now, RegistrationSessionId, RegistrationPurpose)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            credentials.Verify(r => r.ListCredentialsForUserAsync(It.IsAny<Guid>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    private void AssertStartRegistrationTenantFailure(TestUser user, TenantContext? tenant)
    {
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        repo.Setup(r => r.GetUserByIdAsync(user.Id, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies());

        var verification = new PasskeyRegistrationVerificationContext(user.Id, tenant ?? TenantContext.Global, RegistrationSessionId, new AuditContext(user.Id),
            freshMfaProof: CreateMfaProof(user.Id, tenant?.TenantId, DateTimeOffset.UtcNow, RegistrationSessionId));

        Assert.ThrowsAsync<InvalidOperationException>(() => service.StartRegistrationAsync(verification, new StartPasskeyRegistrationRequest("Laptop")));
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

    private async Task<Result> CompleteRegistrationForTenantAsync(Guid? challengeTenantId, Guid? userTenantId, TenantContext? requestTenant)
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
        var service = CreateVerifiedPasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now)));

        var (verification, request) = CreateCompleteRegistrationRequest(challenge, JsonDocument.Parse("{}").RootElement, tenant: requestTenant);
        var result = await service.CompleteRegistrationAsync(verification, request);

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

    private (PasskeyRegistrationVerificationContext Verification, StartPasskeyRegistrationRequest Request) CreateStartRegistrationRequest(Guid userId, string displayName, TenantContext? tenant = null, AuditContext? audit = null, DateTimeOffset? now = null, Guid? sessionId = null)
    {
        var resolvedNow = now ?? DateTimeOffset.UtcNow;
        var resolvedTenant = tenant ?? TenantContext.Global;
        var resolvedSessionId = sessionId ?? RegistrationSessionId;
        return new(new PasskeyRegistrationVerificationContext(userId, resolvedTenant, resolvedSessionId,
            audit ?? new AuditContext(userId), freshPrimaryAuthenticationProof: CreatePrimaryProof(userId, resolvedTenant.TenantId, resolvedNow, resolvedSessionId)),
            new StartPasskeyRegistrationRequest(displayName));
    }

    private (PasskeyRegistrationVerificationContext Verification, CompletePasskeyRegistrationRequest Request) CreateCompleteRegistrationRequest(PasskeyChallenge challenge, JsonElement credentialResponse, string? displayName = null, TenantContext? tenant = null, Guid? userId = null, DateTimeOffset? now = null, Guid? sessionId = null)
    {
        var resolvedUserId = userId ?? challenge.UserId.GetValueOrDefault();
        var resolvedTenant = tenant ?? TenantContext.Global;
        var resolvedNow = now ?? challenge.CreatedAt;
        var resolvedSessionId = sessionId ?? challenge.RegistrationProofSessionId ?? RegistrationSessionId;
        return new(new PasskeyRegistrationVerificationContext(resolvedUserId, resolvedTenant, resolvedSessionId,
            new AuditContext(resolvedUserId), freshPrimaryAuthenticationProof: CreatePrimaryProof(resolvedUserId, resolvedTenant.TenantId, resolvedNow, resolvedSessionId)),
            new CompletePasskeyRegistrationRequest(challenge.Id, credentialResponse, displayName));
    }

    private FreshPrimaryAuthenticationProof CreatePrimaryProof(Guid userId, Guid? tenantId, DateTimeOffset now, Guid sessionId, string purpose = RegistrationPurpose)
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
        _proofSessions[sessionId] = session;
        return result.Value!;
    }

    private FreshMfaVerificationProof CreateMfaProof(Guid userId, Guid? tenantId, DateTimeOffset now, Guid sessionId, string purpose = RegistrationPurpose)
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
        var result = stepUp.CreateFreshMfaProof(CreateValidatedSession(session), new StepUpRequirement(RegistrationFreshnessWindow), purpose);
        _proofSessions[sessionId] = session;
        return result.Value!;
    }

    private static ValidatedAuthenticationSession CreateValidatedSession(AuthenticationSession session) =>
        (ValidatedAuthenticationSession)Activator.CreateInstance(typeof(ValidatedAuthenticationSession),
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic, null, [session], null)!;

    private (AccountSecurityActorContext Actor, RenamePasskeyRequest Request) CreateRenameRequest(
        Guid userId,
        Guid credentialId,
        string displayName,
        DateTimeOffset now,
        Guid? tenantId = null,
        Guid? currentSessionId = null,
        FreshMfaVerificationProof? proof = null,
        AuditContext? audit = null)
    {
        var sessionId = currentSessionId ?? RegistrationSessionId;
        var actor = new AccountSecurityActorContext(
            userId,
            tenantId.HasValue ? new TenantContext(tenantId.Value) : TenantContext.Global,
            sessionId,
            proof ?? CreateMfaProof(userId, tenantId, now, sessionId, ManagementPurpose),
            audit ?? new AuditContext(userId, "127.0.0.1", "NUnit", "corr"));
        return new(actor, new RenamePasskeyRequest(credentialId, displayName));
    }

    private AccountSecurityActorContext CreateManagementActor(Guid userId, DateTimeOffset now, Guid? tenantId = null, Guid? currentSessionId = null, FreshMfaVerificationProof? proof = null, AuditContext? audit = null)
    {
        var sessionId = currentSessionId ?? RegistrationSessionId;
        return new AccountSecurityActorContext(
            userId,
            tenantId.HasValue ? new TenantContext(tenantId.Value) : TenantContext.Global,
            sessionId,
            proof ?? CreateMfaProof(userId, tenantId, now, RegistrationSessionId, ManagementPurpose),
            audit ?? new AuditContext(userId, "127.0.0.1", "NUnit", "corr"));
    }

    private (AccountSecurityActorContext Actor, RevokePasskeyRequest Request) CreateRevokeRequest(
        Guid userId,
        Guid credentialId,
        DateTimeOffset now,
        Guid? tenantId = null,
        Guid? currentSessionId = null,
        FreshMfaVerificationProof? proof = null,
        AuditContext? audit = null)
    {
        var sessionId = currentSessionId ?? RegistrationSessionId;
        var actor = new AccountSecurityActorContext(
            userId,
            tenantId.HasValue ? new TenantContext(tenantId.Value) : TenantContext.Global,
            sessionId,
            proof ?? CreateMfaProof(userId, tenantId, now, sessionId, ManagementPurpose),
            audit ?? new AuditContext(userId, "127.0.0.1", "NUnit", "corr"));
        return new(actor, new RevokePasskeyRequest(credentialId));
    }

    private static Task<Result> RenameAsync(PasskeyService service, (AccountSecurityActorContext Actor, RenamePasskeyRequest Request) call, CancellationToken cancellationToken = default) =>
        service.RenameAsync(call.Actor, call.Request, cancellationToken);

    private static Task<Result> RevokeAsync(PasskeyService service, (AccountSecurityActorContext Actor, RevokePasskeyRequest Request) call, CancellationToken cancellationToken = default) =>
        service.RevokeAsync(call.Actor, call.Request, cancellationToken);

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

    private PasskeyServiceDependencies CreateDependencies(
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
        var persistent = new ForwardingPersistentSink(securityEventSink ?? new RecordingSecurityEventSink());
        var transactions = transactionProvider as AshlarDurableTransactionProvider
            ?? DurableTransactionComposition.Create(transactionProvider ?? new RecordingTransactionProvider(), persistent);
        var fanOut = securityEventSink as SecurityEventFanOutSink
            ?? new SecurityEventFanOutSink(persistent, transactionProvider: transactions);
        var sessions = sessionRepository ?? ActiveSessionRepository();
        var dependencies = new PasskeyServiceDependencies(
            Options.Create(options ?? new PasskeyOptions { Origin = "https://example.com", RelyingPartyId = "example.com" }),
            authenticationOrchestrator ?? new Mock<IAuthenticationOrchestrator>().Object,
            handshakeService ?? new Mock<IAuthenticationHandshakeService>().Object,
            tokenHasher ?? new TestTokenHasher(),
            rateLimiter ?? AllowRateLimiter.Instance,
            new PasskeyServiceInfrastructure(timeProvider, fanOut, transactions));
        StoreInfrastructure.Add(dependencies, new(sessions, ProofValidator(sessions, timeProvider)));
        return dependencies;
    }

    private static ActiveSessionFreshProofValidator ProofValidator(
        IAuthenticationSessionRepository sessions,
        TimeProvider? timeProvider = null)
    {
        return new ActiveSessionFreshProofValidator(sessions, timeProvider ?? TimeProvider.System);
    }

    private static PasskeyService CreateVerifiedPasskeyService(
        IUserRepository users,
        ICredentialRepository credentials,
        IPasskeyChallengeRepository challenges,
        IPasskeyCeremonyValidator validator,
        PasskeyServiceDependencies dependencies)
    {
        var composed = ComposeDependencies(users, credentials, challenges, validator, dependencies);
        var store = CreateStore(users, credentials, challenges, composed);
        return new PasskeyService(store, store, StoreInfrastructure.GetValue(composed, _ => throw new InvalidOperationException()).ProofValidator, validator, [], composed);
    }

    private static PasskeyService CreateVerifiedPasskeyService(
        IUserRepository users,
        ICredentialRepository credentials,
        IPasskeyChallengeRepository challenges,
        IPasskeyCeremonyValidator validator,
        IEnumerable<IAuthenticationProvider> providers,
        PasskeyServiceDependencies dependencies)
    {
        var composed = ComposeDependencies(users, credentials, challenges, validator, dependencies);
        var store = CreateStore(users, credentials, challenges, composed);
        return new PasskeyService(store, store, StoreInfrastructure.GetValue(composed, _ => throw new InvalidOperationException()).ProofValidator, validator, providers, composed);
    }

    private static PasskeyServiceDependencies ComposeDependencies(
        IUserRepository users,
        ICredentialRepository credentials,
        IPasskeyChallengeRepository challenges,
        IPasskeyCeremonyValidator validator,
        PasskeyServiceDependencies dependencies)
    {
        if (users is null || credentials is null || challenges is null || validator is null || dependencies is null)
            return dependencies!;
        var persistent = new ForwardingPersistentSink(dependencies.SecurityEventSink);
        var transactions = DurableTransactionComposition.Create(
            dependencies.TransactionProvider,
            persistent,
            users,
            credentials,
            challenges,
            StoreInfrastructure.GetValue(dependencies, _ => throw new InvalidOperationException()).Sessions);
        var composed = new PasskeyServiceDependencies(
            dependencies.Options,
            dependencies.AuthenticationOrchestrator,
            dependencies.HandshakeService,
            dependencies.TokenHasher,
            dependencies.RateLimiter,
            new PasskeyServiceInfrastructure(dependencies.TimeProvider, new SecurityEventFanOutSink(persistent, transactionProvider: transactions), transactions));
        StoreInfrastructure.Add(composed, StoreInfrastructure.GetValue(dependencies, _ => throw new InvalidOperationException()));
        return composed;
    }

    private static RepositoryPasskeyPersistence CreateStore(IUserRepository users, ICredentialRepository credentials, IPasskeyChallengeRepository challenges, PasskeyServiceDependencies dependencies)
    {
        var infrastructure = StoreInfrastructure.GetValue(dependencies, _ => throw new InvalidOperationException());
        return new(users, credentials, challenges, dependencies.Options.Value.ProviderName);
    }

    private sealed record TestStoreInfrastructure(IAuthenticationSessionRepository Sessions, ActiveSessionFreshProofValidator ProofValidator);

    private sealed class ForwardingPersistentSink(ISecurityEventSink sink) : IPersistentSecurityEventSink
    {
        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default) =>
            sink.RecordAsync(securityEvent, cancellationToken);
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
        var service = CreateVerifiedPasskeyService(new Mock<IUserRepository>().Object, credentials.Object,
            new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object,
            CreateDependencies(new FakeTimeProvider(now), sessionRepository: sessions.Object));

        var rename = await RenameAsync(service, CreateRenameRequest(userId, Guid.NewGuid(), "Name", now));
        var revoke = await RevokeAsync(service, CreateRevokeRequest(userId, Guid.NewGuid(), now));

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
        var service = CreateVerifiedPasskeyService(new Mock<IUserRepository>().Object, credentials.Object,
            new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object,
            CreateDependencies(new FakeTimeProvider(now), sessionRepository: ActiveSessionRepository(Guid.NewGuid())));

        var result = await RenameAsync(service, CreateRenameRequest(userId, Guid.NewGuid(), "Name", now));

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
        var service = CreateVerifiedPasskeyService(new Mock<IUserRepository>().Object, credentials.Object,
            new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object,
            CreateDependencies(new FakeTimeProvider(now), sessionRepository: ActiveSessionRepository(userId)));

        var result = await RenameAsync(service, CreateRenameRequest(userId, Guid.NewGuid(), "Name", now, tenantId: tenantId));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
        credentials.VerifyNoOtherCalls();
    }

    [Test]
    public async Task RenameShouldRejectUnavailableActorAfterSessionValidation()
    {
        var userId = Guid.NewGuid();
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var credentials = new Mock<ICredentialRepository>();
        var service = CreateVerifiedPasskeyService(new Mock<IUserRepository>().Object, credentials.Object,
            new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object,
            CreateDependencies(new FakeTimeProvider(now), sessionRepository: ActiveSessionRepository(userId)));

        var result = await RenameAsync(service, CreateRenameRequest(userId, Guid.NewGuid(), "Name", now));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFoundOrUnavailable));
        credentials.VerifyNoOtherCalls();
    }

    private IAuthenticationSessionRepository ActiveSessionRepository(Guid userId = default, Guid? tenantId = null)
    {
        var repository = new Mock<IAuthenticationSessionRepository>();
        repository.Setup(x => x.GetSessionAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>())).ReturnsAsync((Guid id, CancellationToken _) =>
            userId == Guid.Empty && _proofSessions.TryGetValue(id, out var session) ? session : new AuthenticationSession
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
    public int BeginCount { get; private set; }

    public Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default)
    {
        BeginCount++;
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
