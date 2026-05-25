using System.Text.Json;
using Ashlar.Auditing;
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

        var result = await service.StartRegistrationAsync(new StartPasskeyRegistrationRequest(user.Id, " ", audit));

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
            new Mock<IPasskeyChallengeRepository>().Object,
            new Mock<IPasskeyCeremonyValidator>().Object,
            null!));

        Assert.Throws<ArgumentNullException>(() => _ = new PasskeyServiceDependencies(
            Options.Create(new PasskeyOptions { Origin = "https://example.com", RelyingPartyId = "example.com" }),
            null!,
            new Mock<IAuthenticationHandshakeService>().Object,
            new TestTokenHasher()));
        Assert.Throws<ArgumentNullException>(() => _ = new PasskeyServiceDependencies(
            Options.Create(new PasskeyOptions { Origin = "https://example.com", RelyingPartyId = "example.com" }),
            new Mock<IAuthenticationOrchestrator>().Object,
            null!,
            new TestTokenHasher()));
        Assert.Throws<ArgumentNullException>(() => _ = new PasskeyServiceDependencies(
            Options.Create(new PasskeyOptions { Origin = "https://example.com", RelyingPartyId = "example.com" }),
            new Mock<IAuthenticationOrchestrator>().Object,
            new Mock<IAuthenticationHandshakeService>().Object,
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
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        var events = new RecordingSecurityEventSink();
        challenges.Setup(r => r.GetAsync(challenge.Id, It.IsAny<CancellationToken>())).ReturnsAsync(challenge);
        challenges.Setup(r => r.ConsumeAsync(challenge.Id, challenge.Version, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);
        validator.Setup(v => v.VerifyRegistrationAsync(It.IsAny<PasskeyOptions>(), challenge, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("bad ceremony"));
        var service = new PasskeyService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), events, authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

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
        validator.Setup(v => v.CreateAuthenticationOptions(It.IsAny<PasskeyOptions>(), It.IsAny<string>(), It.Is<IReadOnlyList<UserCredential>>(c => c.Count == 1 && c[0].ProviderKey == "cred")))
            .Returns("{}");
        challenges.Setup(r => r.CreateAsync(It.IsAny<PasskeyChallenge>(), It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.StartAuthenticationAsync(new StartPasskeyAuthenticationRequest(UserId: user.Id));

        Assert.That(result.OptionsJson, Is.EqualTo("{}"));
        repo.Verify(r => r.GetUserByEmailAsync(It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()), Times.Never);
        challenges.Verify(r => r.CreateAsync(It.Is<PasskeyChallenge>(c => c.UserId == user.Id), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task StartAuthenticationAsyncShouldCreateUserlessChallenge()
    {
        var challenges = new Mock<IPasskeyChallengeRepository>();
        var validator = new Mock<IPasskeyCeremonyValidator>();
        validator.Setup(v => v.CreateAuthenticationOptions(It.IsAny<PasskeyOptions>(), It.IsAny<string>(), It.Is<IReadOnlyList<UserCredential>>(c => c.Count == 0)))
            .Returns("{}");
        var service = new PasskeyService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, challenges.Object, validator.Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.StartAuthenticationAsync(new StartPasskeyAuthenticationRequest());

        Assert.That(result.OptionsJson, Is.EqualTo("{}"));
        challenges.Verify(r => r.CreateAsync(It.Is<PasskeyChallenge>(c => c.UserId == null), It.IsAny<CancellationToken>()), Times.Once);
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
        }

        credentials.Verify(r => r.ListCredentialsForUserAsync(It.IsAny<Guid>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
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
            Assert.That(mfa.Status, Is.EqualTo(MfaAuthenticationStatus.MfaRequired));
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
        handshakes.Setup(h => h.GetHandshakeAsync("token", It.IsAny<CancellationToken>())).ReturnsAsync(handshake);
        credentials.Setup(r => r.ListCredentialsForUserAsync(userId, true, It.IsAny<CancellationToken>())).ReturnsAsync([credential]);
        validator.Setup(v => v.CreateAuthenticationOptions(It.IsAny<PasskeyOptions>(), It.IsAny<string>(), It.Is<IReadOnlyList<UserCredential>>(c => c.Count == 1)))
            .Returns("{}");
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: handshakes.Object, tokenHasher: new TestTokenHasher()));

        var result = await service.StartFactorAsync(new StartPasskeyFactorRequest("token"));

        Assert.That(result.Succeeded, Is.True);
        challenges.Verify(r => r.CreateAsync(It.Is<PasskeyChallenge>(c => c.UserId == userId && c.HandshakeTokenHash == "hashed:token" && c.FactorType == "passkey"), It.IsAny<CancellationToken>()), Times.Once);
    }

    [TestCase("", "passkey")]
    [TestCase("token", "")]
    [TestCase("token", "totp")]
    public async Task StartFactorAsyncShouldRejectInvalidRequestShape(string token, string factorType)
    {
        var service = new PasskeyService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.StartFactorAsync(new StartPasskeyFactorRequest(token, factorType));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyChallengeInvalid));
    }

    [Test]
    public async Task StartFactorAsyncShouldRejectInvalidHandshakeStates()
    {
        var userId = Guid.NewGuid();
        var handshakes = new Mock<IAuthenticationHandshakeService>();
        handshakes.SetupSequence(h => h.GetHandshakeAsync("token", It.IsAny<CancellationToken>()))
            .ReturnsAsync((AuthenticationHandshake?)null)
            .ReturnsAsync(CreateHandshake(userId) with { IsRevoked = true })
            .ReturnsAsync(CreateHandshake(userId) with { IsCompleted = true })
            .ReturnsAsync(CreateHandshake(userId) with { ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1) })
            .ReturnsAsync(CreateHandshake(userId) with { RequiredFactors = new HashSet<string> { "totp" } })
            .ReturnsAsync(CreateHandshake(userId) with { VerifiedFactors = new HashSet<string> { "passkey" } });
        var service = new PasskeyService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: handshakes.Object, tokenHasher: new TestTokenHasher()));

        for (var i = 0; i < 6; i++)
        {
            var result = await service.StartFactorAsync(new StartPasskeyFactorRequest("token"));
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyChallengeInvalid));
        }
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
        handshakes.Setup(h => h.GetHandshakeAsync("token", It.IsAny<CancellationToken>())).ReturnsAsync(handshake);
        credentials.Setup(r => r.ListCredentialsForUserAsync(userId, true, It.IsAny<CancellationToken>())).ReturnsAsync(credentialList);
        validator.Setup(v => v.CreateAuthenticationOptions(It.IsAny<PasskeyOptions>(), It.IsAny<string>(), It.Is<IReadOnlyList<UserCredential>>(c => c.Count == 1 && c[0].ProviderKey == "secondary")))
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
        handshakes.Setup(h => h.GetHandshakeAsync("token", It.IsAny<CancellationToken>())).ReturnsAsync(handshake);
        credentials.Setup(r => r.ListCredentialsForUserAsync(userId, true, It.IsAny<CancellationToken>())).ReturnsAsync([credential]);
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: handshakes.Object, tokenHasher: new TestTokenHasher()));

        var result = await service.StartFactorAsync(new StartPasskeyFactorRequest("token"));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyCredentialNotFound));
        validator.Verify(v => v.CreateAuthenticationOptions(It.IsAny<PasskeyOptions>(), It.IsAny<string>(), It.IsAny<IReadOnlyList<UserCredential>>()), Times.Never);
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
        validator.Setup(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), challenge, credential, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyAuthenticationVerificationResult("cred", 2));
        orchestrator.Setup(o => o.VerifyFactorAsync("token", "passkey", It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, user));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteFactorAsync(new CompletePasskeyFactorRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement, "token"));

        Assert.That(result.Succeeded, Is.True);
        orchestrator.Verify(o => o.VerifyFactorAsync("token", "passkey", It.IsAny<AuthenticationContext>(), It.IsAny<PasskeyAssertion>(), It.IsAny<CancellationToken>()), Times.Once);
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
        validator.Setup(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), challenge, credential, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyAuthenticationVerificationResult("cred", 2));
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
        validator.Setup(v => v.VerifyAuthenticationAsync(It.IsAny<PasskeyOptions>(), challenge, credential, It.IsAny<JsonElement>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyAuthenticationVerificationResult("cred", 2));
        orchestrator.Setup(o => o.VerifyFactorAsync("token", "passkey", It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaAuthenticationResult(MfaAuthenticationStatus.HandshakeIncomplete, user, "token", ["totp"]));
        var service = new PasskeyService(repo.Object, credentials.Object, challenges.Object, validator.Object, CreateDependencies(new FakeTimeProvider(now), authenticationOrchestrator: orchestrator.Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteFactorAsync(new CompletePasskeyFactorRequest(challenge.Id, JsonDocument.Parse("""{"id":"cred"}""").RootElement, "token"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.HandshakeIncomplete));
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

    [TestCase("", "passkey")]
    [TestCase("token", "")]
    [TestCase("token", "totp")]
    public async Task CompleteFactorAsyncShouldRejectInvalidRequestShape(string token, string factorType)
    {
        var service = new PasskeyService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, new Mock<IPasskeyChallengeRepository>().Object, new Mock<IPasskeyCeremonyValidator>().Object, CreateDependencies(authenticationOrchestrator: new Mock<IAuthenticationOrchestrator>().Object, handshakeService: new Mock<IAuthenticationHandshakeService>().Object, tokenHasher: new TestTokenHasher()));

        var result = await service.CompleteFactorAsync(new CompletePasskeyFactorRequest(Guid.NewGuid(), JsonDocument.Parse("{}").RootElement, token, factorType));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyChallengeInvalid));
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
            .ReturnsAsync(new PasskeyAuthenticationVerificationResult("cred", 2))
            .ReturnsAsync(new PasskeyAuthenticationVerificationResult("cred", 2));
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
    public async Task ListRenameAndRevokeShouldHandleMissingAndConcurrencyBranches()
    {
        var userId = Guid.NewGuid();
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var passkey = CreatePasskeyCredential(userId, "cred", now);
        var nullMetadataPasskey = CreatePasskeyCredential(userId, "null-metadata", now);
        nullMetadataPasskey.Metadata = "null";
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
        passkey.Metadata = null;
        var repo = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        credentials.Setup(r => r.ListCredentialsForUserAsync(userId, true, It.IsAny<CancellationToken>()))
            .ReturnsAsync([passkey, nullMetadataPasskey, other]);
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
            Assert.That(list, Has.Count.EqualTo(2));
            Assert.That(renameMissing.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyCredentialNotFound));
            Assert.That(renameConflict.FailureCode, Is.EqualTo(AshlarFailureCodes.ConcurrencyConflict));
            Assert.That(renameSuccess.Succeeded, Is.True);
            Assert.That(revokeMissing.FailureCode, Is.EqualTo(AshlarFailureCodes.PasskeyCredentialNotFound));
            Assert.That(revokeConflict.FailureCode, Is.EqualTo(AshlarFailureCodes.ConcurrencyConflict));
            Assert.That(revokeSuccess.Succeeded, Is.True);
        }
    }

    private static PasskeyChallenge CreateRegistrationChallenge(DateTimeOffset now)
    {
        return new PasskeyChallenge
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
        ISecureTokenHasher? tokenHasher = null)
    {
        return new PasskeyServiceDependencies(
            Options.Create(new PasskeyOptions { Origin = "https://example.com", RelyingPartyId = "example.com" }),
            authenticationOrchestrator ?? new Mock<IAuthenticationOrchestrator>().Object,
            handshakeService ?? new Mock<IAuthenticationHandshakeService>().Object,
            tokenHasher ?? new TestTokenHasher(),
            timeProvider,
            securityEventSink);
    }
}

internal sealed record TestUser(Guid Id, string Email) : IUser
{
    public string? Name => null;
    public bool IsActive => true;
    public DateTimeOffset? EmailVerifiedAt => null;
}

internal sealed class TestTokenHasher : ISecureTokenHasher
{
    public string HashToken(string token)
    {
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
