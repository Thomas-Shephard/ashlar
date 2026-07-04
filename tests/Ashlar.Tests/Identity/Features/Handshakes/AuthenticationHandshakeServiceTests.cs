using Ashlar.Auditing;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Security.Tokens;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Identity.Features.Handshakes;

internal sealed class AuthenticationHandshakeServiceTests
{
    private static readonly string[] ExpectedRequiredFactors = ["totp", "email"];
    private static readonly string[] ExpectedCompletionTransactionOperations = ["begin", "read", "update", "commit"];
    private static readonly string[] ExpectedStaleUpdateTransactionOperations = ["begin", "read", "update", "dispose"];

    private Mock<IAuthenticationHandshakeRepository> _repositoryMock;
    private Mock<ISecureTokenHasher> _tokenHasherMock;
    private Mock<IAuthenticationRateLimiter> _rateLimiterMock;
    private Mock<ISecurityEventSink> _eventSinkMock;
    private FakeTimeProvider _timeProvider;
    private AuthenticationHandshakeService _service;

    [SetUp]
    public void SetUp()
    {
        _repositoryMock = new Mock<IAuthenticationHandshakeRepository>();
        _tokenHasherMock = new Mock<ISecureTokenHasher>();
        _rateLimiterMock = new Mock<IAuthenticationRateLimiter>();
        _eventSinkMock = new Mock<ISecurityEventSink>();
        _timeProvider = new FakeTimeProvider(new DateTimeOffset(2025, 1, 1, 12, 0, 0, TimeSpan.Zero));

        _tokenHasherMock.Setup(h => h.HashToken(It.IsAny<string>())).Returns<string>(token => $"hashed:{token}");
        _repositoryMock.Setup(r => r.UpdateAsync(It.IsAny<AuthenticationHandshake>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        _rateLimiterMock.Setup(r => r.CheckAsync(It.IsAny<RateLimitAttempt>(), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RateLimitDecision
            {
                Status = RateLimitStatus.Allowed,
                Remaining = 5,
                WindowResetAt = _timeProvider.GetUtcNow().AddMinutes(1)
            });

        _service = new AuthenticationHandshakeService(
            _repositoryMock.Object,
            new FixedTokenGenerator("raw-token"),
            _tokenHasherMock.Object,
            new NullTransactionProvider(),
            new AuthenticationHandshakeServiceDependencies(
                Options.Create(new AuthenticationHandshakeOptions()),
                _timeProvider,
                _eventSinkMock.Object,
                _rateLimiterMock.Object));
    }

    [Test]
    public async Task CreateHandshakeAsyncShouldReturnHandshakeAndToken()
    {
        var userId = Guid.NewGuid();
        var requiredFactors = new[] { "totp", "email" };
        AuthenticationHandshake? storedHandshake = null;
        _repositoryMock
            .Setup(r => r.CreateAsync(It.IsAny<AuthenticationHandshake>(), It.IsAny<CancellationToken>()))
            .Callback<AuthenticationHandshake, CancellationToken>((handshake, _) => storedHandshake = handshake)
            .Returns(Task.CompletedTask);

        var result = await _service.CreateHandshakeAsync(new CreateAuthenticationHandshakeRequest(userId, requiredFactors));

        Assert.That(result.Value, Is.Not.Null);

        var handshake = result.Value.Handshake;
        var token = result.Value.Token;

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(token, Is.EqualTo("raw-token"));
            Assert.That(handshake.UserId, Is.EqualTo(userId));
            Assert.That(storedHandshake?.TokenHash, Is.EqualTo("hashed:raw-token"));
            Assert.That(handshake.RequiredFactors, Is.EquivalentTo(requiredFactors));
            Assert.That(storedHandshake?.VerifiedFactors, Is.Empty);
            Assert.That(storedHandshake?.IsCompleted, Is.False);
            Assert.That(storedHandshake?.IsRevoked, Is.False);
        }

        _repositoryMock.Verify(r => r.CreateAsync(It.Is<AuthenticationHandshake>(h => h.Id == handshake.Id), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task CreateHandshakeAsyncResultShouldNotExposeTokenHash()
    {
        var result = await _service.CreateHandshakeAsync(new CreateAuthenticationHandshakeRequest(Guid.NewGuid(), ["totp"]));
        var json = JsonSerializer.Serialize(result.Value);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value!.Handshake.GetType().GetProperty("TokenHash"), Is.Null);
            Assert.That(json, Does.Not.Contain("TokenHash"));
            Assert.That(json, Does.Not.Contain("hashed:raw-token"));
        }
    }

    [Test]
    public async Task CreateHandshakeAsyncShouldPersistTenantFromContext()
    {
        var tenantId = Guid.NewGuid();

        var result = await _service.CreateHandshakeAsync(new CreateAuthenticationHandshakeRequest(
            Guid.NewGuid(),
            ["totp"],
            Context: new AuthenticationContext(TenantId: tenantId)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value!.Handshake.TenantId, Is.EqualTo(tenantId));
        }

        _repositoryMock.Verify(r => r.CreateAsync(It.Is<AuthenticationHandshake>(h => h.TenantId == tenantId), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public void CreateHandshakeAsyncShouldThrowOnNullRequest()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(() => _service.CreateHandshakeAsync(null!));
    }

    [Test]
    public void CreateHandshakeAsyncShouldThrowOnEmptyUserId()
    {
        Assert.ThrowsAsync<ArgumentException>(() => _service.CreateHandshakeAsync(new CreateAuthenticationHandshakeRequest(Guid.Empty, ["totp"])));
    }

    [Test]
    public void CreateHandshakeAsyncShouldThrowOnNullRequiredFactors()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(() => _service.CreateHandshakeAsync(new CreateAuthenticationHandshakeRequest(Guid.NewGuid(), null!)));
    }

    [Test]
    public async Task CreateHandshakeAsyncShouldReturnFailureOnEmptyRequiredFactors()
    {
        var result = await _service.CreateHandshakeAsync(new CreateAuthenticationHandshakeRequest(Guid.NewGuid(), []));
        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.NoFactorsSpecified));
        }
    }

    [Test]
    public async Task CreateHandshakeAsyncShouldReturnFailureOnOversizedMetadata()
    {
        var metadata = new Dictionary<string, string> { ["device"] = new('x', 513) };

        var result = await _service.CreateHandshakeAsync(new CreateAuthenticationHandshakeRequest(Guid.NewGuid(), ["totp"], metadata));
        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidMetadata));
        }
    }

    [Test]
    public async Task CreateHandshakeAsyncShouldReturnFailureOnTooManyMetadataEntries()
    {
        var metadata = Enumerable.Range(0, 21).ToDictionary(i => $"key-{i}", _ => "value");

        var result = await _service.CreateHandshakeAsync(new CreateAuthenticationHandshakeRequest(Guid.NewGuid(), ["totp"], metadata));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidMetadata));
        }
    }

    [Test]
    public async Task CreateHandshakeAsyncShouldReturnFailureOnBlankMetadataKey()
    {
        var metadata = new Dictionary<string, string> { [" "] = "value" };

        var result = await _service.CreateHandshakeAsync(new CreateAuthenticationHandshakeRequest(Guid.NewGuid(), ["totp"], metadata));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidMetadata));
        }
    }

    [Test]
    public async Task CreateHandshakeAsyncShouldReturnFailureOnOversizedMetadataKey()
    {
        var metadata = new Dictionary<string, string> { [new string('k', 129)] = "value" };

        var result = await _service.CreateHandshakeAsync(new CreateAuthenticationHandshakeRequest(Guid.NewGuid(), ["totp"], metadata));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidMetadata));
        }
    }

    [Test]
    public async Task CreateHandshakeAsyncShouldTreatNullMetadataValueAsEmpty()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        var metadata = new Dictionary<string, string> { ["device"] = null! };

        var result = await _service.CreateHandshakeAsync(new CreateAuthenticationHandshakeRequest(Guid.NewGuid(), ["totp"], metadata));

        Assert.That(result.Value, Is.Not.Null);
        var handshake = result.Value.Handshake;

        Assert.That(handshake.Metadata?["device"], Is.EqualTo(string.Empty));
    }

    [Test]
    public async Task CreateHandshakeAsyncShouldEnumerateRequiredFactorsOnce()
    {
        var requiredFactors = new SinglePassEnumerable<string>(["totp", "email"]);

        var result = await _service.CreateHandshakeAsync(new CreateAuthenticationHandshakeRequest(Guid.NewGuid(), requiredFactors));

        Assert.That(result.Value, Is.Not.Null);
        var handshake = result.Value.Handshake;

        Assert.That(handshake.RequiredFactors, Is.EquivalentTo(ExpectedRequiredFactors));
    }

    [Test]
    public async Task CompleteFactorVerificationAsyncShouldSucceedAndMarkAsCompletedWhenAllFactorsVerified()
    {
        var userId = Guid.NewGuid();
        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            userId,
            "hashed:raw-token",
            _timeProvider.GetUtcNow(),
            _timeProvider.GetUtcNow().AddMinutes(15),
            false,
            false,
            new HashSet<string> { "totp" },
            new HashSet<string>());

        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        var result = await _service.CompleteFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "totp"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.VerifiedFactors, Contains.Item("totp"));
            Assert.That(result.Value?.IsCompleted, Is.True);
            Assert.That(result.Value?.CompletedAt, Is.EqualTo(_timeProvider.GetUtcNow()));
        }

        _repositoryMock.Verify(r => r.UpdateAsync(It.Is<AuthenticationHandshake>(h => h.IsCompleted && h.CompletedAt == _timeProvider.GetUtcNow()), It.IsAny<CancellationToken>()), Times.Once);
        _repositoryMock.Verify(r => r.FindByTokenHashAsync("hashed:raw-token", true, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task CompleteFactorVerificationAsyncShouldSucceedForTenantHandshakeWithMatchingTenant()
    {
        var tenantId = Guid.NewGuid();
        var handshake = CreateHandshake(tenantId);
        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        var result = await _service.CompleteFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest(
            "raw-token",
            "totp",
            Context: new AuthenticationContext(TenantId: tenantId)));

        Assert.That(result.Succeeded, Is.True);
    }

    [Test]
    public async Task CompleteFactorVerificationAsyncShouldFailGenericallyWhenTenantHandshakeOmitsTenant()
    {
        var handshake = CreateHandshake(Guid.NewGuid());
        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        var result = await _service.CompleteFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "totp"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.HandshakeNotFound));
        }

        _repositoryMock.Verify(r => r.UpdateAsync(It.IsAny<AuthenticationHandshake>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task CompleteFactorVerificationAsyncShouldFailGenericallyWhenTenantHandshakeUsesWrongTenant()
    {
        var handshake = CreateHandshake(Guid.NewGuid());
        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        var result = await _service.CompleteFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest(
            "raw-token",
            "totp",
            Context: new AuthenticationContext(TenantId: Guid.NewGuid())));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.HandshakeNotFound));
    }

    [Test]
    public async Task CompleteFactorVerificationAsyncShouldSucceedForGlobalHandshakeWithOmittedTenant()
    {
        var handshake = CreateHandshake();
        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        var result = await _service.CompleteFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "totp"));

        Assert.That(result.Succeeded, Is.True);
    }

    [Test]
    public async Task CompleteFactorVerificationAsyncShouldFailGenericallyWhenGlobalHandshakeUsesTenant()
    {
        var handshake = CreateHandshake();
        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        var result = await _service.CompleteFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest(
            "raw-token",
            "totp",
            Context: new AuthenticationContext(TenantId: Guid.NewGuid())));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.HandshakeNotFound));
    }

    [Test]
    public async Task BeginVerificationAsyncShouldFailGenericallyBeforeVerificationRateLimitWhenTenantMismatches()
    {
        var handshake = CreateHandshake(Guid.NewGuid());
        var wrongTenantId = Guid.NewGuid();
        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        var result = await _service.BeginVerificationAsync(new BeginAuthenticationHandshakeVerificationRequest(
            "raw-token",
            new AuthenticationContext(TenantId: wrongTenantId)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.HandshakeNotFound));
        }

        _rateLimiterMock.Verify(r => r.CheckAsync(
            It.Is<RateLimitAttempt>(attempt => attempt.Purpose == "handshake-verify"),
            It.IsAny<RateLimitRule>(),
            It.IsAny<CancellationToken>()), Times.Never);
        _eventSinkMock.Verify(sink => sink.RecordAsync(It.Is<AshlarSecurityEvent>(securityEvent =>
            securityEvent.EventType == AshlarSecurityEventTypes.AuthenticationHandshakeFailed &&
            securityEvent.Outcome == SecurityEventOutcomes.Failure &&
            securityEvent.FailureReason == AshlarFailureCodes.HandshakeNotFound.Value &&
            securityEvent.TenantId == wrongTenantId &&
            securityEvent.UserId == null &&
            securityEvent.Properties == null), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task BeginFactorVerificationAsyncShouldFailGenericallyWhenTenantHandshakeOmitsTenant()
    {
        var handshake = CreateHandshake(Guid.NewGuid());
        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        var result = await _service.BeginFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "totp"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.HandshakeNotFound));
        }
    }

    [Test]
    public async Task BeginVerificationAsyncShouldAllowOrchestrationToResolveBackupFactor()
    {
        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "hashed:raw-token",
            _timeProvider.GetUtcNow(),
            _timeProvider.GetUtcNow().AddMinutes(15),
            false,
            false,
            new HashSet<string> { "totp", "passkey" },
            new HashSet<string> { "totp" });

        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", false, It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        var result = await _service.BeginVerificationAsync(new BeginAuthenticationHandshakeVerificationRequest("raw-token"));

        Assert.That(result.Succeeded, Is.True);
    }

    [Test]
    public async Task BeginFactorVerificationAsyncShouldRejectUnrequiredFactor()
    {
        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "hashed:raw-token",
            _timeProvider.GetUtcNow(),
            _timeProvider.GetUtcNow().AddMinutes(15),
            false,
            false,
            new HashSet<string> { "totp", "passkey" },
            new HashSet<string> { "totp" });

        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", false, It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        var result = await _service.BeginFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "backup"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidFactorType));
        }
    }

    [Test]
    public async Task CompleteFactorVerificationAsyncShouldRejectUnrequiredFactor()
    {
        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "hashed:raw-token",
            _timeProvider.GetUtcNow(),
            _timeProvider.GetUtcNow().AddMinutes(15),
            false,
            false,
            new HashSet<string> { "totp", "passkey" },
            new HashSet<string> { "totp" });

        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", true, It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        var result = await _service.CompleteFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "backup"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidFactorType));
        }

        _repositoryMock.Verify(r => r.UpdateAsync(It.IsAny<AuthenticationHandshake>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task CompleteFactorVerificationAsyncShouldLoadForUpdateInsideTransaction()
    {
        var operations = new List<string>();
        var transactionProvider = new RecordingTransactionProvider(operations);
        var service = new AuthenticationHandshakeService(
            _repositoryMock.Object,
            new FixedTokenGenerator("raw-token"),
            _tokenHasherMock.Object,
            transactionProvider,
            new AuthenticationHandshakeServiceDependencies(
                Options.Create(new AuthenticationHandshakeOptions()),
                _timeProvider,
                _eventSinkMock.Object,
                _rateLimiterMock.Object));
        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "hashed:raw-token",
            _timeProvider.GetUtcNow(),
            _timeProvider.GetUtcNow().AddMinutes(15),
            false,
            false,
            new HashSet<string> { "totp" },
            new HashSet<string>());

        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", true, It.IsAny<CancellationToken>()))
            .Callback(() =>
            {
                Assert.That(transactionProvider.IsActive, Is.True);
                operations.Add("read");
            })
            .ReturnsAsync(handshake);
        _repositoryMock.Setup(r => r.UpdateAsync(It.IsAny<AuthenticationHandshake>(), It.IsAny<CancellationToken>()))
            .Callback(() =>
            {
                Assert.That(transactionProvider.IsActive, Is.True);
                operations.Add("update");
            })
            .ReturnsAsync(true);

        var result = await service.CompleteFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "totp"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(operations, Is.EqualTo(ExpectedCompletionTransactionOperations));
        }
    }

    [Test]
    public async Task CompleteFactorVerificationAsyncShouldFailOnStaleUpdateWithoutCommitOrSuccessEvent()
    {
        var operations = new List<string>();
        var transactionProvider = new RecordingTransactionProvider(operations);
        var service = new AuthenticationHandshakeService(
            _repositoryMock.Object,
            new FixedTokenGenerator("raw-token"),
            _tokenHasherMock.Object,
            transactionProvider,
            new AuthenticationHandshakeServiceDependencies(
                Options.Create(new AuthenticationHandshakeOptions()),
                _timeProvider,
                _eventSinkMock.Object,
                _rateLimiterMock.Object));
        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "hashed:raw-token",
            _timeProvider.GetUtcNow(),
            _timeProvider.GetUtcNow().AddMinutes(15),
            false,
            false,
            new HashSet<string> { "totp" },
            new HashSet<string>());

        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", true, It.IsAny<CancellationToken>()))
            .Callback(() => operations.Add("read"))
            .ReturnsAsync(handshake);
        _repositoryMock.Setup(r => r.UpdateAsync(It.IsAny<AuthenticationHandshake>(), It.IsAny<CancellationToken>()))
            .Callback(() => operations.Add("update"))
            .ReturnsAsync(false);

        var result = await service.CompleteFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "totp"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ConcurrencyConflict));
            Assert.That(operations, Is.EqualTo(ExpectedStaleUpdateTransactionOperations));
        }

        _eventSinkMock.Verify(sink => sink.RecordAsync(It.Is<AshlarSecurityEvent>(securityEvent =>
            securityEvent.EventType == AshlarSecurityEventTypes.AuthenticationHandshakeFailed &&
            securityEvent.Outcome == SecurityEventOutcomes.Failure &&
            securityEvent.FailureReason == AshlarFailureCodes.ConcurrencyConflict.Value &&
            securityEvent.UserId == handshake.UserId &&
            securityEvent.Properties != null &&
            securityEvent.Properties.ContainsKey("handshake_id") &&
            securityEvent.Properties["handshake_id"] == handshake.Id.ToString()), It.IsAny<CancellationToken>()), Times.Once);
        _eventSinkMock.Verify(sink => sink.RecordAsync(It.Is<AshlarSecurityEvent>(securityEvent =>
            securityEvent.Outcome == SecurityEventOutcomes.Success &&
            (securityEvent.EventType == AshlarSecurityEventTypes.AuthenticationHandshakeCompleted ||
             securityEvent.EventType == AshlarSecurityEventTypes.AuthenticationHandshakeFactorVerified)), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task CompleteFactorVerificationAsyncShouldSucceedWhenRateLimiterIsNotRegistered()
    {
        var service = new AuthenticationHandshakeService(
            _repositoryMock.Object,
            new FixedTokenGenerator("raw-token"),
            _tokenHasherMock.Object,
            new NullTransactionProvider(),
            new AuthenticationHandshakeServiceDependencies(
                Options.Create(new AuthenticationHandshakeOptions()),
                _timeProvider,
                _eventSinkMock.Object));
        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "hashed:raw-token",
            _timeProvider.GetUtcNow(),
            _timeProvider.GetUtcNow().AddMinutes(15),
            false,
            false,
            new HashSet<string> { "totp" },
            new HashSet<string>());

        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        var result = await service.CompleteFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "totp"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.IsCompleted, Is.True);
        }

        _rateLimiterMock.Verify(r => r.CheckAsync(It.IsAny<RateLimitAttempt>(), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task BeginFactorVerificationAsyncShouldSucceedWhenRateLimiterIsNotRegistered()
    {
        var service = new AuthenticationHandshakeService(
            _repositoryMock.Object,
            new FixedTokenGenerator("raw-token"),
            _tokenHasherMock.Object,
            new NullTransactionProvider(),
            new AuthenticationHandshakeServiceDependencies(
                Options.Create(new AuthenticationHandshakeOptions()),
                _timeProvider,
                _eventSinkMock.Object));
        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "hashed:raw-token",
            _timeProvider.GetUtcNow(),
            _timeProvider.GetUtcNow().AddMinutes(15),
            false,
            false,
            new HashSet<string> { "totp" },
            new HashSet<string>());

        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        var result = await service.BeginFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "totp"));

        Assert.That(result.Value, Is.SameAs(handshake));
        _rateLimiterMock.Verify(r => r.CheckAsync(It.IsAny<RateLimitAttempt>(), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task BeginFactorVerificationAsyncShouldSucceedWhenRateLimitAllowsAttempt()
    {
        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "hashed:raw-token",
            _timeProvider.GetUtcNow(),
            _timeProvider.GetUtcNow().AddMinutes(15),
            false,
            false,
            new HashSet<string> { "totp" },
            new HashSet<string>());

        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        var result = await _service.BeginFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "totp"));

        Assert.That(result.Value, Is.SameAs(handshake));
        _rateLimiterMock.Verify(r => r.CheckAsync(It.IsAny<RateLimitAttempt>(), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()), Times.Exactly(3));
        _rateLimiterMock.Verify(r => r.CheckAsync(It.Is<RateLimitAttempt>(attempt =>
            attempt.Purpose == "handshake-lookup" &&
            attempt.IpAddress == null), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()), Times.Once);
        _rateLimiterMock.Verify(r => r.CheckAsync(It.Is<RateLimitAttempt>(attempt =>
            attempt.Purpose == "handshake-verify" &&
            attempt.IpAddress == null), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()), Times.Exactly(2));
        _repositoryMock.Verify(r => r.FindByTokenHashAsync("hashed:raw-token", false, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task BeginFactorChallengeAsyncShouldUseLookupRateLimitOnly()
    {
        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "hashed:raw-token",
            _timeProvider.GetUtcNow(),
            _timeProvider.GetUtcNow().AddMinutes(15),
            false,
            false,
            new HashSet<string> { "passkey" },
            new HashSet<string>());

        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        var result = await _service.BeginFactorChallengeAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "passkey"));

        Assert.That(result.Value, Is.SameAs(handshake));
        _rateLimiterMock.Verify(r => r.CheckAsync(It.Is<RateLimitAttempt>(attempt =>
            attempt.Purpose == "handshake-lookup"), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()), Times.Once);
        _rateLimiterMock.Verify(r => r.CheckAsync(It.Is<RateLimitAttempt>(attempt =>
            attempt.Purpose == "handshake-verify"), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()), Times.Never);
        _repositoryMock.Verify(r => r.FindByTokenHashAsync("hashed:raw-token", false, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task CompleteFactorVerificationAsyncShouldSucceedAndNotMarkAsCompletedWhenFactorsRemaining()
    {
        var userId = Guid.NewGuid();
        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            userId,
            "hashed:raw-token",
            _timeProvider.GetUtcNow(),
            _timeProvider.GetUtcNow().AddMinutes(15),
            false,
            false,
            new HashSet<string> { "totp", "email" },
            new HashSet<string>());

        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        var result = await _service.CompleteFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "totp"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.VerifiedFactors, Contains.Item("totp"));
            Assert.That(result.Value?.IsCompleted, Is.False);
        }
    }

    [Test]
    public async Task CompleteFactorVerificationAsyncShouldNotMutateOriginalHandshakeMetadata()
    {
        var metadata = new Dictionary<string, string> { ["existing"] = "original" };
        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "hashed:raw-token",
            _timeProvider.GetUtcNow(),
            _timeProvider.GetUtcNow().AddMinutes(15),
            false,
            false,
            new HashSet<string> { "totp" },
            new HashSet<string>(),
            metadata);

        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        var result = await _service.CompleteFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest(
            "raw-token",
            "totp",
            new Dictionary<string, string> { ["existing"] = "updated", ["new"] = "value" }));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(handshake.Metadata, Is.EquivalentTo(new Dictionary<string, string> { ["existing"] = "original" }));
            Assert.That(result.Value?.Metadata, Is.EquivalentTo(new Dictionary<string, string> { ["existing"] = "updated", ["new"] = "value" }));
            Assert.That(result.Value?.Metadata, Is.Not.SameAs(metadata));
        }
    }

    [Test]
    public async Task CompleteFactorVerificationAsyncShouldAddRequestMetadataWhenHandshakeMetadataIsNull()
    {
        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "hashed:raw-token",
            _timeProvider.GetUtcNow(),
            _timeProvider.GetUtcNow().AddMinutes(15),
            false,
            false,
            new HashSet<string> { "totp" },
            new HashSet<string>());

        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        var result = await _service.CompleteFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest(
            "raw-token",
            "totp",
            new Dictionary<string, string> { ["device"] = "trusted" }));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.Metadata, Is.EquivalentTo(new Dictionary<string, string> { ["device"] = "trusted" }));
        }
    }

    [Test]
    public void CompleteFactorVerificationAsyncShouldThrowOnNullRequest()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(() => _service.CompleteFactorVerificationAsync(null!));
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase(" ")]
    public async Task CompleteFactorVerificationAsyncShouldReturnHandshakeNotFoundWhenTokenMissing(string? token)
    {
        var result = await _service.CompleteFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest(token, "totp"));
        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.HandshakeNotFound));
        }

        _repositoryMock.Verify(r => r.FindByTokenHashAsync(It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
        _repositoryMock.Verify(r => r.UpdateAsync(It.IsAny<AuthenticationHandshake>(), It.IsAny<CancellationToken>()), Times.Never);
        _eventSinkMock.Verify(sink => sink.RecordAsync(It.Is<AshlarSecurityEvent>(securityEvent =>
            securityEvent.EventType == AshlarSecurityEventTypes.AuthenticationHandshakeFailed &&
            securityEvent.Outcome == SecurityEventOutcomes.Failure &&
            securityEvent.FailureReason == AshlarFailureCodes.HandshakeNotFound.Value), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task CompleteFactorVerificationAsyncShouldFailWhenHandshakeNotFound()
    {
        _repositoryMock.Setup(r => r.FindByTokenHashAsync(It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()))
                       .ReturnsAsync((AuthenticationHandshake?)null);

        var result = await _service.CompleteFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest("invalid", "totp"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.HandshakeNotFound));
        }
    }

    [Test]
    public async Task CompleteFactorVerificationAsyncShouldReturnHandshakeNotFoundForOverlongTokenWithoutMutatingState()
    {
        var overlongToken = new string('a', 257);
        _tokenHasherMock.Setup(h => h.HashToken(overlongToken)).Throws(new ArgumentException("Token exceeds maximum allowed length.", "token"));

        var result = await _service.CompleteFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest(overlongToken, "totp"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.HandshakeNotFound));
        }

        _repositoryMock.Verify(r => r.FindByTokenHashAsync(It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
        _repositoryMock.Verify(r => r.UpdateAsync(It.IsAny<AuthenticationHandshake>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task BeginFactorChallengeAsyncShouldReturnHandshakeNotFoundForOverlongTokenWithoutLookup()
    {
        var overlongToken = new string('a', 257);
        _tokenHasherMock.Setup(h => h.HashToken(overlongToken)).Throws(new ArgumentException("Token exceeds maximum allowed length.", "token"));

        var result = await _service.BeginFactorChallengeAsync(new VerifyAuthenticationHandshakeRequest(overlongToken, "passkey"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.HandshakeNotFound));
        }

        _repositoryMock.Verify(r => r.FindByTokenHashAsync(It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
        _repositoryMock.Verify(r => r.UpdateAsync(It.IsAny<AuthenticationHandshake>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [TestCase(null)]
    [TestCase(" ")]
    public async Task BeginFactorChallengeAsyncShouldReturnHandshakeNotFoundForMissingTokenWithoutLookup(string? token)
    {
        var result = await _service.BeginFactorChallengeAsync(new VerifyAuthenticationHandshakeRequest(token, "passkey"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.HandshakeNotFound));
        }

        _repositoryMock.Verify(r => r.FindByTokenHashAsync(It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
        _repositoryMock.Verify(r => r.UpdateAsync(It.IsAny<AuthenticationHandshake>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task BeginFactorVerificationAsyncShouldReturnHandshakeNotFoundForOverlongTokenWithoutLookup()
    {
        var overlongToken = new string('a', 257);
        _tokenHasherMock.Setup(h => h.HashToken(overlongToken)).Throws(new ArgumentException("Token exceeds maximum allowed length.", "token"));

        var result = await _service.BeginFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest(overlongToken, "totp"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.HandshakeNotFound));
        }

        _repositoryMock.Verify(r => r.FindByTokenHashAsync(It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
        _repositoryMock.Verify(r => r.UpdateAsync(It.IsAny<AuthenticationHandshake>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [TestCase(null)]
    [TestCase(" ")]
    public async Task BeginFactorVerificationAsyncShouldReturnHandshakeNotFoundForMissingTokenWithoutLookup(string? token)
    {
        var result = await _service.BeginFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest(token, "totp"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.HandshakeNotFound));
        }

        _repositoryMock.Verify(r => r.FindByTokenHashAsync(It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
        _repositoryMock.Verify(r => r.UpdateAsync(It.IsAny<AuthenticationHandshake>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task CompleteFactorVerificationAsyncShouldFailWhenExpired()
    {
        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "hashed:raw-token",
            _timeProvider.GetUtcNow().AddMinutes(-20),
            _timeProvider.GetUtcNow().AddMinutes(-5),
            false,
            false,
            new HashSet<string> { "totp" },
            new HashSet<string>());

        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", It.IsAny<bool>(), It.IsAny<CancellationToken>()))
                       .ReturnsAsync(handshake);

        var result = await _service.CompleteFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "totp"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.HandshakeExpired));
        }
    }

    [Test]
    public async Task CompleteFactorVerificationAsyncShouldFailWhenRevoked()
    {
        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "hashed:raw-token",
            _timeProvider.GetUtcNow(),
            _timeProvider.GetUtcNow().AddMinutes(15),
            true,
            false,
            new HashSet<string> { "totp" },
            new HashSet<string>());

        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", It.IsAny<bool>(), It.IsAny<CancellationToken>()))
                       .ReturnsAsync(handshake);

        var result = await _service.CompleteFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "totp"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.HandshakeRevoked));
        }
    }

    [Test]
    public async Task CompleteFactorVerificationAsyncShouldFailWhenAlreadyCompleted()
    {
        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "hashed:raw-token",
            _timeProvider.GetUtcNow(),
            _timeProvider.GetUtcNow().AddMinutes(15),
            false,
            true,
            new HashSet<string> { "totp" },
            new HashSet<string> { "totp" });

        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", It.IsAny<bool>(), It.IsAny<CancellationToken>()))
                       .ReturnsAsync(handshake);

        var result = await _service.CompleteFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "totp"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.HandshakeAlreadyCompleted));
        }
    }

    [Test]
    public async Task BeginFactorVerificationAsyncShouldFailWhenRateLimited()
    {
        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "hashed:raw-token",
            _timeProvider.GetUtcNow(),
            _timeProvider.GetUtcNow().AddMinutes(15),
            false,
            false,
            new HashSet<string> { "totp" },
            new HashSet<string>());

        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", It.IsAny<bool>(), It.IsAny<CancellationToken>()))
                       .ReturnsAsync(handshake);

        _rateLimiterMock.Setup(r => r.CheckAsync(It.IsAny<RateLimitAttempt>(), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()))
                        .ReturnsAsync(new RateLimitDecision
                        {
                            Status = RateLimitStatus.Blocked,
                            Remaining = 0,
                            WindowResetAt = _timeProvider.GetUtcNow().AddMinutes(1)
                        });

        var context = new AuthenticationContext(IpAddress: "203.0.113.80", CorrelationId: "handshake-rate-limit");

        var result = await _service.BeginFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "totp", Context: context));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.RateLimitExceeded));
        }

        _rateLimiterMock.Verify(r => r.CheckAsync(It.Is<RateLimitAttempt>(attempt =>
            attempt.IpAddress == "203.0.113.80" &&
            attempt.CorrelationId == "handshake-rate-limit"), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task BeginFactorVerificationAsyncShouldFailWhenUserRateLimitIsBlocked()
    {
        var userId = Guid.NewGuid();
        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            userId,
            "hashed:raw-token",
            _timeProvider.GetUtcNow(),
            _timeProvider.GetUtcNow().AddMinutes(15),
            false,
            false,
            new HashSet<string> { "totp" },
            new HashSet<string>());

        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", It.IsAny<bool>(), It.IsAny<CancellationToken>()))
                       .ReturnsAsync(handshake);

        _rateLimiterMock.SetupSequence(r => r.CheckAsync(It.IsAny<RateLimitAttempt>(), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()))
                        .ReturnsAsync(new RateLimitDecision
                        {
                            Status = RateLimitStatus.Allowed,
                            Remaining = 5,
                            WindowResetAt = _timeProvider.GetUtcNow().AddMinutes(1)
                        })
                        .ReturnsAsync(new RateLimitDecision
                        {
                            Status = RateLimitStatus.Allowed,
                            Remaining = 5,
                            WindowResetAt = _timeProvider.GetUtcNow().AddMinutes(1)
                        })
                        .ReturnsAsync(new RateLimitDecision
                        {
                            Status = RateLimitStatus.Blocked,
                            Remaining = 0,
                            WindowResetAt = _timeProvider.GetUtcNow().AddMinutes(1)
                        });

        var context = new AuthenticationContext(IpAddress: "203.0.113.81", CorrelationId: "handshake-user-rate-limit");

        var result = await _service.BeginFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "totp", Context: context));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.RateLimitExceeded));
        }

        _rateLimiterMock.Verify(r => r.CheckAsync(It.Is<RateLimitAttempt>(attempt =>
            attempt.Purpose == "handshake-verify" &&
            attempt.IpAddress == "203.0.113.81" &&
            attempt.UserId == userId.ToString("D") &&
            attempt.CorrelationId == "handshake-user-rate-limit"), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()), Times.Exactly(2));
        _eventSinkMock.Verify(sink => sink.RecordAsync(It.Is<AshlarSecurityEvent>(securityEvent =>
            securityEvent.EventType == AshlarSecurityEventTypes.AuthenticationHandshakeVerificationRateLimited &&
            securityEvent.UserId == userId), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task BeginFactorVerificationAsyncShouldRateLimitInvalidTokenLookupBeforeHashing()
    {
        _rateLimiterMock.Setup(r => r.CheckAsync(It.IsAny<RateLimitAttempt>(), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()))
                        .ReturnsAsync(new RateLimitDecision
                        {
                            Status = RateLimitStatus.Blocked,
                            Remaining = 0,
                            WindowResetAt = _timeProvider.GetUtcNow().AddMinutes(1)
                        });
        var context = new AuthenticationContext(IpAddress: "203.0.113.82");

        var result = await _service.BeginFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest("invalid", "totp", Context: context));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.RateLimitExceeded));
        }

        _rateLimiterMock.Verify(r => r.CheckAsync(It.Is<RateLimitAttempt>(attempt =>
            attempt.Purpose == "handshake-lookup" &&
            attempt.IpAddress == "203.0.113.82"), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()), Times.Once);
        _tokenHasherMock.Verify(h => h.HashToken(It.IsAny<string>()), Times.Never);
        _repositoryMock.Verify(r => r.FindByTokenHashAsync(It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
        _eventSinkMock.Verify(sink => sink.RecordAsync(It.Is<AshlarSecurityEvent>(securityEvent =>
            securityEvent.EventType == AshlarSecurityEventTypes.AuthenticationHandshakeVerificationRateLimited &&
            securityEvent.FailureReason == SecurityEventFailureReasons.RateLimited), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task CompleteFactorVerificationAsyncShouldRejectOversizedMetadata()
    {
        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "hashed:raw-token",
            _timeProvider.GetUtcNow(),
            _timeProvider.GetUtcNow().AddMinutes(15),
            false,
            false,
            new HashSet<string> { "totp" },
            new HashSet<string>());

        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", It.IsAny<bool>(), It.IsAny<CancellationToken>()))
                       .ReturnsAsync(handshake);

        var metadata = new Dictionary<string, string> { ["device"] = new string('x', 513) };

        var result = await _service.CompleteFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "totp", metadata));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidMetadata));
        }
    }

    [Test]
    public async Task CompleteFactorVerificationAsyncShouldTreatNullMetadataValueAsEmpty()
    {
        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "hashed:raw-token",
            _timeProvider.GetUtcNow(),
            _timeProvider.GetUtcNow().AddMinutes(15),
            false,
            false,
            new HashSet<string> { "totp" },
            new HashSet<string>());

        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", It.IsAny<bool>(), It.IsAny<CancellationToken>()))
                       .ReturnsAsync(handshake);

        var result = await _service.CompleteFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest(
            "raw-token",
            "totp",
            // ReSharper disable once NullableWarningSuppressionIsUsed
            new Dictionary<string, string> { ["device"] = null! }));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.Metadata?["device"], Is.EqualTo(string.Empty));
        }
    }

    [Test]
    public async Task BeginFactorVerificationAsyncShouldNotTrustHandshakeMetadataContextInSuspiciousAttemptNotification()
    {
        var userId = Guid.NewGuid();
        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            userId,
            "hashed:raw-token",
            _timeProvider.GetUtcNow(),
            _timeProvider.GetUtcNow().AddMinutes(15),
            false,
            false,
            new HashSet<string> { "totp" },
            new HashSet<string>(),
            new Dictionary<string, string>
            {
                ["ip_address"] = "203.0.113.10",
                ["user_agent"] = "Mozilla/5.0"
            });
        var userRepository = new Mock<IUserRepository>();
        var notificationService = new Mock<ISecurityNotificationService>();
        var service = new AuthenticationHandshakeService(
            _repositoryMock.Object,
            new FixedTokenGenerator("raw-token"),
            _tokenHasherMock.Object,
            new NullTransactionProvider(),
            new AuthenticationHandshakeServiceDependencies(
                Options.Create(new AuthenticationHandshakeOptions()),
                _timeProvider,
                _eventSinkMock.Object,
                _rateLimiterMock.Object,
                userRepository.Object,
                notificationService.Object));

        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", It.IsAny<bool>(), It.IsAny<CancellationToken>()))
                       .ReturnsAsync(handshake);
        _rateLimiterMock.SetupSequence(r => r.CheckAsync(It.IsAny<RateLimitAttempt>(), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()))
                        .ReturnsAsync(new RateLimitDecision
                        {
                            Status = RateLimitStatus.Allowed,
                            Remaining = 5,
                            WindowResetAt = _timeProvider.GetUtcNow().AddMinutes(1)
                        })
                        .ReturnsAsync(new RateLimitDecision
                        {
                            Status = RateLimitStatus.Blocked,
                            Remaining = 0,
                            WindowResetAt = _timeProvider.GetUtcNow().AddMinutes(1)
                        });
        userRepository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
                          .ReturnsAsync(new User { Id = userId, DisplayEmail = "user@example.com" });

        await service.BeginFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "totp"));

        notificationService.Verify(n => n.NotifyAsync(It.Is<SecurityNotification>(notification =>
            notification.Type == SecurityNotificationType.SuspiciousAuthenticationAttempt &&
            notification.IpAddress == null &&
            notification.UserAgent == null), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task BeginFactorVerificationAsyncShouldNotTrustRequestMetadataContextInSuspiciousAttemptNotification()
    {
        var userId = Guid.NewGuid();
        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            userId,
            "hashed:raw-token",
            _timeProvider.GetUtcNow(),
            _timeProvider.GetUtcNow().AddMinutes(15),
            false,
            false,
            new HashSet<string> { "totp" },
            new HashSet<string>(),
            new Dictionary<string, string>
            {
                ["ip_address"] = "198.51.100.1",
                ["user_agent"] = "Original"
            });
        var userRepository = new Mock<IUserRepository>();
        var notificationService = new Mock<ISecurityNotificationService>();
        var service = new AuthenticationHandshakeService(
            _repositoryMock.Object,
            new FixedTokenGenerator("raw-token"),
            _tokenHasherMock.Object,
            new NullTransactionProvider(),
            new AuthenticationHandshakeServiceDependencies(
                Options.Create(new AuthenticationHandshakeOptions()),
                _timeProvider,
                _eventSinkMock.Object,
                _rateLimiterMock.Object,
                userRepository.Object,
                notificationService.Object));

        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", It.IsAny<bool>(), It.IsAny<CancellationToken>()))
                       .ReturnsAsync(handshake);
        _rateLimiterMock.SetupSequence(r => r.CheckAsync(It.IsAny<RateLimitAttempt>(), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()))
                        .ReturnsAsync(new RateLimitDecision
                        {
                            Status = RateLimitStatus.Allowed,
                            Remaining = 5,
                            WindowResetAt = _timeProvider.GetUtcNow().AddMinutes(1)
                        })
                        .ReturnsAsync(new RateLimitDecision
                        {
                            Status = RateLimitStatus.Blocked,
                            Remaining = 0,
                            WindowResetAt = _timeProvider.GetUtcNow().AddMinutes(1)
                        });
        userRepository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
                          .ReturnsAsync(new User { Id = userId, DisplayEmail = "user@example.com" });

        await service.BeginFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest(
            "raw-token",
            "totp",
            new Dictionary<string, string>
            {
                ["ip_address"] = "203.0.113.10",
                ["user_agent"] = "Attempt"
            }));

        notificationService.Verify(n => n.NotifyAsync(It.Is<SecurityNotification>(notification =>
            notification.Type == SecurityNotificationType.SuspiciousAuthenticationAttempt &&
            notification.IpAddress == null &&
            notification.UserAgent == null), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task CompleteFactorVerificationAsyncShouldFailForInvalidFactorType()
    {
        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "hashed:raw-token",
            _timeProvider.GetUtcNow(),
            _timeProvider.GetUtcNow().AddMinutes(15),
            false,
            false,
            new HashSet<string> { "totp" },
            new HashSet<string>());

        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", It.IsAny<bool>(), It.IsAny<CancellationToken>()))
                       .ReturnsAsync(handshake);

        var result = await _service.CompleteFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "invalid"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidFactorType));
        }
    }

    [Test]
    public async Task CompleteFactorVerificationAsyncShouldUseCanonicalRequiredFactorMatching()
    {
        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "hashed:raw-token",
            _timeProvider.GetUtcNow(),
            _timeProvider.GetUtcNow().AddMinutes(15),
            false,
            false,
            new HashSet<string> { "custom_step_up" },
            new HashSet<string>());

        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", It.IsAny<bool>(), It.IsAny<CancellationToken>()))
                       .ReturnsAsync(handshake);

        var result = await _service.CompleteFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "custom-step-up"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.VerifiedFactors, Has.Count.EqualTo(1));
            Assert.That(result.Value?.VerifiedFactors, Does.Contain("custom_step_up"));
            Assert.That(result.Value?.IsCompleted, Is.True);
        }

        _repositoryMock.Verify(r => r.UpdateAsync(
            It.Is<AuthenticationHandshake>(item =>
                item.VerifiedFactors.Contains("custom_step_up") &&
                !item.VerifiedFactors.Contains("custom-step-up")),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task CompleteFactorVerificationAsyncShouldFailForAlreadyVerifiedFactor()
    {
        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "hashed:raw-token",
            _timeProvider.GetUtcNow(),
            _timeProvider.GetUtcNow().AddMinutes(15),
            false,
            false,
            new HashSet<string> { "totp", "email" },
            new HashSet<string> { "totp" });

        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", It.IsAny<bool>(), It.IsAny<CancellationToken>()))
                       .ReturnsAsync(handshake);

        var result = await _service.CompleteFactorVerificationAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "totp"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.FactorAlreadyVerified));
        }
    }

    [Test]
    public async Task RevokeHandshakeAsyncShouldMarkAsRevoked()
    {
        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "hashed:raw-token",
            _timeProvider.GetUtcNow(),
            _timeProvider.GetUtcNow().AddMinutes(15),
            false,
            false,
            new HashSet<string> { "totp" },
            new HashSet<string>());

        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", It.IsAny<bool>(), It.IsAny<CancellationToken>()))
                       .ReturnsAsync(handshake);

        var result = await _service.RevokeHandshakeAsync("raw-token");

        Assert.That(result.Succeeded, Is.True);
        _repositoryMock.Verify(r => r.UpdateAsync(It.Is<AuthenticationHandshake>(h => h.IsRevoked && h.RevokedAt == _timeProvider.GetUtcNow()), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task RevokeHandshakeAsyncShouldFailGenericallyForTenantMismatch()
    {
        var handshake = CreateHandshake(Guid.NewGuid());
        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", true, It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        var result = await _service.RevokeHandshakeAsync("raw-token", new AuthenticationContext(TenantId: Guid.NewGuid()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.HandshakeNotFound));
        }

        _repositoryMock.Verify(r => r.UpdateAsync(It.IsAny<AuthenticationHandshake>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task RevokeHandshakeAsyncShouldFailOnStaleUpdateWithoutCommitOrSuccessEvent()
    {
        var operations = new List<string>();
        var transactionProvider = new RecordingTransactionProvider(operations);
        var service = new AuthenticationHandshakeService(
            _repositoryMock.Object,
            new FixedTokenGenerator("raw-token"),
            _tokenHasherMock.Object,
            transactionProvider,
            new AuthenticationHandshakeServiceDependencies(
                Options.Create(new AuthenticationHandshakeOptions()),
                _timeProvider,
                _eventSinkMock.Object,
                _rateLimiterMock.Object));
        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "hashed:raw-token",
            _timeProvider.GetUtcNow(),
            _timeProvider.GetUtcNow().AddMinutes(15),
            false,
            false,
            new HashSet<string> { "totp" },
            new HashSet<string>());

        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", true, It.IsAny<CancellationToken>()))
                       .Callback(() => operations.Add("read"))
                       .ReturnsAsync(handshake);
        _repositoryMock.Setup(r => r.UpdateAsync(It.IsAny<AuthenticationHandshake>(), It.IsAny<CancellationToken>()))
                       .Callback(() => operations.Add("update"))
                       .ReturnsAsync(false);

        var result = await service.RevokeHandshakeAsync("raw-token");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ConcurrencyConflict));
            Assert.That(operations, Is.EqualTo(ExpectedStaleUpdateTransactionOperations));
        }

        _eventSinkMock.Verify(sink => sink.RecordAsync(It.Is<AshlarSecurityEvent>(securityEvent =>
            securityEvent.EventType == AshlarSecurityEventTypes.AuthenticationHandshakeFailed &&
            securityEvent.Outcome == SecurityEventOutcomes.Failure &&
            securityEvent.FailureReason == AshlarFailureCodes.ConcurrencyConflict.Value &&
            securityEvent.UserId == handshake.UserId &&
            securityEvent.Properties != null &&
            securityEvent.Properties.ContainsKey("handshake_id") &&
            securityEvent.Properties["handshake_id"] == handshake.Id.ToString()), It.IsAny<CancellationToken>()), Times.Once);
        _eventSinkMock.Verify(sink => sink.RecordAsync(It.Is<AshlarSecurityEvent>(securityEvent =>
            securityEvent.EventType == AshlarSecurityEventTypes.AuthenticationHandshakeRevoked &&
            securityEvent.Outcome == SecurityEventOutcomes.Success), It.IsAny<CancellationToken>()), Times.Never);
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase(" ")]
    public async Task RevokeHandshakeAsyncShouldReturnHandshakeNotFoundWhenTokenMissing(string? token)
    {
        var result = await _service.RevokeHandshakeAsync(token);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.HandshakeNotFound));
        }

        _repositoryMock.Verify(r => r.FindByTokenHashAsync(It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
        _repositoryMock.Verify(r => r.UpdateAsync(It.IsAny<AuthenticationHandshake>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task RevokeHandshakeAsyncShouldDoNothingWhenHandshakeNotFound()
    {
        _repositoryMock.Setup(r => r.FindByTokenHashAsync(It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()))
                       .ReturnsAsync((AuthenticationHandshake?)null);

        await _service.RevokeHandshakeAsync("raw-token");

        _repositoryMock.Verify(r => r.UpdateAsync(It.IsAny<AuthenticationHandshake>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task RevokeHandshakeAsyncShouldReturnHandshakeNotFoundForOverlongTokenWithoutMutatingState()
    {
        var overlongToken = new string('a', 257);
        _tokenHasherMock.Setup(h => h.HashToken(overlongToken)).Throws(new ArgumentException("Token exceeds maximum allowed length.", "token"));

        var result = await _service.RevokeHandshakeAsync(overlongToken);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.HandshakeNotFound));
        }

        _repositoryMock.Verify(r => r.FindByTokenHashAsync(It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
        _repositoryMock.Verify(r => r.UpdateAsync(It.IsAny<AuthenticationHandshake>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task RevokeHandshakeAsyncShouldDoNothingWhenAlreadyRevoked()
    {
        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "hashed:raw-token",
            _timeProvider.GetUtcNow(),
            _timeProvider.GetUtcNow().AddMinutes(15),
            true,
            false,
            new HashSet<string> { "totp" },
            new HashSet<string>());

        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", It.IsAny<bool>(), It.IsAny<CancellationToken>()))
                       .ReturnsAsync(handshake);

        await _service.RevokeHandshakeAsync("raw-token");

        _repositoryMock.Verify(r => r.UpdateAsync(It.IsAny<AuthenticationHandshake>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public void ConstructorShouldThrowOnNullRepository()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationHandshakeService(null!, new FixedTokenGenerator(""), _tokenHasherMock.Object, new NullTransactionProvider()));
    }

    [Test]
    public void ConstructorShouldThrowOnNullTokenGenerator()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationHandshakeService(_repositoryMock.Object, null!, _tokenHasherMock.Object, new NullTransactionProvider()));
    }

    [Test]
    public void ConstructorShouldThrowOnNullTokenHasher()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationHandshakeService(_repositoryMock.Object, new FixedTokenGenerator(""), null!, new NullTransactionProvider()));
    }

    [Test]
    public void ConstructorShouldThrowOnNullTransactionProvider()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationHandshakeService(_repositoryMock.Object, new FixedTokenGenerator(""), _tokenHasherMock.Object, null!));
    }

    [Test]
    public void ConstructorShouldAcceptNullOptionalDependencies()
    {
        var service = new AuthenticationHandshakeService(
            _repositoryMock.Object,
            new FixedTokenGenerator(""),
            _tokenHasherMock.Object,
            new NullTransactionProvider());

        Assert.That(service, Is.Not.Null);
    }

    [Test]
    public void ConstructorShouldAcceptDependenciesWithNullOptions()
    {
        var service = new AuthenticationHandshakeService(
            _repositoryMock.Object,
            new FixedTokenGenerator(""),
            _tokenHasherMock.Object,
            new NullTransactionProvider(),
            new AuthenticationHandshakeServiceDependencies(TimeProvider: _timeProvider));

        Assert.That(service, Is.Not.Null);
    }

    private AuthenticationHandshake CreateHandshake(Guid? tenantId = null)
    {
        return new AuthenticationHandshake(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "hashed:raw-token",
            _timeProvider.GetUtcNow(),
            _timeProvider.GetUtcNow().AddMinutes(5),
            false,
            false,
            new HashSet<string> { "totp" },
            new HashSet<string>())
        {
            TenantId = tenantId
        };
    }

    private sealed class FixedTokenGenerator(string token) : ISecureTokenGenerator
    {
        public string GenerateToken(int byteLength = ISecureTokenGenerator.DefaultByteLength) => token;
    }

    private sealed class SinglePassEnumerable<T>(IEnumerable<T> values) : IEnumerable<T>
    {
        private bool _enumerated;

        public IEnumerator<T> GetEnumerator()
        {
            if (_enumerated)
            {
                throw new InvalidOperationException("Sequence was enumerated more than once.");
            }

            _enumerated = true;
            return values.GetEnumerator();
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }

    private sealed class RecordingTransactionProvider(List<string> operations) : IAshlarTransactionProvider
    {
        public bool IsActive { get; private set; }

        public Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Assert.That(IsActive, Is.False);
            IsActive = true;
            operations.Add("begin");
            return Task.FromResult<IAshlarTransaction>(new RecordingTransaction(operations, Complete));
        }

        private void Complete()
        {
            IsActive = false;
        }
    }

    private sealed class RecordingTransaction(List<string> operations, Action complete) : IAshlarTransaction
    {
        private readonly List<Func<CancellationToken, Task>> _hooks = [];
        private bool _completed;

        public async Task CommitAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ObjectDisposedException.ThrowIf(_completed, this);
            operations.Add("commit");
            _completed = true;
            complete();

            foreach (var hook in _hooks)
            {
                await hook(CancellationToken.None);
            }
        }

        public Task RollbackAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ObjectDisposedException.ThrowIf(_completed, this);
            operations.Add("rollback");
            _completed = true;
            complete();
            return Task.CompletedTask;
        }

        public void OnCommitted(Func<CancellationToken, Task> action)
        {
            ObjectDisposedException.ThrowIf(_completed, this);
            _hooks.Add(action ?? throw new ArgumentNullException(nameof(action)));
        }

        public ValueTask DisposeAsync()
        {
            if (!_completed)
            {
                operations.Add("dispose");
                _completed = true;
                complete();
            }

            return ValueTask.CompletedTask;
        }
    }
}
