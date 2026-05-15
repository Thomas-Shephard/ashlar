using Ashlar.Auditing;
using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Identity;

public sealed class AuthenticationHandshakeServiceTests
{
    private static readonly string[] ExpectedRequiredFactors = ["totp", "email"];

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

        var result = await _service.CreateHandshakeAsync(new CreateAuthenticationHandshakeRequest(userId, requiredFactors));

        Assert.That(result.Value, Is.Not.Null);

        var handshake = result.Value.Handshake;
        var token = result.Value.Token;

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(token, Is.EqualTo("raw-token"));
            Assert.That(handshake.UserId, Is.EqualTo(userId));
            Assert.That(handshake.TokenHash, Is.EqualTo("hashed:raw-token"));
            Assert.That(handshake.RequiredFactors, Is.EquivalentTo(requiredFactors));
            Assert.That(handshake.VerifiedFactors, Is.Empty);
            Assert.That(handshake.IsCompleted, Is.False);
            Assert.That(handshake.IsRevoked, Is.False);
        }

        _repositoryMock.Verify(r => r.CreateAsync(It.Is<AuthenticationHandshake>(h => h.Id == handshake.Id), It.IsAny<CancellationToken>()), Times.Once);
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
            Assert.That(result.FailureReason, Is.EqualTo("no_factors_specified"));
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
            Assert.That(result.FailureReason, Is.EqualTo("invalid_metadata"));
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
            Assert.That(result.FailureReason, Is.EqualTo("invalid_metadata"));
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
            Assert.That(result.FailureReason, Is.EqualTo("invalid_metadata"));
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
            Assert.That(result.FailureReason, Is.EqualTo("invalid_metadata"));
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
    public async Task VerifyFactorAsyncShouldSucceedAndMarkAsCompletedWhenAllFactorsVerified()
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

        var result = await _service.VerifyFactorAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "totp"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.VerifiedFactors, Contains.Item("totp"));
            Assert.That(result.Value?.IsCompleted, Is.True);
            Assert.That(result.Value?.CompletedAt, Is.EqualTo(_timeProvider.GetUtcNow()));
        }

        _repositoryMock.Verify(r => r.UpdateAsync(It.Is<AuthenticationHandshake>(h => h.IsCompleted && h.CompletedAt == _timeProvider.GetUtcNow()), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task VerifyFactorAsyncShouldSucceedWhenRateLimiterIsNotRegistered()
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

        var result = await service.VerifyFactorAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "totp"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.IsCompleted, Is.True);
        }

        _rateLimiterMock.Verify(r => r.CheckAsync(It.IsAny<RateLimitAttempt>(), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task VerifyFactorAsyncShouldSucceedAndNotMarkAsCompletedWhenFactorsRemaining()
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

        var result = await _service.VerifyFactorAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "totp"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.VerifiedFactors, Contains.Item("totp"));
            Assert.That(result.Value?.IsCompleted, Is.False);
        }
    }

    [Test]
    public async Task VerifyFactorAsyncShouldNotMutateOriginalHandshakeMetadata()
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

        var result = await _service.VerifyFactorAsync(new VerifyAuthenticationHandshakeRequest(
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
    public async Task VerifyFactorAsyncShouldAddRequestMetadataWhenHandshakeMetadataIsNull()
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

        var result = await _service.VerifyFactorAsync(new VerifyAuthenticationHandshakeRequest(
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
    public void VerifyFactorAsyncShouldThrowOnNullRequest()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(() => _service.VerifyFactorAsync(null!));
    }

    [Test]
    public async Task VerifyFactorAsyncShouldFailWhenTokenMissing()
    {
        var result = await _service.VerifyFactorAsync(new VerifyAuthenticationHandshakeRequest("", "totp"));
        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo("empty_token"));
        }
    }

    [Test]
    public async Task VerifyFactorAsyncShouldFailWhenHandshakeNotFound()
    {
        _repositoryMock.Setup(r => r.FindByTokenHashAsync(It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()))
                       .ReturnsAsync((AuthenticationHandshake?)null);

        var result = await _service.VerifyFactorAsync(new VerifyAuthenticationHandshakeRequest("invalid", "totp"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo("handshake_not_found"));
        }
    }

    [Test]
    public async Task VerifyFactorAsyncShouldFailWhenExpired()
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

        var result = await _service.VerifyFactorAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "totp"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo("handshake_expired"));
        }
    }

    [Test]
    public async Task VerifyFactorAsyncShouldFailWhenRevoked()
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

        var result = await _service.VerifyFactorAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "totp"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo("handshake_revoked"));
        }
    }

    [Test]
    public async Task VerifyFactorAsyncShouldFailWhenAlreadyCompleted()
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

        var result = await _service.VerifyFactorAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "totp"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo("handshake_already_completed"));
        }
    }

    [Test]
    public async Task VerifyFactorAsyncShouldFailWhenRateLimited()
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

        var result = await _service.VerifyFactorAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "totp"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo("Rate limit exceeded."));
        }
    }

    [Test]
    public async Task VerifyFactorAsyncShouldRejectOversizedMetadata()
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

        var result = await _service.VerifyFactorAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "totp", metadata));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo("invalid_metadata"));
        }
    }

    [Test]
    public async Task VerifyFactorAsyncShouldTreatNullMetadataValueAsEmpty()
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

        var result = await _service.VerifyFactorAsync(new VerifyAuthenticationHandshakeRequest(
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
    public async Task VerifyFactorAsyncShouldNotTrustHandshakeMetadataContextInSuspiciousAttemptNotification()
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
        var identityRepository = new Mock<IIdentityRepository>();
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
                identityRepository.Object,
                notificationService.Object));

        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", It.IsAny<bool>(), It.IsAny<CancellationToken>()))
                       .ReturnsAsync(handshake);
        _rateLimiterMock.Setup(r => r.CheckAsync(It.IsAny<RateLimitAttempt>(), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()))
                        .ReturnsAsync(new RateLimitDecision
                        {
                            Status = RateLimitStatus.Blocked,
                            Remaining = 0,
                            WindowResetAt = _timeProvider.GetUtcNow().AddMinutes(1)
                        });
        identityRepository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
                          .ReturnsAsync(new User { Id = userId, Email = "user@example.com" });

        await service.VerifyFactorAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "totp"));

        notificationService.Verify(n => n.NotifyAsync(It.Is<SecurityNotification>(notification =>
            notification.Type == SecurityNotificationType.SuspiciousAuthenticationAttempt &&
            notification.IpAddress == null &&
            notification.UserAgent == null), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task VerifyFactorAsyncShouldNotTrustRequestMetadataContextInSuspiciousAttemptNotification()
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
        var identityRepository = new Mock<IIdentityRepository>();
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
                identityRepository.Object,
                notificationService.Object));

        _repositoryMock.Setup(r => r.FindByTokenHashAsync("hashed:raw-token", It.IsAny<bool>(), It.IsAny<CancellationToken>()))
                       .ReturnsAsync(handshake);
        _rateLimiterMock.Setup(r => r.CheckAsync(It.IsAny<RateLimitAttempt>(), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()))
                        .ReturnsAsync(new RateLimitDecision
                        {
                            Status = RateLimitStatus.Blocked,
                            Remaining = 0,
                            WindowResetAt = _timeProvider.GetUtcNow().AddMinutes(1)
                        });
        identityRepository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
                          .ReturnsAsync(new User { Id = userId, Email = "user@example.com" });

        await service.VerifyFactorAsync(new VerifyAuthenticationHandshakeRequest(
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
    public async Task VerifyFactorAsyncShouldFailForInvalidFactorType()
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

        var result = await _service.VerifyFactorAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "invalid"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo("invalid_factor_type"));
        }
    }

    [Test]
    public async Task VerifyFactorAsyncShouldFailForAlreadyVerifiedFactor()
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

        var result = await _service.VerifyFactorAsync(new VerifyAuthenticationHandshakeRequest("raw-token", "totp"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo("factor_already_verified"));
        }
    }

    [Test]
    public async Task GetHandshakeAsyncShouldReturnHandshake()
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

        var result = await _service.GetHandshakeAsync("raw-token");

        Assert.That(result, Is.EqualTo(handshake));
    }

    [Test]
    public async Task GetHandshakeAsyncShouldReturnNullWhenTokenMissing()
    {
        var result = await _service.GetHandshakeAsync("");
        Assert.That(result, Is.Null);
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

        await _service.RevokeHandshakeAsync("raw-token");

        _repositoryMock.Verify(r => r.UpdateAsync(It.Is<AuthenticationHandshake>(h => h.IsRevoked && h.RevokedAt == _timeProvider.GetUtcNow()), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task RevokeHandshakeAsyncShouldDoNothingWhenTokenMissing()
    {
        await _service.RevokeHandshakeAsync("");
        _repositoryMock.Verify(r => r.FindByTokenHashAsync(It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
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
}
