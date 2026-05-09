using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Identity;

public sealed class AuthenticationSessionServiceTests
{
    private Mock<IAuthenticationSessionRepository> _repositoryMock;
    private Mock<ISecureTokenHasher> _tokenHasherMock;
    private FakeTimeProvider _timeProvider;
    private AuthenticationSessionService _service;

    [SetUp]
    public void SetUp()
    {
        _repositoryMock = new Mock<IAuthenticationSessionRepository>();
        _tokenHasherMock = new Mock<ISecureTokenHasher>();
        _timeProvider = new FakeTimeProvider(new DateTimeOffset(2025, 1, 1, 12, 0, 0, TimeSpan.Zero));

        _tokenHasherMock.Setup(h => h.HashToken(It.IsAny<string>())).Returns<string>(token => $"hashed:{token}");

        _service = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            timeProvider: _timeProvider);
    }

    [Test]
    public async Task CreateSessionAsyncShouldReturnRawTokenAndStoreOnlyTokenHash()
    {
        AuthenticationSession? storedSession = null;
        _repositoryMock
            .Setup(r => r.CreateSessionAsync(It.IsAny<AuthenticationSession>(), It.IsAny<CancellationToken>()))
            .Callback<AuthenticationSession, CancellationToken>((session, _) => storedSession = session)
            .Returns(Task.CompletedTask);

        var result = await _service.CreateSessionAsync(Guid.NewGuid(), new CreateAuthenticationSessionRequest());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Token, Is.EqualTo("raw-token"));
            Assert.That(storedSession?.TokenHash, Is.EqualTo("hashed:raw-token"));
            Assert.That(storedSession?.TokenHash, Is.Not.EqualTo(result.Token));
            Assert.That(storedSession, Is.SameAs(result.Session));
        }
    }

    [Test]
    public async Task CreateSessionAsyncShouldUseClockAndDefaultLifetime()
    {
        var now = _timeProvider.GetUtcNow();
        AuthenticationSession? storedSession = null;
        _repositoryMock
            .Setup(r => r.CreateSessionAsync(It.IsAny<AuthenticationSession>(), It.IsAny<CancellationToken>()))
            .Callback<AuthenticationSession, CancellationToken>((session, _) => storedSession = session)
            .Returns(Task.CompletedTask);

        await _service.CreateSessionAsync(Guid.NewGuid(), new CreateAuthenticationSessionRequest());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(storedSession?.CreatedAt, Is.EqualTo(now));
            Assert.That(storedSession?.ExpiresAt, Is.EqualTo(now.AddDays(14)));
        }
    }

    [Test]
    public async Task CreateSessionAsyncShouldUseRequestedLifetime()
    {
        var now = _timeProvider.GetUtcNow();
        AuthenticationSession? storedSession = null;
        _repositoryMock
            .Setup(r => r.CreateSessionAsync(It.IsAny<AuthenticationSession>(), It.IsAny<CancellationToken>()))
            .Callback<AuthenticationSession, CancellationToken>((session, _) => storedSession = session)
            .Returns(Task.CompletedTask);

        await _service.CreateSessionAsync(Guid.NewGuid(), new CreateAuthenticationSessionRequest(Lifetime: TimeSpan.FromHours(2)));

        Assert.That(storedSession?.ExpiresAt, Is.EqualTo(now.AddHours(2)));
    }

    [Test]
    public async Task CreateSessionAsyncShouldStoreOptionalSessionContext()
    {
        AuthenticationSession? storedSession = null;
        _repositoryMock
            .Setup(r => r.CreateSessionAsync(It.IsAny<AuthenticationSession>(), It.IsAny<CancellationToken>()))
            .Callback<AuthenticationSession, CancellationToken>((session, _) => storedSession = session)
            .Returns(Task.CompletedTask);

        await _service.CreateSessionAsync(
            Guid.NewGuid(),
            new CreateAuthenticationSessionRequest(
                IpAddress: "127.0.0.1",
                UserAgent: "test-agent",
                Metadata: """{"device":"test"}"""));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(storedSession?.IpAddress, Is.EqualTo("127.0.0.1"));
            Assert.That(storedSession?.UserAgent, Is.EqualTo("test-agent"));
            Assert.That(storedSession?.Metadata, Is.EqualTo("""{"device":"test"}"""));
        }
    }

    [Test]
    public async Task CreateSessionAsyncShouldOmitOptionalSessionContextWhenDisabled()
    {
        var service = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionOptions
            {
                StoreIpAddress = false,
                StoreUserAgent = false,
                StoreMetadata = false
            },
            _timeProvider);

        AuthenticationSession? storedSession = null;
        _repositoryMock
            .Setup(r => r.CreateSessionAsync(It.IsAny<AuthenticationSession>(), It.IsAny<CancellationToken>()))
            .Callback<AuthenticationSession, CancellationToken>((session, _) => storedSession = session)
            .Returns(Task.CompletedTask);

        await service.CreateSessionAsync(
            Guid.NewGuid(),
            new CreateAuthenticationSessionRequest(
                IpAddress: "127.0.0.1",
                UserAgent: "test-agent",
                Metadata: """{"device":"test"}"""));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(storedSession?.IpAddress, Is.Null);
            Assert.That(storedSession?.UserAgent, Is.Null);
            Assert.That(storedSession?.Metadata, Is.Null);
        }
    }

    [Test]
    public void CreateSessionAsyncShouldRejectEmptyUserId()
    {
        Assert.ThrowsAsync<ArgumentException>(() => _service.CreateSessionAsync(Guid.Empty, new CreateAuthenticationSessionRequest()));
    }

    [Test]
    public void CreateSessionAsyncShouldRejectNullRequest()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(() => _service.CreateSessionAsync(Guid.NewGuid(), null!));
    }

    [Test]
    public void CreateSessionAsyncShouldRejectNonPositiveRequestedLifetime()
    {
        Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            _service.CreateSessionAsync(Guid.NewGuid(), new CreateAuthenticationSessionRequest(Lifetime: TimeSpan.Zero)));
    }

    [Test]
    public void CreateSessionAsyncShouldRejectTooLongIpAddress()
    {
        Assert.ThrowsAsync<ArgumentException>(() =>
            _service.CreateSessionAsync(Guid.NewGuid(), new CreateAuthenticationSessionRequest(IpAddress: new string('1', 46))));
    }

    [Test]
    public void CreateSessionAsyncShouldRejectTooLongUserAgent()
    {
        Assert.ThrowsAsync<ArgumentException>(() =>
            _service.CreateSessionAsync(Guid.NewGuid(), new CreateAuthenticationSessionRequest(UserAgent: new string('a', 513))));
    }

    [Test]
    public void CreateSessionAsyncShouldRejectTooLongMetadata()
    {
        Assert.ThrowsAsync<ArgumentException>(() =>
            _service.CreateSessionAsync(Guid.NewGuid(), new CreateAuthenticationSessionRequest(Metadata: new string('m', 8193))));
    }

    [Test]
    public async Task ValidateSessionAsyncShouldSucceedForActiveSession()
    {
        var session = CreateSession(expiresAt: _timeProvider.GetUtcNow().AddHours(1));
        _repositoryMock
            .Setup(r => r.GetSessionByTokenHashAsync("hashed:raw-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(session);
        _repositoryMock
            .Setup(r => r.UpdateSessionLastSeenAsync(session.Id, _timeProvider.GetUtcNow(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var result = await _service.ValidateSessionAsync("raw-token");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Status, Is.EqualTo(AuthenticationSessionValidationStatus.Success));
            Assert.That(result.Session, Is.EqualTo(session));
            Assert.That(result.UserId, Is.EqualTo(session.UserId));
        }
    }

    [Test]
    public async Task ValidateSessionAsyncShouldFailForMissingToken()
    {
        var result = await _service.ValidateSessionAsync(" ");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.Status, Is.EqualTo(AuthenticationSessionValidationStatus.Failed));
            _repositoryMock.Verify(r => r.GetSessionByTokenHashAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task ValidateSessionAsyncShouldFailWhenHasherRejectsToken()
    {
        _tokenHasherMock
            .Setup(h => h.HashToken("oversized-token"))
            .Throws(new ArgumentException("Token exceeds maximum allowed length.", "token"));

        var result = await _service.ValidateSessionAsync("oversized-token");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.Status, Is.EqualTo(AuthenticationSessionValidationStatus.Failed));
            _repositoryMock.Verify(r => r.GetSessionByTokenHashAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task ValidateSessionAsyncShouldReturnFailedWhenSessionIsMissing()
    {
        _repositoryMock
            .Setup(r => r.GetSessionByTokenHashAsync("hashed:raw-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync((AuthenticationSession?)null);

        var result = await _service.ValidateSessionAsync("raw-token");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.Status, Is.EqualTo(AuthenticationSessionValidationStatus.Failed));
        }
    }

    [Test]
    public async Task ValidateSessionAsyncShouldReturnExpiredForExpiredSession()
    {
        var session = CreateSession(expiresAt: _timeProvider.GetUtcNow());
        _repositoryMock
            .Setup(r => r.GetSessionByTokenHashAsync("hashed:raw-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(session);

        var result = await _service.ValidateSessionAsync("raw-token");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.Status, Is.EqualTo(AuthenticationSessionValidationStatus.Expired));
            Assert.That(result.Session, Is.EqualTo(session));
            Assert.That(result.UserId, Is.EqualTo(session.UserId));
        }
    }

    [Test]
    public async Task ValidateSessionAsyncShouldReturnRevokedForRevokedSession()
    {
        var session = CreateSession(expiresAt: _timeProvider.GetUtcNow().AddHours(1));
        session.RevokedAt = _timeProvider.GetUtcNow().AddMinutes(-1);
        _repositoryMock
            .Setup(r => r.GetSessionByTokenHashAsync("hashed:raw-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(session);

        var result = await _service.ValidateSessionAsync("raw-token");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.Status, Is.EqualTo(AuthenticationSessionValidationStatus.Revoked));
            Assert.That(result.Session, Is.EqualTo(session));
            Assert.That(result.UserId, Is.EqualTo(session.UserId));
        }
    }

    [Test]
    public async Task ValidateSessionAsyncShouldUpdateLastSeenWhenThresholdElapsed()
    {
        var now = _timeProvider.GetUtcNow();
        var session = CreateSession(expiresAt: now.AddHours(1), lastSeenAt: now.AddMinutes(-6));
        _repositoryMock
            .Setup(r => r.GetSessionByTokenHashAsync("hashed:raw-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(session);
        _repositoryMock
            .Setup(r => r.UpdateSessionLastSeenAsync(session.Id, now, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var result = await _service.ValidateSessionAsync("raw-token");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(session.LastSeenAt, Is.EqualTo(now));
        }
    }

    [Test]
    public async Task ValidateSessionAsyncShouldNotMutateLastSeenWhenRepositoryReturnsFalse()
    {
        var now = _timeProvider.GetUtcNow();
        var lastSeenAt = now.AddMinutes(-6);
        var session = CreateSession(expiresAt: now.AddHours(1), lastSeenAt: lastSeenAt);
        _repositoryMock
            .Setup(r => r.GetSessionByTokenHashAsync("hashed:raw-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(session);
        _repositoryMock
            .Setup(r => r.UpdateSessionLastSeenAsync(session.Id, now, It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var result = await _service.ValidateSessionAsync("raw-token");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(session.LastSeenAt, Is.EqualTo(lastSeenAt));
        }
    }

    [Test]
    public async Task ValidateSessionAsyncShouldNotUpdateLastSeenWhenThresholdHasNotElapsed()
    {
        var now = _timeProvider.GetUtcNow();
        var lastSeenAt = now.AddMinutes(-4);
        var session = CreateSession(expiresAt: now.AddHours(1), lastSeenAt: lastSeenAt);
        _repositoryMock
            .Setup(r => r.GetSessionByTokenHashAsync("hashed:raw-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(session);

        var result = await _service.ValidateSessionAsync("raw-token");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(session.LastSeenAt, Is.EqualTo(lastSeenAt));
            _repositoryMock.Verify(r => r.UpdateSessionLastSeenAsync(It.IsAny<Guid>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task ValidateSessionAsyncShouldSucceedWhenLastSeenUpdateFails()
    {
        var session = CreateSession(expiresAt: _timeProvider.GetUtcNow().AddHours(1));
        _repositoryMock
            .Setup(r => r.GetSessionByTokenHashAsync("hashed:raw-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(session);
        _repositoryMock
            .Setup(r => r.UpdateSessionLastSeenAsync(session.Id, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("store unavailable"));

        var result = await _service.ValidateSessionAsync("raw-token");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Status, Is.EqualTo(AuthenticationSessionValidationStatus.Success));
            Assert.That(session.LastSeenAt, Is.Null);
        }
    }

    [Test]
    public async Task RevokeSessionAsyncShouldPassCurrentTimeAndReason()
    {
        var sessionId = Guid.NewGuid();
        var now = _timeProvider.GetUtcNow();
        _repositoryMock
            .Setup(r => r.RevokeSessionAsync(sessionId, now, "signed-out", It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var revoked = await _service.RevokeSessionAsync(sessionId, "signed-out");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revoked, Is.True);
            _repositoryMock.Verify(r => r.RevokeSessionAsync(sessionId, now, "signed-out", It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [Test]
    public void RevokeSessionAsyncShouldRejectEmptySessionId()
    {
        Assert.ThrowsAsync<ArgumentException>(() => _service.RevokeSessionAsync(Guid.Empty));
    }

    [Test]
    public async Task RevokeSessionsForUserAsyncShouldPassCurrentTimeAndReason()
    {
        var userId = Guid.NewGuid();
        var now = _timeProvider.GetUtcNow();
        _repositoryMock
            .Setup(r => r.RevokeSessionsForUserAsync(userId, now, "password-reset", It.IsAny<CancellationToken>()))
            .ReturnsAsync(3);

        var revoked = await _service.RevokeSessionsForUserAsync(userId, "password-reset");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revoked, Is.EqualTo(3));
            _repositoryMock.Verify(r => r.RevokeSessionsForUserAsync(userId, now, "password-reset", It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [Test]
    public void RevokeSessionsForUserAsyncShouldRejectEmptyUserId()
    {
        Assert.ThrowsAsync<ArgumentException>(() => _service.RevokeSessionsForUserAsync(Guid.Empty));
    }

    [Test]
    public async Task ListSessionsForUserAsyncShouldReturnSummaries()
    {
        var userId = Guid.NewGuid();
        var sessions = new List<AuthenticationSession>
        {
            CreateSession(expiresAt: _timeProvider.GetUtcNow().AddHours(1), userId: userId),
            CreateSession(expiresAt: _timeProvider.GetUtcNow().AddHours(-1), userId: userId)
        };
        sessions[0].IpAddress = "1.1.1.1";
        sessions[0].UserAgent = "agent-1";

        _repositoryMock
            .Setup(r => r.ListSessionsForUserAsync(userId, true, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(sessions.Where(s => s.IsActive(_timeProvider.GetUtcNow())).ToList().AsReadOnly());

        var result = await _service.ListSessionsForUserAsync(userId, new ListAuthenticationSessionsRequest { ActiveOnly = true, CurrentSessionId = sessions[0].Id });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result, Has.Count.EqualTo(1));
            Assert.That(result[0].Id, Is.EqualTo(sessions[0].Id));
            Assert.That(result[0].IpAddress, Is.EqualTo("1.1.1.1"));
            Assert.That(result[0].UserAgent, Is.EqualTo("agent-1"));
            Assert.That(result[0].IsCurrent, Is.True);
            Assert.That(result[0].IsActive, Is.True);
        }
    }

    [Test]
    public async Task ListSessionsForUserAsyncShouldIncludeInactiveWhenRequested()
    {
        var userId = Guid.NewGuid();
        var sessions = new List<AuthenticationSession>
        {
            CreateSession(expiresAt: _timeProvider.GetUtcNow().AddHours(1), userId: userId),
            CreateSession(expiresAt: _timeProvider.GetUtcNow().AddHours(-1), userId: userId)
        };

        _repositoryMock
            .Setup(r => r.ListSessionsForUserAsync(userId, false, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(sessions.AsReadOnly());

        var result = await _service.ListSessionsForUserAsync(userId, new ListAuthenticationSessionsRequest { ActiveOnly = false });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result, Has.Count.EqualTo(2));
            Assert.That(result[0].IsActive, Is.True);
            Assert.That(result[1].IsActive, Is.False);
        }
    }

    [Test]
    public void ListSessionsForUserAsyncShouldRejectEmptyUserId()
    {
        Assert.ThrowsAsync<ArgumentException>(() => _service.ListSessionsForUserAsync(Guid.Empty, new ListAuthenticationSessionsRequest()));
    }

    [Test]
    public void ListSessionsForUserAsyncShouldRejectNullRequest()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(() => _service.ListSessionsForUserAsync(Guid.NewGuid(), null!));
    }

    [Test]
    public async Task RevokeSessionForUserAsyncShouldPassCurrentTimeAndReason()
    {
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var now = _timeProvider.GetUtcNow();
        _repositoryMock
            .Setup(r => r.RevokeSessionByIdAsync(sessionId, userId, now, "user-initiated", It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var revoked = await _service.RevokeSessionForUserAsync(userId, new RevokeAuthenticationSessionRequest { SessionId = sessionId, Reason = "user-initiated" });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revoked, Is.True);
            _repositoryMock.Verify(r => r.RevokeSessionByIdAsync(sessionId, userId, now, "user-initiated", It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [Test]
    public void RevokeSessionForUserAsyncShouldRejectEmptyUserId()
    {
        Assert.ThrowsAsync<ArgumentException>(() => _service.RevokeSessionForUserAsync(Guid.Empty, new RevokeAuthenticationSessionRequest { SessionId = Guid.NewGuid() }));
    }

    [Test]
    public void RevokeSessionForUserAsyncShouldRejectNullRequest()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(() => _service.RevokeSessionForUserAsync(Guid.NewGuid(), null!));
    }

    [Test]
    public async Task RevokeOtherSessionsAsyncShouldPassCurrentTimeAndReason()
    {
        var userId = Guid.NewGuid();
        var currentSessionId = Guid.NewGuid();
        var now = _timeProvider.GetUtcNow();
        _repositoryMock
            .Setup(r => r.RevokeOtherSessionsForUserAsync(userId, currentSessionId, now, "security-cleanup", It.IsAny<CancellationToken>()))
            .ReturnsAsync(5);

        var revoked = await _service.RevokeOtherSessionsAsync(userId, new RevokeOtherAuthenticationSessionsRequest { CurrentSessionId = currentSessionId, Reason = "security-cleanup" });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revoked, Is.EqualTo(5));
            _repositoryMock.Verify(r => r.RevokeOtherSessionsForUserAsync(userId, currentSessionId, now, "security-cleanup", It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [Test]
    public void RevokeOtherSessionsAsyncShouldRejectEmptyUserId()
    {
        Assert.ThrowsAsync<ArgumentException>(() => _service.RevokeOtherSessionsAsync(Guid.Empty, new RevokeOtherAuthenticationSessionsRequest { CurrentSessionId = Guid.NewGuid() }));
    }

    [Test]
    public void RevokeOtherSessionsAsyncShouldRejectNullRequest()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(() => _service.RevokeOtherSessionsAsync(Guid.NewGuid(), null!));
    }

    [Test]
    public void RevokeOtherSessionsAsyncShouldRejectEmptyCurrentSessionId()
    {
        Assert.ThrowsAsync<ArgumentException>(() => _service.RevokeOtherSessionsAsync(Guid.NewGuid(), new RevokeOtherAuthenticationSessionsRequest { CurrentSessionId = Guid.Empty }));
    }

    [Test]
    public void ConstructorShouldThrowOnNullRepository()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationSessionService(null!, _tokenHasherMock.Object, new FixedSessionTokenGenerator("raw-token"), new NullTransactionProvider()));
    }

    [Test]
    public void ConstructorShouldThrowOnNullTokenHasher()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationSessionService(_repositoryMock.Object, null!, new FixedSessionTokenGenerator("raw-token"), new NullTransactionProvider()));
    }

    [Test]
    public void ConstructorShouldThrowOnNullTokenGenerator()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationSessionService(_repositoryMock.Object, _tokenHasherMock.Object, null!, new NullTransactionProvider()));
    }

    [Test]
    public void ConstructorShouldThrowOnNullTransactionProvider()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationSessionService(_repositoryMock.Object, _tokenHasherMock.Object, new FixedSessionTokenGenerator("raw-token"), null!));
    }

    [Test]
    public void ConstructorShouldAcceptValidOptions()
    {
        var service = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionOptions
            {
                DefaultLifetime = TimeSpan.FromDays(7),
                LastSeenUpdateThreshold = TimeSpan.Zero,
                TokenByteLength = 192,
                MaxIpAddressLength = 1,
                MaxUserAgentLength = 1,
                MaxMetadataLength = 1
            });

        Assert.That(service, Is.Not.Null);
    }

    [Test]
    public void ConstructorShouldRejectNonPositiveDefaultLifetime()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => _ = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionOptions { DefaultLifetime = TimeSpan.Zero }));
    }

    [Test]
    public void ConstructorShouldRejectNegativeLastSeenUpdateThreshold()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => _ = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionOptions { LastSeenUpdateThreshold = TimeSpan.FromTicks(-1) }));
    }

    [Test]
    public void ConstructorShouldRejectTooSmallTokenByteLength()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => _ = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionOptions { TokenByteLength = 31 }));
    }

    [Test]
    public void ConstructorShouldRejectTooLargeTokenByteLength()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => _ = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionOptions { TokenByteLength = 193 }));
    }

    [Test]
    public void ConstructorShouldRejectNonPositiveMaxIpAddressLength()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => _ = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionOptions { MaxIpAddressLength = 0 }));
    }

    [Test]
    public void ConstructorShouldRejectNonPositiveMaxUserAgentLength()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => _ = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionOptions { MaxUserAgentLength = 0 }));
    }

    [Test]
    public void ConstructorShouldRejectNonPositiveMaxMetadataLength()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => _ = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionOptions { MaxMetadataLength = 0 }));
    }

    private AuthenticationSession CreateSession(DateTimeOffset expiresAt, DateTimeOffset? lastSeenAt = null, Guid? userId = null)
    {
        return new AuthenticationSession
        {
            Id = Guid.NewGuid(),
            UserId = userId ?? Guid.NewGuid(),
            TokenHash = "hashed:raw-token",
            CreatedAt = _timeProvider.GetUtcNow().AddDays(-1),
            ExpiresAt = expiresAt,
            LastSeenAt = lastSeenAt
        };
    }

    private sealed class FixedSessionTokenGenerator(string token) : ISecureTokenGenerator
    {
        public string GenerateToken(int byteLength = ISecureTokenGenerator.DefaultByteLength)
        {
            return token;
        }
    }
}
