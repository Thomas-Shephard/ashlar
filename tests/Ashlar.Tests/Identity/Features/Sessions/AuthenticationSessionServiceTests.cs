using Ashlar.Auditing;
using Ashlar.Identity.Notifications;
using Ashlar.Security.Tokens;
using Ashlar.Testing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Identity.Features.Sessions;

internal sealed class AuthenticationSessionServiceTests
{
    private Mock<IAuthenticationSessionRepository> _repositoryMock;
    private Mock<ISecureTokenHasher> _tokenHasherMock;
    private Mock<IUserRepository> _userRepositoryMock;
    private FakeTimeProvider _timeProvider;
    private AuthenticationSessionService _service;

    [SetUp]
    public void SetUp()
    {
        _repositoryMock = new Mock<IAuthenticationSessionRepository>();
        _tokenHasherMock = new Mock<ISecureTokenHasher>();
        _userRepositoryMock = new Mock<IUserRepository>();
        _timeProvider = new FakeTimeProvider(new DateTimeOffset(2025, 1, 1, 12, 0, 0, TimeSpan.Zero));

        _tokenHasherMock.Setup(h => h.HashToken(It.IsAny<string>())).Returns<string>(token => $"hashed:{token}");
        _userRepositoryMock
            .Setup(r => r.GetUserByIdAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Guid userId, CancellationToken _) => new User { Id = userId, Email = "user@example.com" });

        _service = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(TimeProvider: _timeProvider, UserRepository: _userRepositoryMock.Object));
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
    public async Task CreateSessionAsyncShouldStorePrimaryAuthenticationMetadataOnly()
    {
        AuthenticationSession? storedSession = null;
        _repositoryMock
            .Setup(r => r.CreateSessionAsync(It.IsAny<AuthenticationSession>(), It.IsAny<CancellationToken>()))
            .Callback<AuthenticationSession, CancellationToken>((session, _) => storedSession = session)
            .Returns(Task.CompletedTask);
        var authenticatedAt = _timeProvider.GetUtcNow().AddMinutes(-1);
        var primaryProvider = AuthenticationProviderKey.EmailCode;

        await _service.CreateSessionAsync(
            Guid.NewGuid(),
            new CreateAuthenticationSessionRequest(
                AuthenticatedAt: authenticatedAt,
                PrimaryProvider: primaryProvider));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(storedSession?.AuthenticatedAt, Is.EqualTo(authenticatedAt));
            Assert.That(storedSession?.PrimaryProvider, Is.EqualTo(primaryProvider));
            Assert.That(storedSession?.AdditionalVerificationAt, Is.Null);
            Assert.That(storedSession?.AdditionalVerificationProvider, Is.Null);
            Assert.That(storedSession?.AdditionalVerificationFactor, Is.Null);
        }
    }

    [Test]
    public void CreateAuthenticationSessionRequestShouldNotExposeAdditionalVerificationInputs()
    {
        var properties = typeof(CreateAuthenticationSessionRequest).GetProperties().Select(property => property.Name).ToArray();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(properties, Does.Not.Contain("AdditionalVerificationAt"));
            Assert.That(properties, Does.Not.Contain("AdditionalVerificationProvider"));
            Assert.That(properties, Does.Not.Contain("AdditionalVerificationFactor"));
        }
    }

    [Test]
    public void AuthenticationSessionServiceInterfaceShouldNotExposeIdOnlyRevocation()
    {
        var idOnlyRevocation = typeof(IAuthenticationSessionService)
            .GetMethods()
            .Where(method => method.Name == "RevokeSessionAsync")
            .SingleOrDefault(method =>
            {
                var parameters = method.GetParameters();
                return parameters.Length > 0 && parameters[0].ParameterType == typeof(Guid);
            });

        Assert.That(idOnlyRevocation, Is.Null);
    }

    [Test]
    public async Task CreateSessionAsyncShouldOmitOptionalSessionContextWhenDisabled()
    {
        var service = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(_userRepositoryMock.Object, Options: new AuthenticationSessionOptions
            {
                StoreIpAddress = false,
                StoreUserAgent = false,
                StoreMetadata = false
            }, TimeProvider: _timeProvider));

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
    public void CreateSessionAsyncShouldRejectUnconfiguredPrimaryProvider()
    {
        var request = new CreateAuthenticationSessionRequest(
            PrimaryProvider: new AuthenticationProviderKey((ProviderType)ProviderType.StorageFallbackValue, "unknown"));

        Assert.ThrowsAsync<ArgumentException>(() => _service.CreateSessionAsync(Guid.NewGuid(), request));
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
    public async Task CreateSessionAsyncShouldSucceedForTenantUserWithMatchingTenant()
    {
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        _userRepositoryMock
            .Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, Email = "tenant@example.com", TenantId = tenantId });

        var result = await _service.CreateSessionAsync(userId, new CreateAuthenticationSessionRequest(TenantId: tenantId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Session.TenantId, Is.EqualTo(tenantId));
            _repositoryMock.Verify(r => r.CreateSessionAsync(It.Is<AuthenticationSession>(session => session.UserId == userId && session.TenantId == tenantId), It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [Test]
    public async Task CreateSessionAsyncShouldSucceedForGlobalUserWithNullTenant()
    {
        var userId = Guid.NewGuid();
        _userRepositoryMock
            .Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, Email = "global@example.com", TenantId = null });

        var result = await _service.CreateSessionAsync(userId, new CreateAuthenticationSessionRequest(TenantId: null));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Session.TenantId, Is.Null);
            _repositoryMock.Verify(r => r.CreateSessionAsync(It.Is<AuthenticationSession>(session => session.UserId == userId && session.TenantId == null), It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [TestCase(true)]
    [TestCase(false)]
    public async Task CreateSessionAsyncShouldRejectTenantMismatchesBeforeRepositoryCreation(bool requestedTenantIsNull)
    {
        var userId = Guid.NewGuid();
        var userTenantId = Guid.NewGuid();
        var requestedTenantId = requestedTenantIsNull ? (Guid?)null : Guid.NewGuid();
        _userRepositoryMock
            .Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, Email = "tenant@example.com", TenantId = userTenantId });

        var exception = Assert.ThrowsAsync<AshlarOperationException>(async () =>
            await _service.CreateSessionAsync(userId, new CreateAuthenticationSessionRequest(TenantId: requestedTenantId)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exception!.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            _repositoryMock.Verify(r => r.CreateSessionAsync(It.IsAny<AuthenticationSession>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task CreateSessionAsyncShouldRejectTenantSessionForGlobalUserBeforeRepositoryCreation()
    {
        var userId = Guid.NewGuid();
        _userRepositoryMock
            .Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, Email = "global@example.com", TenantId = null });

        var exception = Assert.ThrowsAsync<AshlarOperationException>(async () =>
            await _service.CreateSessionAsync(userId, new CreateAuthenticationSessionRequest(TenantId: Guid.NewGuid())));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exception!.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            _repositoryMock.Verify(r => r.CreateSessionAsync(It.IsAny<AuthenticationSession>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task CreateSessionAsyncShouldNotGenerateTokenWhenTenantMismatches()
    {
        var tokenGenerator = new CountingSessionTokenGenerator();
        var tokenHasher = new Mock<ISecureTokenHasher>();
        tokenHasher.Setup(h => h.HashToken(It.IsAny<string>())).Returns("hash");
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        _userRepositoryMock
            .Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, Email = "tenant@example.com", TenantId = tenantId });
        var service = new AuthenticationSessionService(
            _repositoryMock.Object,
            tokenHasher.Object,
            tokenGenerator,
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(TimeProvider: _timeProvider, UserRepository: _userRepositoryMock.Object));

        var exception = Assert.ThrowsAsync<AshlarOperationException>(async () =>
            await service.CreateSessionAsync(userId, new CreateAuthenticationSessionRequest(TenantId: Guid.NewGuid())));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exception?.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            Assert.That(tokenGenerator.Count, Is.Zero);
            tokenHasher.Verify(h => h.HashToken(It.IsAny<string>()), Times.Never);
        }
    }

    [TestCase(UserAccountState.Disabled, SecurityEventFailureReasons.UserDisabled)]
    [TestCase(UserAccountState.Locked, SecurityEventFailureReasons.UserLocked)]
    [TestCase(UserAccountState.Suspended, SecurityEventFailureReasons.UserSuspended)]
    public async Task CreateSessionAsyncShouldRejectUnavailableUsersBeforeTokenGeneration(UserAccountState accountState, string failureReason)
    {
        var tokenGenerator = new CountingSessionTokenGenerator();
        var tokenHasher = new Mock<ISecureTokenHasher>();
        tokenHasher.Setup(h => h.HashToken(It.IsAny<string>())).Returns("hash");
        var sink = new RecordingSecurityEventSink();
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        _userRepositoryMock
            .Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, Email = "user@example.com", AccountState = accountState, TenantId = tenantId });
        var service = new AuthenticationSessionService(
            _repositoryMock.Object,
            tokenHasher.Object,
            tokenGenerator,
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(TimeProvider: _timeProvider, SecurityEventSink: sink, UserRepository: _userRepositoryMock.Object));

        var exception = Assert.ThrowsAsync<AshlarOperationException>(async () =>
            await service.CreateSessionAsync(userId, new CreateAuthenticationSessionRequest(
                TenantId: tenantId,
                IpAddress: "203.0.113.25",
                UserAgent: "blocked-user-agent",
                CorrelationId: "blocked-user-correlation")));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exception?.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFoundOrUnavailable));
            Assert.That(tokenGenerator.Count, Is.Zero);
            tokenHasher.Verify(h => h.HashToken(It.IsAny<string>()), Times.Never);
            _repositoryMock.Verify(r => r.CreateSessionAsync(It.IsAny<AuthenticationSession>(), It.IsAny<CancellationToken>()), Times.Never);

            var securityEvent = sink.Events.Single();
            Assert.That(securityEvent.UserId, Is.EqualTo(userId));
            Assert.That(securityEvent.TenantId, Is.EqualTo(tenantId));
            Assert.That(securityEvent.IpAddress, Is.EqualTo("203.0.113.25"));
            Assert.That(securityEvent.UserAgent, Is.EqualTo("blocked-user-agent"));
            Assert.That(securityEvent.CorrelationId, Is.EqualTo("blocked-user-correlation"));
            Assert.That(securityEvent.FailureReason, Is.EqualTo(failureReason));
        }
    }

    [Test]
    public async Task CreateSessionAsyncShouldAuditTenantMismatchWithoutLeakingOtherTenantDetails()
    {
        var sink = new RecordingSecurityEventSink();
        var userId = Guid.NewGuid();
        var userTenantId = Guid.NewGuid();
        var requestedTenantId = Guid.NewGuid();
        _userRepositoryMock
            .Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, Email = "tenant@example.com", TenantId = userTenantId });
        var service = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(TimeProvider: _timeProvider, SecurityEventSink: sink, UserRepository: _userRepositoryMock.Object));

        Assert.ThrowsAsync<AshlarOperationException>(async () =>
            await service.CreateSessionAsync(userId, new CreateAuthenticationSessionRequest(TenantId: requestedTenantId)));

        var securityEvent = sink.Events.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(securityEvent.UserId, Is.EqualTo(userId));
            Assert.That(securityEvent.TenantId, Is.EqualTo(requestedTenantId));
            Assert.That(securityEvent.FailureReason, Is.EqualTo(AshlarFailureCodes.TenantMismatchValue));
            Assert.That(securityEvent.SessionId, Is.Null);
            Assert.That(securityEvent.Properties, Is.Null);
        }
    }

    [Test]
    public void ConstructorShouldRequireUserRepositoryForTenantValidation()
    {
        Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(null!, TimeProvider: _timeProvider)));
    }

    [Test]
    public async Task CreateSessionAsyncShouldRejectMissingUserBeforeRepositoryCreation()
    {
        var userId = Guid.NewGuid();
        var sink = new RecordingSecurityEventSink();
        _userRepositoryMock
            .Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((IUser?)null);
        var service = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(TimeProvider: _timeProvider, SecurityEventSink: sink, UserRepository: _userRepositoryMock.Object));

        var tenantId = Guid.NewGuid();
        var exception = Assert.ThrowsAsync<AshlarOperationException>(async () =>
            await service.CreateSessionAsync(userId, new CreateAuthenticationSessionRequest(
                TenantId: tenantId,
                IpAddress: "203.0.113.24",
                UserAgent: "missing-user-agent",
                CorrelationId: "missing-user-correlation")));

        using (Assert.EnterMultipleScope())
        {
            var securityEvent = sink.Events.Single();
            Assert.That(exception!.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(securityEvent.TenantId, Is.EqualTo(tenantId));
            Assert.That(securityEvent.IpAddress, Is.EqualTo("203.0.113.24"));
            Assert.That(securityEvent.UserAgent, Is.EqualTo("missing-user-agent"));
            Assert.That(securityEvent.CorrelationId, Is.EqualTo("missing-user-correlation"));
            Assert.That(securityEvent.FailureReason, Is.EqualTo(AshlarFailureCodes.UserNotFoundValue));
            _repositoryMock.Verify(r => r.CreateSessionAsync(It.IsAny<AuthenticationSession>(), It.IsAny<CancellationToken>()), Times.Never);
        }
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
            Assert.That(result.Status, Is.EqualTo(AuthenticationSessionValidationStatus.Succeeded));
            Assert.That(result.Session, Is.EqualTo(session));
            Assert.That(result.UserId, Is.EqualTo(session.UserId));
        }
    }

    [TestCase(null)]
    [TestCase(" ")]
    public async Task ValidateSessionAsyncShouldFailForMissingToken(string? token)
    {
        var result = await _service.ValidateSessionAsync(token);

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

    [TestCase(UserAccountState.Disabled, SecurityEventFailureReasons.UserDisabled)]
    [TestCase(UserAccountState.Locked, SecurityEventFailureReasons.UserLocked)]
    [TestCase(UserAccountState.Suspended, SecurityEventFailureReasons.UserSuspended)]
    public async Task ValidateSessionAsyncShouldFailForUnavailableUser(UserAccountState accountState, string failureReason)
    {
        var sink = new RecordingSecurityEventSink();
        var now = _timeProvider.GetUtcNow();
        var session = CreateSession(expiresAt: now.AddHours(1), userId: Guid.NewGuid());
        _repositoryMock
            .Setup(r => r.GetSessionByTokenHashAsync("hashed:raw-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(session);
        _userRepositoryMock
            .Setup(r => r.GetUserByIdAsync(session.UserId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = session.UserId, Email = "user@example.com", AccountState = accountState });
        var service = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(TimeProvider: _timeProvider, SecurityEventSink: sink, UserRepository: _userRepositoryMock.Object));

        var result = await service.ValidateSessionAsync("raw-token");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.Status, Is.EqualTo(AuthenticationSessionValidationStatus.Failed));
            Assert.That(result.Session, Is.EqualTo(session));
            Assert.That(result.UserId, Is.EqualTo(session.UserId));
            Assert.That(sink.Events.Single().FailureReason, Is.EqualTo(failureReason));
        }

        _repositoryMock.Verify(r => r.UpdateSessionLastSeenAsync(It.IsAny<Guid>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task ValidateSessionAsyncShouldFailForMissingUser()
    {
        var sink = new RecordingSecurityEventSink();
        var session = CreateSession(expiresAt: _timeProvider.GetUtcNow().AddHours(1), userId: Guid.NewGuid());
        _repositoryMock
            .Setup(r => r.GetSessionByTokenHashAsync("hashed:raw-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(session);
        _userRepositoryMock
            .Setup(r => r.GetUserByIdAsync(session.UserId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((IUser?)null);
        var service = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(TimeProvider: _timeProvider, SecurityEventSink: sink, UserRepository: _userRepositoryMock.Object));

        var result = await service.ValidateSessionAsync("raw-token");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.Status, Is.EqualTo(AuthenticationSessionValidationStatus.Failed));
            Assert.That(result.Session, Is.EqualTo(session));
            Assert.That(result.UserId, Is.EqualTo(session.UserId));
            Assert.That(sink.Events.Single().FailureReason, Is.EqualTo(AshlarFailureCodes.UserNotFoundValue));
        }

        _repositoryMock.Verify(r => r.UpdateSessionLastSeenAsync(It.IsAny<Guid>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Never);
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
        var logger = new RecordingLogger<AuthenticationSessionService>();
        var service = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(TimeProvider: _timeProvider, UserRepository: _userRepositoryMock.Object),
            logger);

        _repositoryMock
            .Setup(r => r.GetSessionByTokenHashAsync("hashed:raw-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(session);
        _repositoryMock
            .Setup(r => r.UpdateSessionLastSeenAsync(session.Id, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("store unavailable"));

        var result = await service.ValidateSessionAsync("raw-token");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Status, Is.EqualTo(AuthenticationSessionValidationStatus.Succeeded));
            Assert.That(session.LastSeenAt, Is.Null);
        }

        Assert.That(logger.Entries, Has.Some.Matches<LogEntry>(entry =>
            entry.Level == LogLevel.Warning
            && entry.Message.Contains("last-seen update failed", StringComparison.Ordinal)));
    }

    [Test]
    public async Task MarkStepUpVerifiedAsyncShouldUpdateActiveUserSession()
    {
        var userId = Guid.NewGuid();
        var session = CreateSession(expiresAt: _timeProvider.GetUtcNow().AddHours(1), userId: userId);
        var provider = new AuthenticationProviderKey(ProviderType.Mfa, "totp");
        var now = _timeProvider.GetUtcNow();
        session.AdditionalVerificationAt = now;
        session.AdditionalVerificationProvider = provider;
        session.AdditionalVerificationFactor = "totp";
        _repositoryMock
            .Setup(r => r.MarkStepUpVerifiedAsync(session.Id, userId, now, provider, "totp", It.IsAny<CancellationToken>()))
            .ReturnsAsync(session);

        var result = await _service.MarkStepUpVerifiedAsync(userId, new MarkSessionStepUpVerifiedRequest
        {
            SessionId = session.Id,
            VerifiedProvider = provider,
            VerifiedFactor = " totp "
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value, Is.EqualTo(session));
        }
    }

    [Test]
    public async Task MarkStepUpVerifiedAsyncShouldFailWhenRepositoryDoesNotUpdate()
    {
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var provider = new AuthenticationProviderKey(ProviderType.Mfa, "totp");
        _repositoryMock
            .Setup(r => r.MarkStepUpVerifiedAsync(sessionId, userId, _timeProvider.GetUtcNow(), provider, "totp", It.IsAny<CancellationToken>()))
            .ReturnsAsync((AuthenticationSession?)null);

        var result = await _service.MarkStepUpVerifiedAsync(userId, new MarkSessionStepUpVerifiedRequest
        {
            SessionId = sessionId,
            VerifiedProvider = provider,
            VerifiedFactor = "totp"
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.SessionNotFoundOrInactive));
        }
    }

    [TestCase(UserAccountState.Disabled, SecurityEventFailureReasons.UserDisabled)]
    [TestCase(UserAccountState.Locked, SecurityEventFailureReasons.UserLocked)]
    [TestCase(UserAccountState.Suspended, SecurityEventFailureReasons.UserSuspended)]
    public async Task MarkStepUpVerifiedAsyncShouldRejectUnavailableUsersBeforeRepositoryUpdate(UserAccountState accountState, string failureReason)
    {
        var sink = new RecordingSecurityEventSink();
        var service = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(TimeProvider: _timeProvider, SecurityEventSink: sink, UserRepository: _userRepositoryMock.Object));
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var provider = new AuthenticationProviderKey(ProviderType.Mfa, "totp");
        _userRepositoryMock
            .Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, Email = "user@example.com", AccountState = accountState, TenantId = tenantId });

        var result = await service.MarkStepUpVerifiedAsync(userId, new MarkSessionStepUpVerifiedRequest
        {
            SessionId = sessionId,
            VerifiedProvider = provider,
            VerifiedFactor = "totp",
            Tenant = new TenantContext(tenantId)
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFoundOrUnavailable));
            Assert.That(sink.Events.Single().FailureReason, Is.EqualTo(failureReason));
            Assert.That(sink.Events.Single().TenantId, Is.EqualTo(tenantId));
            Assert.That(sink.Events.Single().Properties?["factor"], Is.EqualTo("totp"));
            _repositoryMock.Verify(r => r.MarkStepUpVerifiedAsync(It.IsAny<Guid>(), It.IsAny<Guid>(), It.IsAny<DateTimeOffset>(), It.IsAny<AuthenticationProviderKey>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task MarkStepUpVerifiedAsyncShouldAuditUnavailableGlobalUserWithoutTenant()
    {
        var sink = new RecordingSecurityEventSink();
        var service = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(TimeProvider: _timeProvider, SecurityEventSink: sink, UserRepository: _userRepositoryMock.Object));
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var provider = new AuthenticationProviderKey(ProviderType.Mfa, "totp");
        _userRepositoryMock
            .Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, Email = "user@example.com", AccountState = UserAccountState.Disabled });

        var result = await service.MarkStepUpVerifiedAsync(userId, new MarkSessionStepUpVerifiedRequest
        {
            SessionId = sessionId,
            VerifiedProvider = provider,
            VerifiedFactor = "totp"
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(sink.Events.Single().TenantId, Is.Null);
            Assert.That(sink.Events.Single().FailureReason, Is.EqualTo(SecurityEventFailureReasons.UserDisabled));
        }
    }

    [TestCase(true)]
    [TestCase(false)]
    public async Task MarkStepUpVerifiedAsyncShouldRejectTenantMismatchBeforeRepositoryUpdate(bool requestedTenantIsNull)
    {
        var userId = Guid.NewGuid();
        var userTenantId = Guid.NewGuid();
        var requestedTenantId = requestedTenantIsNull ? (Guid?)null : Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var provider = new AuthenticationProviderKey(ProviderType.Mfa, "totp");
        _userRepositoryMock
            .Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, Email = "tenant@example.com", TenantId = userTenantId });

        var result = await _service.MarkStepUpVerifiedAsync(userId, new MarkSessionStepUpVerifiedRequest
        {
            SessionId = sessionId,
            VerifiedProvider = provider,
            VerifiedFactor = "totp",
            Tenant = requestedTenantIsNull ? null : new TenantContext(requestedTenantId)
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            _repositoryMock.Verify(r => r.MarkStepUpVerifiedAsync(It.IsAny<Guid>(), It.IsAny<Guid>(), It.IsAny<DateTimeOffset>(), It.IsAny<AuthenticationProviderKey>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task MarkStepUpVerifiedAsyncShouldRejectTenantContextForGlobalUserBeforeRepositoryUpdate()
    {
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var provider = new AuthenticationProviderKey(ProviderType.Mfa, "totp");
        _userRepositoryMock
            .Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, Email = "global@example.com" });

        var result = await _service.MarkStepUpVerifiedAsync(userId, new MarkSessionStepUpVerifiedRequest
        {
            SessionId = sessionId,
            VerifiedProvider = provider,
            VerifiedFactor = "totp",
            Tenant = new TenantContext(Guid.NewGuid())
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            _repositoryMock.Verify(r => r.MarkStepUpVerifiedAsync(It.IsAny<Guid>(), It.IsAny<Guid>(), It.IsAny<DateTimeOffset>(), It.IsAny<AuthenticationProviderKey>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task MarkStepUpVerifiedAsyncShouldAuditTenantMismatchSafely()
    {
        var sink = new RecordingSecurityEventSink();
        var service = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(TimeProvider: _timeProvider, SecurityEventSink: sink, UserRepository: _userRepositoryMock.Object));
        var userId = Guid.NewGuid();
        var requestedTenantId = Guid.NewGuid();
        var provider = new AuthenticationProviderKey(ProviderType.Mfa, "totp");
        _userRepositoryMock
            .Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, Email = "tenant@example.com", TenantId = Guid.NewGuid() });

        await service.MarkStepUpVerifiedAsync(userId, new MarkSessionStepUpVerifiedRequest
        {
            SessionId = Guid.NewGuid(),
            VerifiedProvider = provider,
            VerifiedFactor = "totp",
            Tenant = new TenantContext(requestedTenantId),
            Audit = new AuditContext(ActorUserId: Guid.NewGuid(), IpAddress: "203.0.113.44")
        });

        var securityEvent = sink.Events.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(securityEvent.FailureReason, Is.EqualTo(AshlarFailureCodes.TenantMismatchValue));
            Assert.That(securityEvent.TenantId, Is.EqualTo(requestedTenantId));
            Assert.That(securityEvent.Properties?["factor"], Is.EqualTo("totp"));
        }
    }

    [Test]
    public async Task MarkStepUpVerifiedAsyncShouldRecordSecurityEvent()
    {
        var securityEvents = new Mock<ISecurityEventSink>();
        var service = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(TimeProvider: _timeProvider, SecurityEventSink: securityEvents.Object, UserRepository: _userRepositoryMock.Object));
        var userId = Guid.NewGuid();
        var session = CreateSession(expiresAt: _timeProvider.GetUtcNow().AddHours(1), userId: userId);
        session.AdditionalVerificationAt = _timeProvider.GetUtcNow();
        session.AdditionalVerificationProvider = AuthenticationProviderKey.Passkey;
        session.AdditionalVerificationFactor = "passkey";
        _repositoryMock
            .Setup(r => r.MarkStepUpVerifiedAsync(session.Id, userId, _timeProvider.GetUtcNow(), AuthenticationProviderKey.Passkey, "passkey", It.IsAny<CancellationToken>()))
            .ReturnsAsync(session);

        await service.MarkStepUpVerifiedAsync(userId, new MarkSessionStepUpVerifiedRequest
        {
            SessionId = session.Id,
            VerifiedProvider = AuthenticationProviderKey.Passkey,
            VerifiedFactor = "passkey",
            Audit = new AuditContext(ActorUserId: userId, IpAddress: "203.0.113.1")
        });

        securityEvents.Verify(x => x.RecordAsync(It.Is<AshlarSecurityEvent>(e =>
            e.EventType == AshlarSecurityEventTypes.SessionStepUpVerified &&
            e.Outcome == SecurityEventOutcomes.Success &&
            e.UserId == userId &&
            e.SessionId == session.Id &&
            e.Provider == AuthenticationProviderKey.Passkey &&
            e.Properties != null &&
            e.Properties["factor"] == "passkey"), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public void MarkStepUpVerifiedAsyncShouldRejectInvalidInput()
    {
        var provider = new AuthenticationProviderKey(ProviderType.Mfa, "totp");

        Assert.ThrowsAsync<ArgumentException>(() => _service.MarkStepUpVerifiedAsync(Guid.Empty, new MarkSessionStepUpVerifiedRequest { SessionId = Guid.NewGuid(), VerifiedProvider = provider, VerifiedFactor = "totp" }));
        Assert.ThrowsAsync<ArgumentException>(() => _service.MarkStepUpVerifiedAsync(Guid.NewGuid(), new MarkSessionStepUpVerifiedRequest { SessionId = Guid.Empty, VerifiedProvider = provider, VerifiedFactor = "totp" }));
        Assert.ThrowsAsync<ArgumentException>(() => _service.MarkStepUpVerifiedAsync(Guid.NewGuid(), new MarkSessionStepUpVerifiedRequest { SessionId = Guid.NewGuid(), VerifiedProvider = default, VerifiedFactor = "totp" }));
        Assert.ThrowsAsync<ArgumentException>(() => _service.MarkStepUpVerifiedAsync(Guid.NewGuid(), new MarkSessionStepUpVerifiedRequest { SessionId = Guid.NewGuid(), VerifiedProvider = new AuthenticationProviderKey((ProviderType)ProviderType.StorageFallbackValue, "unknown"), VerifiedFactor = "totp" }));
        Assert.ThrowsAsync<ArgumentException>(() => _service.MarkStepUpVerifiedAsync(Guid.NewGuid(), new MarkSessionStepUpVerifiedRequest { SessionId = Guid.NewGuid(), VerifiedProvider = provider, VerifiedFactor = " " }));
        Assert.ThrowsAsync<ArgumentException>(() => _service.MarkStepUpVerifiedAsync(Guid.NewGuid(), new MarkSessionStepUpVerifiedRequest { SessionId = Guid.NewGuid(), VerifiedProvider = provider, VerifiedFactor = new string('x', 129) }));
    }

    [Test]
    public void ConstructorShouldAcceptRequiredUserRepositoryDependency()
    {
        var service = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(UserRepository: _userRepositoryMock.Object));

        Assert.That(service, Is.Not.Null);
    }

    [Test]
    public async Task RevokeSessionsForUserAsyncShouldPassCurrentTimeAndReason()
    {
        var userId = Guid.NewGuid();
        var now = _timeProvider.GetUtcNow();
        _repositoryMock
            .Setup(r => r.RevokeSessionsForUserAsync(userId, now, "password-reset", null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(3);

        var revoked = await _service.RevokeSessionsForUserAsync(userId, "password-reset");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revoked, Is.EqualTo(3));
            _repositoryMock.Verify(r => r.RevokeSessionsForUserAsync(userId, now, "password-reset", null, It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [Test]
    public void RevokeSessionsForUserAsyncShouldRejectEmptyUserId()
    {
        Assert.ThrowsAsync<ArgumentException>(() => _service.RevokeSessionsForUserAsync(Guid.Empty));
    }

    [Test]
    public async Task RevokeSessionsForUserAsyncShouldNotifyAllSessionsRevoked()
    {
        var userId = Guid.NewGuid();
        var now = _timeProvider.GetUtcNow();
        var user = new User { Id = userId, Email = "user@example.com" };
        var userRepository = new Mock<IUserRepository>();
        var notificationService = new Mock<ISecurityNotificationService>();
        var service = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(
                TimeProvider: _timeProvider,
                UserRepository: userRepository.Object,
                NotificationService: notificationService.Object));

        _repositoryMock
            .Setup(r => r.RevokeSessionsForUserAsync(userId, now, "password-reset", It.Is<TenantContext?>(t => t != null), It.IsAny<CancellationToken>()))
            .ReturnsAsync(2);
        userRepository
            .Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        await service.RevokeSessionsForUserAsync(userId, "password-reset", new TenantContext(Guid.NewGuid()));

        notificationService.Verify(n => n.NotifyAsync(It.Is<SecurityNotification>(notification =>
            notification.Type == SecurityNotificationType.AllSessionsRevoked &&
            notification.RecipientEmail == user.Email &&
            notification.OccurredAt == now &&
            notification.Metadata != null &&
            notification.Metadata["count"] == "2" &&
            notification.Metadata["reason"] == "password-reset"), It.IsAny<CancellationToken>()), Times.Once);
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
            .Setup(r => r.RevokeSessionByIdAsync(sessionId, userId, now, "user-initiated", null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var revoked = await _service.RevokeSessionForUserAsync(userId, new RevokeAuthenticationSessionRequest { SessionId = sessionId, Reason = "user-initiated" });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revoked, Is.True);
            _repositoryMock.Verify(r => r.RevokeSessionByIdAsync(sessionId, userId, now, "user-initiated", null, It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [Test]
    public async Task RevokeSessionForUserAsyncShouldNotifyWithAuditContext()
    {
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var secondSessionId = Guid.NewGuid();
        var now = _timeProvider.GetUtcNow();
        var user = new User { Id = userId, Email = "user@example.com" };
        var userRepository = new Mock<IUserRepository>();
        var notificationService = new Mock<ISecurityNotificationService>();
        var service = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(
                TimeProvider: _timeProvider,
                UserRepository: userRepository.Object,
                NotificationService: notificationService.Object));
        var audit = new AuditContext(ActorUserId: userId, IpAddress: "203.0.113.60", UserAgent: "session-agent", CorrelationId: "session-correlation");

        _repositoryMock
            .Setup(r => r.RevokeSessionByIdAsync(sessionId, userId, now, null, It.Is<TenantContext?>(t => t != null), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
        _repositoryMock
            .Setup(r => r.RevokeSessionByIdAsync(secondSessionId, userId, now, null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
        userRepository
            .Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var revoked = await service.RevokeSessionForUserAsync(userId, new RevokeAuthenticationSessionRequest { SessionId = sessionId, Tenant = new TenantContext(Guid.NewGuid()), Audit = audit });
        var secondRevoked = await service.RevokeSessionForUserAsync(userId, new RevokeAuthenticationSessionRequest { SessionId = secondSessionId, Audit = audit });

        Assert.That(revoked && secondRevoked, Is.True);
        notificationService.Verify(n => n.NotifyAsync(It.Is<SecurityNotification>(notification =>
            notification.Type == SecurityNotificationType.SessionRevoked &&
            notification.IpAddress == "203.0.113.60" &&
            notification.UserAgent == "session-agent"), It.IsAny<CancellationToken>()), Times.Exactly(2));
    }

    [Test]
    public async Task RevokeSessionForUserAsyncShouldNotifyWithoutAuditContext()
    {
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var now = _timeProvider.GetUtcNow();
        var userRepository = new Mock<IUserRepository>();
        var notificationService = new Mock<ISecurityNotificationService>();
        var service = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(
                TimeProvider: _timeProvider,
                UserRepository: userRepository.Object,
                NotificationService: notificationService.Object));

        _repositoryMock
            .Setup(r => r.RevokeSessionByIdAsync(sessionId, userId, now, null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
        userRepository
            .Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, Email = "user@example.com" });

        var revoked = await service.RevokeSessionForUserAsync(userId, new RevokeAuthenticationSessionRequest { SessionId = sessionId });

        Assert.That(revoked, Is.True);
        notificationService.Verify(n => n.NotifyAsync(It.Is<SecurityNotification>(notification =>
            notification.Type == SecurityNotificationType.SessionRevoked &&
            notification.IpAddress == null &&
            notification.UserAgent == null), It.IsAny<CancellationToken>()), Times.Once);
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
    public void RevokeSessionForUserAsyncShouldRejectEmptySessionId()
    {
        Assert.ThrowsAsync<ArgumentException>(() => _service.RevokeSessionForUserAsync(Guid.NewGuid(), new RevokeAuthenticationSessionRequest { SessionId = Guid.Empty }));
    }

    [Test]
    public void RevokeSessionForUserAsyncShouldRejectOversizedReason()
    {
        Assert.ThrowsAsync<ArgumentException>(() => _service.RevokeSessionForUserAsync(
            Guid.NewGuid(),
            new RevokeAuthenticationSessionRequest { SessionId = Guid.NewGuid(), Reason = new string('x', 513) }));
    }

    [Test]
    public async Task RevokeOtherSessionsAsyncShouldPassCurrentTimeAndReason()
    {
        var userId = Guid.NewGuid();
        var currentSessionId = Guid.NewGuid();
        var now = _timeProvider.GetUtcNow();
        _repositoryMock
            .Setup(r => r.RevokeOtherSessionsForUserAsync(userId, currentSessionId, now, "security-cleanup", null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(5);

        var revoked = await _service.RevokeOtherSessionsAsync(userId, new RevokeOtherAuthenticationSessionsRequest { CurrentSessionId = currentSessionId, Reason = "security-cleanup" });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revoked, Is.EqualTo(5));
            _repositoryMock.Verify(r => r.RevokeOtherSessionsForUserAsync(userId, currentSessionId, now, "security-cleanup", null, It.IsAny<CancellationToken>()), Times.Once);
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
    public void RevokeOtherSessionsAsyncShouldRejectOversizedReason()
    {
        Assert.ThrowsAsync<ArgumentException>(() => _service.RevokeOtherSessionsAsync(
            Guid.NewGuid(),
            new RevokeOtherAuthenticationSessionsRequest { CurrentSessionId = Guid.NewGuid(), Reason = new string('x', 513) }));
    }

    [Test]
    public void ConstructorShouldThrowOnNullRepository()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationSessionService(null!, _tokenHasherMock.Object, new FixedSessionTokenGenerator("raw-token"), new NullTransactionProvider(), new AuthenticationSessionServiceDependencies(UserRepository: _userRepositoryMock.Object)));
    }

    [Test]
    public void ConstructorShouldThrowOnNullTokenHasher()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationSessionService(_repositoryMock.Object, null!, new FixedSessionTokenGenerator("raw-token"), new NullTransactionProvider(), new AuthenticationSessionServiceDependencies(UserRepository: _userRepositoryMock.Object)));
    }

    [Test]
    public void ConstructorShouldThrowOnNullTokenGenerator()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationSessionService(_repositoryMock.Object, _tokenHasherMock.Object, null!, new NullTransactionProvider(), new AuthenticationSessionServiceDependencies(UserRepository: _userRepositoryMock.Object)));
    }

    [Test]
    public void ConstructorShouldThrowOnNullTransactionProvider()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationSessionService(_repositoryMock.Object, _tokenHasherMock.Object, new FixedSessionTokenGenerator("raw-token"), null!, new AuthenticationSessionServiceDependencies(UserRepository: _userRepositoryMock.Object)));
    }

    [Test]
    public void ConstructorShouldAcceptValidOptions()
    {
        var service = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(_userRepositoryMock.Object, Options: new AuthenticationSessionOptions
            {
                DefaultLifetime = TimeSpan.FromDays(7),
                LastSeenUpdateThreshold = TimeSpan.Zero,
                TokenByteLength = 192,
                MaxIpAddressLength = 1,
                MaxUserAgentLength = 1,
                MaxMetadataLength = 1
            }));

        Assert.That(service, Is.Not.Null);
    }

    [Test]
    public void ConstructorShouldPreferDependencyLoggerWhenLoggerArgumentIsNull()
    {
        var logger = new RecordingLogger<AuthenticationSessionService>();

        var service = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(UserRepository: _userRepositoryMock.Object, Logger: logger),
            logger: null);

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
            new AuthenticationSessionServiceDependencies(_userRepositoryMock.Object, Options: new AuthenticationSessionOptions { DefaultLifetime = TimeSpan.Zero })));
    }

    [Test]
    public void ConstructorShouldRejectNegativeLastSeenUpdateThreshold()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => _ = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(_userRepositoryMock.Object, Options: new AuthenticationSessionOptions { LastSeenUpdateThreshold = TimeSpan.FromTicks(-1) })));
    }

    [Test]
    public void ConstructorShouldRejectTooSmallTokenByteLength()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => _ = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(_userRepositoryMock.Object, Options: new AuthenticationSessionOptions { TokenByteLength = 31 })));
    }

    [Test]
    public void ConstructorShouldRejectTooLargeTokenByteLength()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => _ = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(_userRepositoryMock.Object, Options: new AuthenticationSessionOptions { TokenByteLength = 193 })));
    }

    [Test]
    public void ConstructorShouldRejectNonPositiveMaxIpAddressLength()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => _ = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(_userRepositoryMock.Object, Options: new AuthenticationSessionOptions { MaxIpAddressLength = 0 })));
    }

    [Test]
    public void ConstructorShouldRejectNonPositiveMaxUserAgentLength()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => _ = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(_userRepositoryMock.Object, Options: new AuthenticationSessionOptions { MaxUserAgentLength = 0 })));
    }

    [Test]
    public void ConstructorShouldRejectNonPositiveMaxMetadataLength()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => _ = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(_userRepositoryMock.Object, Options: new AuthenticationSessionOptions { MaxMetadataLength = 0 })));
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

    private sealed class CountingSessionTokenGenerator : ISecureTokenGenerator
    {
        public int Count { get; private set; }

        public string GenerateToken(int byteLength = ISecureTokenGenerator.DefaultByteLength)
        {
            Count++;
            return "raw-token";
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
}
