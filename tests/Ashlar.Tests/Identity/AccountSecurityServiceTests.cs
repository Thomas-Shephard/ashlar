using Ashlar.Auditing;
using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.Models.Totp;
using Ashlar.Identity.Notifications;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Identity;

internal sealed class AccountSecurityServiceTests
{
    private readonly Guid _userId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private FakeTimeProvider _timeProvider;
    private InMemoryIdentityRepository _identityRepository;
    private InMemorySessionRepository _sessionRepository;
    private RecordingSecurityEventSink _events;
    private AccountSecurityService _service;

    [SetUp]
    public void SetUp()
    {
        _timeProvider = new FakeTimeProvider(new DateTimeOffset(2026, 5, 17, 12, 0, 0, TimeSpan.Zero));
        _identityRepository = new InMemoryIdentityRepository();
        _sessionRepository = new InMemorySessionRepository();
        _events = new RecordingSecurityEventSink();
        var sessionService = new AuthenticationSessionService(
            _sessionRepository,
            Mock.Of<Ashlar.Security.Tokens.ISecureTokenHasher>(h => h.HashToken(It.IsAny<string>()) == "hash"),
            Mock.Of<Ashlar.Security.Tokens.ISecureTokenGenerator>(g => g.GenerateToken(It.IsAny<int>()) == "token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(TimeProvider: _timeProvider, SecurityEventSink: _events));
        _service = new AccountSecurityService(
            _identityRepository,
            sessionService,
            new NullTransactionProvider(),
            new AllowAccountSecurityGuard(),
            new AccountSecurityServiceDependencies(_timeProvider, _events, _events));
    }

    [Test]
    public async Task DisableUserAsyncShouldDeactivateUserRevokeSessionsAndAudit()
    {
        _identityRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };
        _sessionRepository.Sessions.Add(CreateSession(_userId));

        var result = await _service.DisableUserAsync(_userId, CreateRequest("risk"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(_identityRepository.Users[_userId].IsActive, Is.False);
            Assert.That(_sessionRepository.Sessions.Single().RevokedAt, Is.EqualTo(_timeProvider.GetUtcNow()));
            Assert.That(result.Value?.SessionsRevoked, Is.EqualTo(1));
            Assert.That(_events.Events.Any(e => e.EventType == AshlarSecurityEventTypes.UserDisabled && e.ActorUserId.HasValue), Is.True);
        }
    }

    [Test]
    public async Task DisableUserAsyncShouldUseSessionServiceNotifications()
    {
        _identityRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };
        _sessionRepository.Sessions.Add(CreateSession(_userId));
        var notifications = new Mock<ISecurityNotificationService>();
        var sessionService = new AuthenticationSessionService(
            _sessionRepository,
            Mock.Of<Ashlar.Security.Tokens.ISecureTokenHasher>(h => h.HashToken(It.IsAny<string>()) == "hash"),
            Mock.Of<Ashlar.Security.Tokens.ISecureTokenGenerator>(g => g.GenerateToken(It.IsAny<int>()) == "token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(
                TimeProvider: _timeProvider,
                SecurityEventSink: _events,
                IdentityRepository: _identityRepository,
                NotificationService: notifications.Object));
        var service = new AccountSecurityService(
            _identityRepository,
            sessionService,
            new NullTransactionProvider(),
            new AllowAccountSecurityGuard(),
            new AccountSecurityServiceDependencies(_timeProvider, _events, _events));

        var result = await service.DisableUserAsync(_userId, CreateRequest("risk"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(_events.Events.Any(e => e.EventType == AshlarSecurityEventTypes.SessionsRevokedForUser), Is.True);
        }

        notifications.Verify(n => n.NotifyAsync(It.Is<SecurityNotification>(notification =>
            notification.Type == SecurityNotificationType.AllSessionsRevoked &&
            notification.RecipientEmail == "user@example.com" &&
            notification.Metadata != null &&
            notification.Metadata["reason"] == "risk"), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task DisableUserAsyncShouldReturnGuardFailureWhenGuardRejectsOperation()
    {
        _identityRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };
        var service = new AccountSecurityService(
            _identityRepository,
            Mock.Of<IAuthenticationSessionService>(),
            new NullTransactionProvider(),
            new RejectingAccountSecurityGuard(),
            new AccountSecurityServiceDependencies(_timeProvider, _events, _events));

        var result = await service.DisableUserAsync(_userId, CreateRequest());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(new AshlarFailureCode("guard_rejected")));
            Assert.That(_identityRepository.Users[_userId].IsActive, Is.True);
            Assert.That(_events.Events.Single().FailureReason, Is.EqualTo("guard_rejected"));
        }
    }

    [Test]
    public async Task DisableUserAsyncShouldReturnUserNotFoundForMissingUser()
    {
        var result = await _service.DisableUserAsync(_userId, CreateRequest());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(_events.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.UserDisabled));
        }
    }

    [Test]
    public async Task DisableUserAsyncShouldReturnUserNotFoundForTenantMismatch()
    {
        _identityRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true, TenantId = Guid.NewGuid() };
        _sessionRepository.Sessions.Add(CreateSession(_userId));

        var result = await _service.DisableUserAsync(_userId, CreateRequest(tenantId: Guid.NewGuid()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(_identityRepository.Users[_userId].IsActive, Is.True);
            Assert.That(_sessionRepository.Sessions.Single().RevokedAt, Is.Null);
            Assert.That(_events.Events.Single().FailureReason, Is.EqualTo(AshlarFailureCodes.UserNotFound.Value));
        }
    }

    [Test]
    public async Task DisableUserAsyncShouldAllowMatchingTenant()
    {
        var tenantId = Guid.NewGuid();
        _identityRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true, TenantId = tenantId };

        var result = await _service.DisableUserAsync(_userId, CreateRequest(tenantId: tenantId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(_identityRepository.Users[_userId].IsActive, Is.False);
            Assert.That(_events.Events.Any(e => e.EventType == AshlarSecurityEventTypes.UserDisabled && e.TenantId == tenantId), Is.True);
        }
    }

    [Test]
    public async Task DisableUserAsyncShouldReturnUserNotFoundWhenTenantScopeTargetsGlobalUser()
    {
        _identityRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };

        var result = await _service.DisableUserAsync(_userId, CreateRequest(tenantId: Guid.NewGuid()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(_identityRepository.Users[_userId].IsActive, Is.True);
        }
    }

    [Test]
    public async Task DisableUserAsyncShouldAllowExplicitGlobalTenantForGlobalUser()
    {
        _identityRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };

        var result = await _service.DisableUserAsync(_userId, new AccountSecurityOperationRequest(new AuditContext(Guid.NewGuid()), TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(_identityRepository.Users[_userId].IsActive, Is.False);
        }
    }

    [Test]
    public async Task DisableUserAsyncShouldNotUpdateInactiveUserButShouldRevokeSessions()
    {
        _identityRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = false };
        _sessionRepository.Sessions.Add(CreateSession(_userId));

        var result = await _service.DisableUserAsync(_userId, CreateRequest());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.UserChanged, Is.False);
            Assert.That(result.Value?.SessionsRevoked, Is.EqualTo(1));
            Assert.That(_sessionRepository.Sessions.Single().RevocationReason, Is.EqualTo("admin"));
        }
    }

    [Test]
    public async Task DisableUserAsyncShouldUseValidationErrorWhenGuardFailureHasNoDetails()
    {
        _identityRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };
        var service = new AccountSecurityService(
            _identityRepository,
            Mock.Of<IAuthenticationSessionService>(),
            new NullTransactionProvider(),
            new EmptyFailureAccountSecurityGuard(),
            new AccountSecurityServiceDependencies(_timeProvider, _events, _events));

        var result = await service.DisableUserAsync(_userId, CreateRequest());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(_events.Events.Single().FailureReason, Is.EqualTo(AshlarFailureCodes.ValidationError.Value));
        }
    }

    [Test]
    public async Task ReactivateUserAsyncShouldReactivateWithoutRevokingCredentials()
    {
        _identityRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = false };
        _identityRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));

        var result = await _service.ReactivateUserAsync(_userId, CreateRequest());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(_identityRepository.Users[_userId].IsActive, Is.True);
            Assert.That(_identityRepository.Credentials.Single().RevokedAt, Is.Null);
            Assert.That(_events.Events.Any(e => e.EventType == AshlarSecurityEventTypes.UserReactivated), Is.True);
        }
    }

    [Test]
    public async Task ReactivateUserAsyncShouldReturnUserNotFoundForMissingUser()
    {
        var result = await _service.ReactivateUserAsync(_userId, CreateRequest());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(_events.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.UserReactivated));
        }
    }

    [Test]
    public async Task ReactivateUserAsyncShouldReturnUserNotFoundForTenantMismatch()
    {
        _identityRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = false, TenantId = Guid.NewGuid() };

        var result = await _service.ReactivateUserAsync(_userId, CreateRequest(tenantId: Guid.NewGuid()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(_identityRepository.Users[_userId].IsActive, Is.False);
        }
    }

    [Test]
    public async Task ReactivateUserAsyncShouldNoopForActiveUser()
    {
        _identityRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };

        var result = await _service.ReactivateUserAsync(_userId, CreateRequest("manual-review"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.UserChanged, Is.False);
            Assert.That(_events.Events.Single().Properties?["reason"], Is.EqualTo("manual-review"));
        }
    }

    [Test]
    public async Task RevokeSessionsAsyncShouldReturnUserNotFoundForMissingUser()
    {
        var result = await _service.RevokeSessionsAsync(_userId, CreateRequest());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(_events.Events.Single().FailureReason, Is.EqualTo(AshlarFailureCodes.UserNotFound.Value));
        }
    }

    [Test]
    public async Task RevokeSessionsAsyncShouldReturnUserNotFoundForTenantMismatch()
    {
        _identityRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true, TenantId = Guid.NewGuid() };
        _sessionRepository.Sessions.Add(CreateSession(_userId));

        var result = await _service.RevokeSessionsAsync(_userId, CreateRequest(tenantId: Guid.NewGuid()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(_sessionRepository.Sessions.Single().RevokedAt, Is.Null);
        }
    }

    [Test]
    public async Task RevokeSessionsAsyncShouldRevokeSessionsForExistingUser()
    {
        _identityRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };
        _sessionRepository.Sessions.Add(CreateSession(_userId));

        var result = await _service.RevokeSessionsAsync(_userId, CreateRequest());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.SessionsRevoked, Is.EqualTo(1));
            Assert.That(_events.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.SessionsRevokedForUser));
        }
    }

    [Test]
    public async Task RevokeCredentialsAsyncShouldRevokeMatchingProviderCredentials()
    {
        _identityRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };
        _identityRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));

        var result = await _service.RevokeCredentialsAsync(_userId, AuthenticationProviderKey.Local, CreateRequest("rotation"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.CredentialsRevoked, Is.EqualTo(1));
            Assert.That(_identityRepository.Credentials.Single().RevokedAt, Is.Not.Null);
            Assert.That(_events.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.UserCredentialsRevoked));
        }
    }

    [Test]
    public async Task RevokeCredentialsAsyncShouldReturnUserNotFoundForMissingUser()
    {
        var result = await _service.RevokeCredentialsAsync(_userId, AuthenticationProviderKey.Local, CreateRequest(tenantId: Guid.NewGuid()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(_events.Events.Single().Provider, Is.EqualTo(AuthenticationProviderKey.Local));
        }
    }

    [Test]
    public async Task RevokeCredentialsAsyncShouldReturnUserNotFoundForTenantMismatch()
    {
        _identityRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true, TenantId = Guid.NewGuid() };
        _identityRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));

        var result = await _service.RevokeCredentialsAsync(_userId, AuthenticationProviderKey.Local, CreateRequest(tenantId: Guid.NewGuid()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(_identityRepository.Credentials.Single().RevokedAt, Is.Null);
        }
    }

    [Test]
    public void RevokeCredentialsAsyncShouldRejectUninitializedProvider()
    {
        Assert.ThrowsAsync<ArgumentException>(() => _service.RevokeCredentialsAsync(_userId, default, CreateRequest()));
    }

    [Test]
    public async Task ResetMfaAsyncShouldRevokeTotpAndRecoveryCodeCredentialsOnly()
    {
        _identityRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };
        _identityRepository.Credentials.Add(CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.Mfa, "totp")));
        _identityRepository.Credentials.Add(CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.RecoveryCode, "RecoveryCode")));
        _identityRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));

        var result = await _service.ResetMfaAsync(_userId, CreateRequest("lost-device"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.CredentialsRevoked, Is.EqualTo(2));
            Assert.That(_identityRepository.Credentials.Count(c => c.RevokedAt.HasValue), Is.EqualTo(2));
            Assert.That(_identityRepository.Credentials.Single(c => c.ProviderType == ProviderType.Local).RevokedAt, Is.Null);
            Assert.That(_events.Events.Any(e => e.EventType == AshlarSecurityEventTypes.UserMfaReset), Is.True);
        }
    }

    [Test]
    public async Task ResetMfaAsyncShouldReturnUserNotFoundForMissingUser()
    {
        var result = await _service.ResetMfaAsync(_userId, CreateRequest());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(_events.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.UserMfaReset));
        }
    }

    [Test]
    public async Task ResetMfaAsyncShouldReturnUserNotFoundForTenantMismatch()
    {
        _identityRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true, TenantId = Guid.NewGuid() };
        _identityRepository.Credentials.Add(CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.Mfa, "totp")));

        var result = await _service.ResetMfaAsync(_userId, CreateRequest(tenantId: Guid.NewGuid()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(_identityRepository.Credentials.Single().RevokedAt, Is.Null);
        }
    }

    [Test]
    public async Task ResetMfaAsyncShouldUseConfiguredProviderKeys()
    {
        var totpProvider = new AuthenticationProviderKey(ProviderType.Mfa, "custom-totp");
        var recoveryProvider = new AuthenticationProviderKey(ProviderType.RecoveryCode, "custom-recovery");
        _identityRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };
        _identityRepository.Credentials.Add(CreateCredential(_userId, totpProvider));
        _identityRepository.Credentials.Add(CreateCredential(_userId, recoveryProvider));
        var service = new AccountSecurityService(
            _identityRepository,
            Mock.Of<IAuthenticationSessionService>(),
            new NullTransactionProvider(),
            new AllowAccountSecurityGuard(),
            new AccountSecurityServiceDependencies(
                _timeProvider,
                _events,
                _events,
                Options.Create(new TotpOptions { ProviderKey = totpProvider }),
                Options.Create(new RecoveryCodeOptions { ProviderKey = recoveryProvider })));

        var result = await service.ResetMfaAsync(_userId, CreateRequest());

        Assert.That(result.Value?.CredentialsRevoked, Is.EqualTo(2));
    }

    [Test]
    public async Task DisableUserAsyncShouldSupportUsersWithoutTenantInterface()
    {
        var repository = new Mock<IIdentityRepository>();
        repository
            .Setup(r => r.GetUserByIdAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new BasicUser(_userId, "basic@example.com", true));
        var service = new AccountSecurityService(
            repository.Object,
            Mock.Of<IAuthenticationSessionService>(),
            new NullTransactionProvider(),
            new AllowAccountSecurityGuard(),
            new AccountSecurityServiceDependencies());

        var result = await service.DisableUserAsync(_userId, CreateRequest());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            repository.Verify(r => r.UpdateUserAsync(It.Is<IUser>(u => ((ITenantUser)u).TenantId == null), It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [Test]
    public async Task DisableUserAsyncShouldReturnUserNotFoundForTenantScopedRequestWhenUserHasNoTenantInterface()
    {
        var repository = new Mock<IIdentityRepository>();
        repository
            .Setup(r => r.GetUserByIdAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new BasicUser(_userId, "basic@example.com", true));
        var service = new AccountSecurityService(
            repository.Object,
            Mock.Of<IAuthenticationSessionService>(),
            new NullTransactionProvider(),
            new AllowAccountSecurityGuard(),
            new AccountSecurityServiceDependencies(_timeProvider, _events, _events));

        var result = await service.DisableUserAsync(_userId, CreateRequest(tenantId: Guid.NewGuid()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldReturnNonSecretSummary()
    {
        _identityRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true, EmailVerifiedAt = _timeProvider.GetUtcNow() };
        var localCredential = CreateCredential(_userId, AuthenticationProviderKey.Local);
        localCredential.CredentialValue = "secret";
        var mfaCredential = CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.Mfa, "totp"));
        mfaCredential.CredentialValue = "secret";
        _identityRepository.Credentials.Add(localCredential);
        _identityRepository.Credentials.Add(mfaCredential);
        _sessionRepository.Sessions.Add(CreateSession(_userId));
        await _events.RecordAsync(new AshlarSecurityEvent { Id = Guid.NewGuid(), EventType = "test", UserId = _userId, OccurredAt = _timeProvider.GetUtcNow() });

        var result = await _service.GetUserSecurityPostureAsync(_userId, new UserSecurityPostureRequest(RecentSecurityEventWindow: TimeSpan.FromDays(1)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.IsActive, Is.True);
            Assert.That(result.Value?.IsEmailVerified, Is.True);
            Assert.That(result.Value?.IsMfaConfigured, Is.True);
            Assert.That(result.Value?.ActiveSessionCount, Is.EqualTo(1));
            Assert.That(result.Value?.RecentSecurityEventCount, Is.EqualTo(1));
            Assert.That(result.Value?.ConfiguredCredentials, Has.Count.EqualTo(2));
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldReturnUserNotFoundForMissingUser()
    {
        var result = await _service.GetUserSecurityPostureAsync(_userId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldReturnUserNotFoundForTenantMismatch()
    {
        _identityRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true, TenantId = Guid.NewGuid() };

        var result = await _service.GetUserSecurityPostureAsync(_userId, new UserSecurityPostureRequest(new TenantContext(Guid.NewGuid())));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldOmitEventCountWhenWindowOrRepositoryMissing()
    {
        _identityRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };
        _identityRepository.Credentials.Add(CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.RecoveryCode, "RecoveryCode")));
        var sessionService = new Mock<IAuthenticationSessionService>();
        sessionService
            .Setup(s => s.ListSessionsForUserAsync(_userId, It.IsAny<ListAuthenticationSessionsRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Array.Empty<AuthenticationSessionSummary>());
        var service = new AccountSecurityService(
            _identityRepository,
            sessionService.Object,
            new NullTransactionProvider(),
            new AllowAccountSecurityGuard(),
            new AccountSecurityServiceDependencies(_timeProvider, _events));

        var result = await service.GetUserSecurityPostureAsync(_userId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.IsMfaConfigured, Is.True);
            Assert.That(result.Value?.RecentSecurityEventCount, Is.Null);
        }
    }

    [Test]
    public void ConstructorShouldThrowForNullDependencies()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new AccountSecurityService(null!, Mock.Of<IAuthenticationSessionService>(), new NullTransactionProvider(), new AllowAccountSecurityGuard(), new AccountSecurityServiceDependencies()));
            Assert.Throws<ArgumentNullException>(() => _ = new AccountSecurityService(_identityRepository, null!, new NullTransactionProvider(), new AllowAccountSecurityGuard(), new AccountSecurityServiceDependencies()));
            Assert.Throws<ArgumentNullException>(() => _ = new AccountSecurityService(_identityRepository, Mock.Of<IAuthenticationSessionService>(), null!, new AllowAccountSecurityGuard(), new AccountSecurityServiceDependencies()));
            Assert.Throws<ArgumentNullException>(() => _ = new AccountSecurityService(_identityRepository, Mock.Of<IAuthenticationSessionService>(), new NullTransactionProvider(), null!, new AccountSecurityServiceDependencies()));
            Assert.Throws<ArgumentNullException>(() => _ = new AccountSecurityService(_identityRepository, Mock.Of<IAuthenticationSessionService>(), new NullTransactionProvider(), new AllowAccountSecurityGuard(), null!));
        }
    }

    [Test]
    public void OperationsShouldValidateUserIdAndAuditRequest()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentException>(() => _service.DisableUserAsync(Guid.Empty, CreateRequest()));
            Assert.ThrowsAsync<ArgumentNullException>(() => _service.DisableUserAsync(_userId, null!));
            Assert.ThrowsAsync<ArgumentException>(() => _service.ReactivateUserAsync(Guid.Empty, CreateRequest()));
            Assert.ThrowsAsync<ArgumentNullException>(() => _service.ReactivateUserAsync(_userId, null!));
            Assert.ThrowsAsync<ArgumentException>(() => _service.RevokeSessionsAsync(Guid.Empty, CreateRequest()));
            Assert.ThrowsAsync<ArgumentNullException>(() => _service.RevokeSessionsAsync(_userId, null!));
            Assert.ThrowsAsync<ArgumentException>(() => _service.ResetMfaAsync(Guid.Empty, CreateRequest()));
            Assert.ThrowsAsync<ArgumentNullException>(() => _service.ResetMfaAsync(_userId, null!));
            Assert.ThrowsAsync<ArgumentException>(() => _service.GetUserSecurityPostureAsync(Guid.Empty));
        }
    }

    private static AccountSecurityOperationRequest CreateRequest(string? reason = null, Guid? tenantId = null)
    {
        return new AccountSecurityOperationRequest(new AuditContext(Guid.NewGuid(), "127.0.0.1", "agent", "corr"), tenantId.HasValue ? new TenantContext(tenantId) : null, reason);
    }

    private AuthenticationSession CreateSession(Guid userId)
    {
        return new AuthenticationSession
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            TokenHash = Guid.NewGuid().ToString("N"),
            CreatedAt = _timeProvider.GetUtcNow(),
            ExpiresAt = _timeProvider.GetUtcNow().AddHours(1)
        };
    }

    private UserCredential CreateCredential(Guid userId, AuthenticationProviderKey provider)
    {
        return new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = provider.Type,
            ProviderName = provider.Name,
            ProviderKey = Guid.NewGuid().ToString("N"),
            Version = "v1",
            Status = CredentialStatus.Active,
            CreatedAt = _timeProvider.GetUtcNow()
        };
    }

    private sealed class RecordingSecurityEventSink : ISecurityEventSink, IUserSecurityEventSummaryRepository
    {
        public List<AshlarSecurityEvent> Events { get; } = [];

        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            Events.Add(securityEvent);
            return Task.CompletedTask;
        }

        public Task<int> CountSecurityEventsForUserAsync(Guid userId, DateTimeOffset since, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Events.Count(e => e.UserId == userId && e.OccurredAt >= since));
        }
    }

    private sealed class RejectingAccountSecurityGuard : IAccountSecurityGuard
    {
        public Task<Result> CanDisableUserAsync(IUser user, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Result.Failure(new AshlarFailureCode("guard_rejected")));
        }
    }

    private sealed class EmptyFailureAccountSecurityGuard : IAccountSecurityGuard
    {
        public Task<Result> CanDisableUserAsync(IUser user, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new Result(false));
        }
    }

    private sealed record BasicUser(Guid Id, string Email, bool IsActive) : IUser
    {
        public string? Name => null;
        public DateTimeOffset? EmailVerifiedAt => null;
    }

    private sealed class InMemoryIdentityRepository : IIdentityRepository
    {
        public Dictionary<Guid, User> Users { get; } = [];
        public List<UserCredential> Credentials { get; } = [];

        public Task<IUser?> GetUserByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IUser?>(Users.Values.FirstOrDefault(u => u.Email == email && u.TenantId == tenantId));
        }

        public Task<IUser?> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IUser?>(Users.GetValueOrDefault(userId));
        }

        public Task<UserCredential?> GetCredentialForUserAsync(Guid userId, ProviderType type, string providerName, string? providerKey = null, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Credentials.FirstOrDefault(c => c.UserId == userId && c.ProviderType == type && c.ProviderName == providerName && c.RevokedAt == null && (providerKey == null || c.ProviderKey == providerKey)));
        }

        public Task<IUser?> GetUserByProviderKeyAsync(ProviderType type, string providerName, string providerKey, CancellationToken cancellationToken = default)
        {
            var credential = Credentials.FirstOrDefault(c => c.ProviderType == type && c.ProviderName == providerName && c.ProviderKey == providerKey && c.RevokedAt == null);
            return Task.FromResult<IUser?>(credential == null ? null : Users.GetValueOrDefault(credential.UserId));
        }

        public Task<IReadOnlyList<UserCredential>> ListCredentialsForUserAsync(Guid userId, bool activeOnly = true, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IReadOnlyList<UserCredential>>(Credentials.Where(c => c.UserId == userId && (!activeOnly || c.RevokedAt == null)).ToList().AsReadOnly());
        }

        public Task CreateUserAsync(IUser user, CancellationToken cancellationToken = default)
        {
            Users[user.Id] = new User { Id = user.Id, Email = user.Email, IsActive = user.IsActive, Name = user.Name, TenantId = (user as ITenantUser)?.TenantId, EmailVerifiedAt = user.EmailVerifiedAt };
            return Task.CompletedTask;
        }

        public Task UpdateUserAsync(IUser user, CancellationToken cancellationToken = default)
        {
            Users[user.Id] = new User { Id = user.Id, Email = user.Email, IsActive = user.IsActive, Name = user.Name, TenantId = (user as ITenantUser)?.TenantId, EmailVerifiedAt = user.EmailVerifiedAt };
            return Task.CompletedTask;
        }

        public Task CreateCredentialAsync(UserCredential credential, CancellationToken cancellationToken = default)
        {
            Credentials.Add(credential);
            return Task.CompletedTask;
        }

        public Task CreateOrReplaceCredentialAsync(UserCredential credential, CancellationToken cancellationToken = default)
        {
            Credentials.RemoveAll(c => c.ProviderType == credential.ProviderType && c.ProviderName == credential.ProviderName && c.ProviderKey == credential.ProviderKey);
            Credentials.Add(credential);
            return Task.CompletedTask;
        }

        public Task<bool> UpdateCredentialAsync(UserCredential credential, string expectedVersion, CancellationToken cancellationToken = default) => Task.FromResult(true);

        public Task<bool> ConsumeCredentialAsync(Guid credentialId, string expectedVersion, CancellationToken cancellationToken = default) => Task.FromResult(Credentials.RemoveAll(c => c.Id == credentialId) > 0);

        public Task<int> RevokeCredentialsAsync(Guid userId, ProviderType type, string providerName, CancellationToken cancellationToken = default)
        {
            var revokedAt = DateTimeOffset.UtcNow;
            var count = 0;
            foreach (var credential in Credentials.Where(c => c.UserId == userId && c.ProviderType == type && c.ProviderName == providerName && c.RevokedAt == null))
            {
                credential.RevokedAt = revokedAt;
                credential.Status = CredentialStatus.Revoked;
                count++;
            }

            return Task.FromResult(count);
        }
    }

    private sealed class InMemorySessionRepository : IAuthenticationSessionRepository
    {
        public List<AuthenticationSession> Sessions { get; } = [];

        public Task CreateSessionAsync(AuthenticationSession session, CancellationToken cancellationToken = default)
        {
            Sessions.Add(session);
            return Task.CompletedTask;
        }

        public Task<AuthenticationSession?> GetSessionByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default) => Task.FromResult(Sessions.FirstOrDefault(s => s.TokenHash == tokenHash));

        public Task<AuthenticationSession?> GetSessionAsync(Guid sessionId, CancellationToken cancellationToken = default) => Task.FromResult(Sessions.FirstOrDefault(s => s.Id == sessionId));

        public Task<bool> UpdateSessionLastSeenAsync(Guid sessionId, DateTimeOffset lastSeenAt, CancellationToken cancellationToken = default) => Task.FromResult(true);

        public Task<bool> RevokeSessionAsync(Guid sessionId, DateTimeOffset revokedAt, string? reason = null, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Revoke(s => s.Id == sessionId, revokedAt, reason) == 1);
        }

        public Task<int> RevokeSessionsForUserAsync(Guid userId, DateTimeOffset revokedAt, string? reason = null, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Revoke(s => s.UserId == userId, revokedAt, reason));
        }

        public Task<IReadOnlyList<AuthenticationSession>> ListSessionsForUserAsync(Guid userId, bool activeOnly, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IReadOnlyList<AuthenticationSession>>(Sessions.Where(s => s.UserId == userId && (!activeOnly || s.IsActive(now))).ToList().AsReadOnly());
        }

        public Task<bool> RevokeSessionByIdAsync(Guid sessionId, Guid userId, DateTimeOffset revokedAt, string? reason = null, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Revoke(s => s.Id == sessionId && s.UserId == userId, revokedAt, reason) == 1);
        }

        public Task<int> RevokeOtherSessionsForUserAsync(Guid userId, Guid excludedSessionId, DateTimeOffset revokedAt, string? reason = null, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Revoke(s => s.UserId == userId && s.Id != excludedSessionId, revokedAt, reason));
        }

        private int Revoke(Func<AuthenticationSession, bool> predicate, DateTimeOffset revokedAt, string? reason)
        {
            var count = 0;
            foreach (var session in Sessions.Where(s => predicate(s) && s.RevokedAt == null))
            {
                session.RevokedAt = revokedAt;
                session.RevocationReason = reason;
                count++;
            }

            return count;
        }
    }
}
