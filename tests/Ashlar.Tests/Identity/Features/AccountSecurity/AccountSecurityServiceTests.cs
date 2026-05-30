using Ashlar.Auditing;
using Ashlar.Identity.Models.Totp;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.Providers.RecoveryCode;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Identity.Features.AccountSecurity;

internal sealed class AccountSecurityServiceTests
{
    private static readonly string[] ExpectedAppAndRecoveryFactors = ["Authenticator app", "Recovery codes"];
    private static readonly string[] ExpectedAuthenticatorAppFactor = ["Authenticator app"];
    private static readonly string[] ExpectedEmailSignIn = ["Email sign-in"];
    private static readonly string[] ExpectedCustomFactor = ["custom_factor"];
    private readonly Guid _userId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private FakeTimeProvider _timeProvider;
    private InMemoryUserCredentialStore _userRepository;
    private InMemorySessionRepository _sessionRepository;
    private RecordingSecurityEventSink _events;
    private AccountSecurityService _service;

    [SetUp]
    public void SetUp()
    {
        _timeProvider = new FakeTimeProvider(new DateTimeOffset(2026, 5, 17, 12, 0, 0, TimeSpan.Zero));
        _userRepository = new InMemoryUserCredentialStore();
        _sessionRepository = new InMemorySessionRepository();
        _events = new RecordingSecurityEventSink();
        var sessionService = new AuthenticationSessionService(
            _sessionRepository,
            Mock.Of<Ashlar.Security.Tokens.ISecureTokenHasher>(h => h.HashToken(It.IsAny<string>()) == "hash"),
            Mock.Of<Ashlar.Security.Tokens.ISecureTokenGenerator>(g => g.GenerateToken(It.IsAny<int>()) == "token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(TimeProvider: _timeProvider, SecurityEventSink: _events, UserRepository: _userRepository));
        _service = new AccountSecurityService(
            _userRepository,
            _userRepository,
            sessionService,
            new NullTransactionProvider(),
            new AllowAccountSecurityGuard(),
            new AccountSecurityServiceDependencies(_timeProvider, _events, _events, ProviderRegistry: CreateDefaultProviderRegistry()));
    }

    [Test]
    public async Task DisableUserAsyncShouldDeactivateUserRevokeSessionsAndAudit()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };
        _sessionRepository.Sessions.Add(CreateSession(_userId));

        var result = await _service.DisableUserAsync(_userId, CreateRequest("risk"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(_userRepository.Users[_userId].IsActive, Is.False);
            Assert.That(_sessionRepository.Sessions.Single().RevokedAt, Is.EqualTo(_timeProvider.GetUtcNow()));
            Assert.That(result.Value?.SessionsRevoked, Is.EqualTo(1));
            Assert.That(_events.Events.Any(e => e.EventType == AshlarSecurityEventTypes.UserDisabled && e.ActorUserId.HasValue), Is.True);
        }
    }

    [Test]
    public async Task DisableUserAsyncShouldUseSessionServiceNotifications()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };
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
                UserRepository: _userRepository,
                NotificationService: notifications.Object));
        var service = new AccountSecurityService(
            _userRepository,
            _userRepository,
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
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };
        var service = new AccountSecurityService(
            _userRepository,
            _userRepository,
            Mock.Of<IAuthenticationSessionService>(),
            new NullTransactionProvider(),
            new RejectingAccountSecurityGuard(),
            new AccountSecurityServiceDependencies(_timeProvider, _events, _events));

        var result = await service.DisableUserAsync(_userId, CreateRequest());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(new AshlarFailureCode("guard_rejected")));
            Assert.That(_userRepository.Users[_userId].IsActive, Is.True);
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
    public async Task DisableUserAsyncShouldReturnTenantMismatchForTenantMismatch()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true, TenantId = Guid.NewGuid() };
        _sessionRepository.Sessions.Add(CreateSession(_userId));
        var requestedTenantId = Guid.NewGuid();

        var result = await _service.DisableUserAsync(_userId, CreateRequest(tenantId: requestedTenantId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            Assert.That(_userRepository.Users[_userId].IsActive, Is.True);
            Assert.That(_sessionRepository.Sessions.Single().RevokedAt, Is.Null);
            Assert.That(_events.Events.Single().FailureReason, Is.EqualTo(AshlarFailureCodes.TenantMismatch.Value));
            Assert.That(_events.Events.Single().TenantId, Is.EqualTo(requestedTenantId));
        }
    }

    [Test]
    public async Task DisableUserAsyncShouldAllowMatchingTenant()
    {
        var tenantId = Guid.NewGuid();
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true, TenantId = tenantId };

        var result = await _service.DisableUserAsync(_userId, CreateRequest(tenantId: tenantId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(_userRepository.Users[_userId].IsActive, Is.False);
            Assert.That(_events.Events.Any(e => e.EventType == AshlarSecurityEventTypes.UserDisabled && e.TenantId == tenantId), Is.True);
        }
    }

    [Test]
    public async Task DisableUserAsyncShouldReturnTenantMismatchWhenTenantScopeTargetsGlobalUser()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };

        var result = await _service.DisableUserAsync(_userId, CreateRequest(tenantId: Guid.NewGuid()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            Assert.That(_userRepository.Users[_userId].IsActive, Is.True);
        }
    }

    [Test]
    public async Task DisableUserAsyncShouldTreatMissingTenantAsGlobalOnly()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true, TenantId = Guid.NewGuid() };

        var result = await _service.DisableUserAsync(_userId, CreateRequest());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            Assert.That(_userRepository.Users[_userId].IsActive, Is.True);
            Assert.That(_events.Events.Single().TenantId, Is.Null);
            Assert.That(_events.Events.Single().FailureReason, Is.EqualTo(AshlarFailureCodes.TenantMismatch.Value));
        }
    }

    [Test]
    public async Task DisableUserAsyncShouldAllowExplicitGlobalTenantForGlobalUser()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };

        var result = await _service.DisableUserAsync(_userId, new AccountSecurityOperationRequest(new AuditContext(Guid.NewGuid()), TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(_userRepository.Users[_userId].IsActive, Is.False);
        }
    }

    [Test]
    public async Task DisableUserAsyncShouldNotUpdateInactiveUserButShouldRevokeSessions()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = false };
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
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };
        var service = new AccountSecurityService(
            _userRepository,
            _userRepository,
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
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = false };
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));

        var result = await _service.ReactivateUserAsync(_userId, CreateRequest());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(_userRepository.Users[_userId].IsActive, Is.True);
            Assert.That(_userRepository.Credentials.Single().RevokedAt, Is.Null);
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
    public async Task ReactivateUserAsyncShouldReturnTenantMismatchForTenantMismatch()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = false, TenantId = Guid.NewGuid() };

        var result = await _service.ReactivateUserAsync(_userId, CreateRequest(tenantId: Guid.NewGuid()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            Assert.That(_userRepository.Users[_userId].IsActive, Is.False);
        }
    }

    [Test]
    public async Task ReactivateUserAsyncShouldNoopForActiveUser()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };

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
    public async Task RevokeSessionsAsyncShouldReturnTenantMismatchForTenantMismatch()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true, TenantId = Guid.NewGuid() };
        _sessionRepository.Sessions.Add(CreateSession(_userId));

        var result = await _service.RevokeSessionsAsync(_userId, CreateRequest(tenantId: Guid.NewGuid()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            Assert.That(_sessionRepository.Sessions.Single().RevokedAt, Is.Null);
        }
    }

    [Test]
    public async Task RevokeSessionsAsyncShouldRevokeSessionsForExistingUser()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };
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
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));

        var result = await _service.RevokeCredentialsAsync(_userId, AuthenticationProviderKey.Local, CreateRequest("rotation"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.CredentialsRevoked, Is.EqualTo(1));
            Assert.That(_userRepository.Credentials.Single().RevokedAt, Is.Not.Null);
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
    public async Task RevokeCredentialsAsyncShouldReturnTenantMismatchForTenantMismatch()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true, TenantId = Guid.NewGuid() };
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));

        var result = await _service.RevokeCredentialsAsync(_userId, AuthenticationProviderKey.Local, CreateRequest(tenantId: Guid.NewGuid()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            Assert.That(_userRepository.Credentials.Single().RevokedAt, Is.Null);
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
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };
        _userRepository.Credentials.Add(CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.Mfa, "totp")));
        _userRepository.Credentials.Add(CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.RecoveryCode, "RecoveryCode")));
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));

        var result = await _service.ResetMfaAsync(_userId, CreateRequest("lost-device"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.CredentialsRevoked, Is.EqualTo(2));
            Assert.That(_userRepository.Credentials.Count(c => c.RevokedAt.HasValue), Is.EqualTo(2));
            Assert.That(_userRepository.Credentials.Single(c => c.ProviderType == ProviderType.Local).RevokedAt, Is.Null);
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
    public async Task ResetMfaAsyncShouldReturnTenantMismatchForTenantMismatch()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true, TenantId = Guid.NewGuid() };
        _userRepository.Credentials.Add(CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.Mfa, "totp")));

        var result = await _service.ResetMfaAsync(_userId, CreateRequest(tenantId: Guid.NewGuid()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            Assert.That(_userRepository.Credentials.Single().RevokedAt, Is.Null);
        }
    }

    [Test]
    public async Task ResetMfaAsyncShouldUseConfiguredProviderKeys()
    {
        var totpProvider = new AuthenticationProviderKey(ProviderType.Mfa, "custom-totp");
        var recoveryProvider = new AuthenticationProviderKey(ProviderType.RecoveryCode, "custom-recovery");
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };
        _userRepository.Credentials.Add(CreateCredential(_userId, totpProvider));
        _userRepository.Credentials.Add(CreateCredential(_userId, recoveryProvider));
        var service = new AccountSecurityService(
            _userRepository,
            _userRepository,
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
        var repository = new Mock<IUserRepository>();
        repository
            .Setup(r => r.GetUserByIdAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new BasicUser(_userId, "basic@example.com", true));
        var service = new AccountSecurityService(
            repository.Object,
            Mock.Of<ICredentialRepository>(),
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
    public async Task DisableUserAsyncShouldReturnTenantMismatchForTenantScopedRequestWhenUserHasNoTenantInterface()
    {
        var repository = new Mock<IUserRepository>();
        repository
            .Setup(r => r.GetUserByIdAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new BasicUser(_userId, "basic@example.com", true));
        var service = new AccountSecurityService(
            repository.Object,
            Mock.Of<ICredentialRepository>(),
            Mock.Of<IAuthenticationSessionService>(),
            new NullTransactionProvider(),
            new AllowAccountSecurityGuard(),
            new AccountSecurityServiceDependencies(_timeProvider, _events, _events));

        var result = await service.DisableUserAsync(_userId, CreateRequest(tenantId: Guid.NewGuid()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldReturnNonSecretSummary()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true, EmailVerifiedAt = _timeProvider.GetUtcNow() };
        var localCredential = CreateCredential(_userId, AuthenticationProviderKey.Local);
        localCredential.CredentialValue = "secret";
        var mfaCredential = CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.Mfa, "totp"));
        mfaCredential.CredentialValue = "secret";
        _userRepository.Credentials.Add(localCredential);
        _userRepository.Credentials.Add(mfaCredential);
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
            Assert.That(result.Value?.GetConfiguredCredentials(), Has.Count.EqualTo(2));
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldClassifyEmailSignInOnly()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };

        var result = await _service.GetUserSecurityPostureAsync(_userId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value?.CanSignIn, Is.True);
            Assert.That(result.Value?.PrimaryCredentials.Single().DisplayName, Is.EqualTo("Email sign-in"));
            Assert.That(result.Value?.AdditionalVerificationFactors, Is.Empty);
            Assert.That(result.Value?.Policy.IsAdditionalVerificationRequired, Is.False);
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldPreferDurableEmailCredentialWhenPresent()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.EmailCode));

        var result = await _service.GetUserSecurityPostureAsync(_userId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value?.PrimaryCredentials, Has.Count.EqualTo(1));
            Assert.That(result.Value?.PrimaryCredentials.Single().Provider, Is.EqualTo(AuthenticationProviderKey.EmailCode));
            Assert.That(result.Value?.PrimaryCredentials.Single().DisplayName, Is.EqualTo("Email sign-in"));
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldClassifyTotpAndRecoveryCodesAsAdditionalVerification()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));
        _userRepository.Credentials.Add(CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.Mfa, "totp")));
        _userRepository.Credentials.Add(CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.RecoveryCode, "RecoveryCode")));

        var result = await _service.GetUserSecurityPostureAsync(_userId);
        var factors = result.Value!.AdditionalVerificationFactors;

        using (Assert.EnterMultipleScope())
        {
            Assert.That(factors.Select(f => f.DisplayName), Is.EquivalentTo(ExpectedAppAndRecoveryFactors));
            Assert.That(result.Value.IsMfaConfigured, Is.True);
            Assert.That(result.Value.PrimaryCredentials.Select(item => item.DisplayName), Does.Contain("Password"));
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldTreatPasskeyAsPrimaryAndNotImplicitTwoFactorPolicy()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Passkey));

        var result = await _service.GetUserSecurityPostureAsync(_userId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value?.CanSignIn, Is.True);
            Assert.That(result.Value?.PrimaryCredentials.Select(item => item.DisplayName), Does.Contain("Passkeys"));
            Assert.That(result.Value?.AdditionalVerificationFactors.Single().DisplayName, Is.EqualTo("Passkeys"));
            Assert.That(result.Value?.Policy.IsAdditionalVerificationRequired, Is.False);
            Assert.That(result.Value?.Policy.IsReadyForAdditionalVerification, Is.True);
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldShowPasskeyAndTotpWithoutRawProviderNames()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Passkey));
        _userRepository.Credentials.Add(CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.Mfa, "totp")));

        var result = await _service.GetUserSecurityPostureAsync(_userId);
        var names = result.Value!.CredentialInventory.Select(item => item.DisplayName).ToList();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(names, Does.Contain("Passkeys"));
            Assert.That(names, Does.Contain("Authenticator app"));
            Assert.That(names, Does.Not.Contain("PASSKEY:PASSKEY"));
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldReportMissingRequiredTotp()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));
        var service = CreateService(new StaticMfaPolicyEvaluator(true, [AuthenticationFactorTypes.Totp]));

        var result = await service.GetUserSecurityPostureAsync(_userId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value?.Policy.IsAdditionalVerificationRequired, Is.True);
            Assert.That(result.Value?.Policy.IsReadyForAdditionalVerification, Is.False);
            Assert.That(result.Value?.Policy.IsLockedOutByPolicy, Is.True);
            Assert.That(result.Value?.Policy.MissingRequiredFactorDisplayNames, Is.EqualTo(ExpectedAuthenticatorAppFactor));
            Assert.That(result.Value?.CanSignIn, Is.False);
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldAllowPasskeyAsAdditionalVerificationWhenPolicyRequiresIt()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Passkey));
        var service = CreateService(new StaticMfaPolicyEvaluator(true, [AuthenticationFactorTypes.Passkey]));

        var result = await service.GetUserSecurityPostureAsync(_userId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value?.Policy.IsAdditionalVerificationRequired, Is.True);
            Assert.That(result.Value?.Policy.IsReadyForAdditionalVerification, Is.True);
            Assert.That(result.Value?.Policy.MissingRequiredFactorTypes, Is.Empty);
            Assert.That(result.Value?.CanSignIn, Is.True);
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldRequireAnyUsableFactorWhenPolicyHasNoSpecificFactors()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));
        var service = CreateService(new StaticMfaPolicyEvaluator(true, []));

        var result = await service.GetUserSecurityPostureAsync(_userId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value?.Policy.IsAdditionalVerificationRequired, Is.True);
            Assert.That(result.Value?.Policy.RequiredFactorTypes, Is.Empty);
            Assert.That(result.Value?.Policy.AllowedFactorTypes, Is.Empty);
            Assert.That(result.Value?.Policy.HasUsableAdditionalVerificationFactor, Is.False);
            Assert.That(result.Value?.Policy.IsReadyForAdditionalVerification, Is.False);
            Assert.That(result.Value?.Policy.MissingRequiredFactorTypes, Is.Empty);
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldAllowAnyUsableFactorWhenPolicyHasNoSpecificFactors()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));
        _userRepository.Credentials.Add(CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.Mfa, "totp")));
        var service = CreateService(new StaticMfaPolicyEvaluator(true, []));

        var result = await service.GetUserSecurityPostureAsync(_userId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value?.Policy.IsAdditionalVerificationRequired, Is.True);
            Assert.That(result.Value?.Policy.HasUsableAdditionalVerificationFactor, Is.True);
            Assert.That(result.Value?.Policy.IsReadyForAdditionalVerification, Is.True);
            Assert.That(result.Value?.Policy.MissingRequiredFactorTypes, Is.Empty);
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldExposeEmptyAllowedFactorsWhenPolicyDoesNotProvideAllowedFactors()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));
        _userRepository.Credentials.Add(CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.Mfa, "totp")));
        var service = CreateService(new StaticMfaPolicyEvaluator(true, [AuthenticationFactorTypes.Totp]));

        var result = await service.GetUserSecurityPostureAsync(_userId);

        Assert.That(result.Value?.Policy.AllowedFactorTypes, Is.Empty);
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldReportInactiveUserCannotSignIn()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = false };
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));

        var result = await _service.GetUserSecurityPostureAsync(_userId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value?.IsActive, Is.False);
            Assert.That(result.Value?.CanSignIn, Is.False);
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldClassifyUnknownProviderSafely()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };
        _userRepository.Credentials.Add(CreateCredential(_userId, new AuthenticationProviderKey("Custom", "HardwareThing")));

        var result = await _service.GetUserSecurityPostureAsync(_userId);
        var item = result.Value!.CredentialInventory.Single();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(item.Purpose, Is.EqualTo(CredentialPosturePurpose.Unknown));
            Assert.That(item.IsPrimaryCredential, Is.False);
            Assert.That(item.IsAdditionalVerificationFactor, Is.False);
            Assert.That(item.DisplayName, Is.EqualTo("HardwareThing"));
            Assert.That(result.Value.CanSignIn, Is.True);
            Assert.That(result.Value.PrimaryCredentials.Select(credential => credential.DisplayName), Does.Contain("Email sign-in"));
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldNotClassifyUnregisteredBuiltInPrimaryProvider()
    {
        var service = CreateService(providerRegistry: new AuthenticationProviderRegistry([]));
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "", IsActive = true };
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));

        var result = await service.GetUserSecurityPostureAsync(_userId);
        var item = result.Value!.CredentialInventory.Single();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(item.Purpose, Is.EqualTo(CredentialPosturePurpose.Unknown));
            Assert.That(item.IsPrimaryCredential, Is.False);
            Assert.That(result.Value.PrimaryCredentials, Is.Empty);
            Assert.That(result.Value.CanSignIn, Is.False);
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldNotClassifyBuiltInProviderWhenRegistryIsMissing()
    {
        var service = new AccountSecurityService(
            _userRepository,
            _userRepository,
            Mock.Of<IAuthenticationSessionService>(s => s.ListSessionsForUserAsync(
                It.IsAny<Guid>(),
                It.IsAny<ListAuthenticationSessionsRequest>(),
                It.IsAny<CancellationToken>()) == Task.FromResult<IReadOnlyList<AuthenticationSessionSummary>>(Array.Empty<AuthenticationSessionSummary>())),
            new NullTransactionProvider(),
            new AllowAccountSecurityGuard(),
            new AccountSecurityServiceDependencies(_timeProvider, _events, _events));
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "", IsActive = true };
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Passkey));

        var result = await service.GetUserSecurityPostureAsync(_userId);
        var item = result.Value!.CredentialInventory.Single();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(item.Purpose, Is.EqualTo(CredentialPosturePurpose.Unknown));
            Assert.That(item.FactorType, Is.Null);
            Assert.That(item.IsPrimaryCredential, Is.False);
            Assert.That(item.IsAdditionalVerificationFactor, Is.False);
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldClassifyRegisteredCustomPrimaryProvider()
    {
        var providerKey = new AuthenticationProviderKey("Custom", "HardwareThing");
        var provider = new Mock<IPrimaryAuthenticationProvider>();
        provider.SetupGet(item => item.Key).Returns(providerKey);
        var registry = new AuthenticationProviderRegistry([provider.Object]);
        var service = CreateService(providerRegistry: registry);
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "", IsActive = true };
        _userRepository.Credentials.Add(CreateCredential(_userId, providerKey));

        var result = await service.GetUserSecurityPostureAsync(_userId);
        var item = result.Value!.CredentialInventory.Single();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(item.Purpose, Is.EqualTo(CredentialPosturePurpose.Primary));
            Assert.That(item.IsPrimaryCredential, Is.True);
            Assert.That(item.DisplayName, Is.EqualTo("HardwareThing"));
            Assert.That(result.Value.PrimaryCredentials.Single(), Is.SameAs(item));
            Assert.That(result.Value.CanSignIn, Is.True);
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldClassifyRegisteredCustomSecondaryProvider()
    {
        var providerKey = new AuthenticationProviderKey("Custom", "StepUpThing");
        var provider = new Mock<ISecondaryAuthenticationFactorProvider>();
        provider.SetupGet(item => item.Key).Returns(providerKey);
        provider.SetupGet(item => item.FactorType).Returns("custom_step_up");
        var registry = new AuthenticationProviderRegistry([provider.Object]);
        var service = CreateService(providerRegistry: registry);
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "", IsActive = true };
        _userRepository.Credentials.Add(CreateCredential(_userId, providerKey));

        var result = await service.GetUserSecurityPostureAsync(_userId);
        var item = result.Value!.CredentialInventory.Single();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(item.Purpose, Is.EqualTo(CredentialPosturePurpose.AdditionalVerification));
            Assert.That(item.FactorType, Is.EqualTo("custom_step_up"));
            Assert.That(item.IsPrimaryCredential, Is.False);
            Assert.That(item.IsAdditionalVerificationFactor, Is.True);
            Assert.That(result.Value.PrimaryCredentials, Is.Empty);
            Assert.That(result.Value.AdditionalVerificationFactors.Single().FactorType, Is.EqualTo("custom_step_up"));
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldUseExternalProviderFriendlyNames()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };
        _userRepository.Credentials.Add(CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.OAuth, "github")));
        _userRepository.Credentials.Add(CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.Oidc, "OIDC")));
        _userRepository.Credentials.Add(CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.Saml2, "enterprise-sso")));

        var result = await _service.GetUserSecurityPostureAsync(_userId);
        var names = result.Value!.PrimaryCredentials.Select(item => item.DisplayName).ToList();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(names, Does.Contain("github"));
            Assert.That(names, Does.Contain("External sign-in"));
            Assert.That(names, Does.Contain("enterprise-sso"));
            Assert.That(result.Value.CanSignIn, Is.True);
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldNormalizeCustomPolicyFactors()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));
        var service = CreateService(new StaticMfaPolicyEvaluator(true, [" custom-factor ", "custom_factor"]));

        var result = await service.GetUserSecurityPostureAsync(_userId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value?.Policy.RequiredFactorTypes, Is.EqualTo(ExpectedCustomFactor));
            Assert.That(result.Value?.Policy.MissingRequiredFactorDisplayNames, Is.EqualTo(ExpectedCustomFactor));
            Assert.That(result.Value?.Policy.IsLockedOutByPolicy, Is.True);
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldPassTenantContextIntoPolicyEvaluation()
    {
        var tenantId = Guid.NewGuid();
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true, TenantId = tenantId };
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));
        var evaluator = new CapturingMfaPolicyEvaluator();
        var service = CreateService(evaluator);

        var result = await service.GetUserSecurityPostureAsync(_userId, new UserSecurityPostureRequest(new TenantContext(tenantId)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(evaluator.Context?.TenantId, Is.EqualTo(tenantId));
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldClassifyRegisteredTotpProviderMetadata()
    {
        var configuredTotp = new AuthenticationProviderKey(ProviderType.Mfa, "authenticator");
        var registry = new AuthenticationProviderRegistry(
        [
            CreateSecondaryProvider(configuredTotp, AuthenticationFactorTypes.Totp).Object,
            CreateSecondaryProvider(new AuthenticationProviderKey(ProviderType.Mfa, "totp"), AuthenticationFactorTypes.Totp).Object
        ]);
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };
        _userRepository.Credentials.Add(CreateCredential(_userId, configuredTotp));
        _userRepository.Credentials.Add(CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.Mfa, "totp")));
        var service = new AccountSecurityService(
            _userRepository,
            _userRepository,
            Mock.Of<IAuthenticationSessionService>(s => s.ListSessionsForUserAsync(
                It.IsAny<Guid>(),
                It.IsAny<ListAuthenticationSessionsRequest>(),
                It.IsAny<CancellationToken>()) == Task.FromResult<IReadOnlyList<AuthenticationSessionSummary>>(Array.Empty<AuthenticationSessionSummary>())),
            new NullTransactionProvider(),
            new AllowAccountSecurityGuard(),
            new AccountSecurityServiceDependencies(
                _timeProvider,
                _events,
                _events,
                Options.Create(new TotpOptions { ProviderKey = configuredTotp }),
                ProviderRegistry: registry));

        var result = await service.GetUserSecurityPostureAsync(_userId);

        Assert.That(result.Value?.AdditionalVerificationFactors.Single().DisplayName, Is.EqualTo("Authenticator app"));
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldKeepUnavailableCredentialsInInventoryOnly()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };
        var revokedPasskey = CreateCredential(_userId, AuthenticationProviderKey.Passkey);
        revokedPasskey.Status = CredentialStatus.Revoked;
        revokedPasskey.RevokedAt = _timeProvider.GetUtcNow();
        var expiredTotp = CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.Mfa, "totp"));
        expiredTotp.ExpiresAt = _timeProvider.GetUtcNow().AddMinutes(-1);
        _userRepository.Credentials.Add(revokedPasskey);
        _userRepository.Credentials.Add(expiredTotp);
        var service = CreateService(new StaticMfaPolicyEvaluator(true, [AuthenticationFactorTypes.Totp]));

        var result = await service.GetUserSecurityPostureAsync(_userId);
        var totpFactor = result.Value?.AdditionalVerificationFactors.Single(factor => factor.FactorType == AuthenticationFactorTypes.Totp);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value?.CredentialInventory, Has.Count.EqualTo(2));
            Assert.That(result.Value?.CredentialInventory.All(item => !item.IsAvailable), Is.True);
            Assert.That(result.Value?.PrimaryCredentials.Select(item => item.DisplayName), Is.EqualTo(ExpectedEmailSignIn));
            Assert.That(totpFactor?.IsConfigured, Is.True);
            Assert.That(totpFactor?.IsUsable, Is.False);
            Assert.That(result.Value?.Policy.IsReadyForAdditionalVerification, Is.False);
            Assert.That(result.Value?.Policy.MissingRequiredFactorDisplayNames, Is.EqualTo(ExpectedAuthenticatorAppFactor));
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldNotAddEmailSignInForBlankEmail()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, Email = " ", IsActive = true };
        var service = CreateService();

        var result = await service.GetUserSecurityPostureAsync(_userId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.PrimaryCredentials, Is.Empty);
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
    public async Task GetUserSecurityPostureAsyncShouldReturnTenantMismatchForTenantMismatch()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true, TenantId = Guid.NewGuid() };

        var result = await _service.GetUserSecurityPostureAsync(_userId, new UserSecurityPostureRequest(new TenantContext(Guid.NewGuid())));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldOmitEventCountWhenWindowOrRepositoryMissing()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, Email = "user@example.com", IsActive = true };
        _userRepository.Credentials.Add(CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.RecoveryCode, "RecoveryCode")));
        var sessionService = new Mock<IAuthenticationSessionService>();
        sessionService
            .Setup(s => s.ListSessionsForUserAsync(_userId, It.IsAny<ListAuthenticationSessionsRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Array.Empty<AuthenticationSessionSummary>());
        var service = new AccountSecurityService(
            _userRepository,
            _userRepository,
            sessionService.Object,
            new NullTransactionProvider(),
            new AllowAccountSecurityGuard(),
            new AccountSecurityServiceDependencies(_timeProvider, _events, ProviderRegistry: CreateDefaultProviderRegistry()));

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
            Assert.Throws<ArgumentNullException>(() => _ = new AccountSecurityService(null!, _userRepository, Mock.Of<IAuthenticationSessionService>(), new NullTransactionProvider(), new AllowAccountSecurityGuard(), new AccountSecurityServiceDependencies()));
            Assert.Throws<ArgumentNullException>(() => _ = new AccountSecurityService(_userRepository, null!, Mock.Of<IAuthenticationSessionService>(), new NullTransactionProvider(), new AllowAccountSecurityGuard(), new AccountSecurityServiceDependencies()));
            Assert.Throws<ArgumentNullException>(() => _ = new AccountSecurityService(_userRepository, _userRepository, null!, new NullTransactionProvider(), new AllowAccountSecurityGuard(), new AccountSecurityServiceDependencies()));
            Assert.Throws<ArgumentNullException>(() => _ = new AccountSecurityService(_userRepository, _userRepository, Mock.Of<IAuthenticationSessionService>(), null!, new AllowAccountSecurityGuard(), new AccountSecurityServiceDependencies()));
            Assert.Throws<ArgumentNullException>(() => _ = new AccountSecurityService(_userRepository, _userRepository, Mock.Of<IAuthenticationSessionService>(), new NullTransactionProvider(), null!, new AccountSecurityServiceDependencies()));
            Assert.Throws<ArgumentNullException>(() => _ = new AccountSecurityService(_userRepository, _userRepository, Mock.Of<IAuthenticationSessionService>(), new NullTransactionProvider(), new AllowAccountSecurityGuard(), null!));
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

    private AccountSecurityService CreateService(
        IMfaPolicyEvaluator? mfaPolicyEvaluator = null,
        IAuthenticationProviderRegistry? providerRegistry = null)
    {
        return new AccountSecurityService(
            _userRepository,
            _userRepository,
            Mock.Of<IAuthenticationSessionService>(s => s.ListSessionsForUserAsync(
                It.IsAny<Guid>(),
                It.IsAny<ListAuthenticationSessionsRequest>(),
                It.IsAny<CancellationToken>()) == Task.FromResult<IReadOnlyList<AuthenticationSessionSummary>>(Array.Empty<AuthenticationSessionSummary>())),
            new NullTransactionProvider(),
            new AllowAccountSecurityGuard(),
            new AccountSecurityServiceDependencies(_timeProvider, _events, _events, MfaPolicyEvaluator: mfaPolicyEvaluator, ProviderRegistry: providerRegistry ?? CreateDefaultProviderRegistry()));
    }

    private static AuthenticationProviderRegistry CreateDefaultProviderRegistry()
    {
        return new AuthenticationProviderRegistry(
        [
            CreatePrimaryProvider(AuthenticationProviderKey.Local).Object,
            CreatePrimaryProvider(AuthenticationProviderKey.EmailCode).Object,
            CreatePrimaryProvider(AuthenticationProviderKey.MagicLink).Object,
            CreatePrimaryProvider(new AuthenticationProviderKey(ProviderType.OAuth, "github")).Object,
            CreatePrimaryProvider(new AuthenticationProviderKey(ProviderType.Oidc, "OIDC")).Object,
            CreatePrimaryProvider(new AuthenticationProviderKey(ProviderType.Saml2, "enterprise-sso")).Object,
            CreateSecondaryProvider(new AuthenticationProviderKey(ProviderType.Mfa, "totp"), AuthenticationFactorTypes.Totp).Object,
            CreateSecondaryProvider(new AuthenticationProviderKey(ProviderType.RecoveryCode, "RecoveryCode"), AuthenticationFactorTypes.RecoveryCode).Object,
            CreatePasskeyProvider().Object
        ]);
    }

    private static Mock<IPrimaryAuthenticationProvider> CreatePrimaryProvider(AuthenticationProviderKey providerKey)
    {
        var provider = new Mock<IPrimaryAuthenticationProvider>();
        provider.SetupGet(item => item.Key).Returns(providerKey);
        return provider;
    }

    private static Mock<IPrimaryAuthenticationProvider> CreatePasskeyProvider()
    {
        var provider = new Mock<IPrimaryAuthenticationProvider>();
        provider.SetupGet(item => item.Key).Returns(AuthenticationProviderKey.Passkey);
        provider.As<ISecondaryAuthenticationFactorProvider>()
            .SetupGet(item => item.Key)
            .Returns(AuthenticationProviderKey.Passkey);
        provider.As<ISecondaryAuthenticationFactorProvider>()
            .SetupGet(item => item.FactorType)
            .Returns(AuthenticationFactorTypes.Passkey);
        return provider;
    }

    private static Mock<ISecondaryAuthenticationFactorProvider> CreateSecondaryProvider(AuthenticationProviderKey providerKey, string factorType)
    {
        var provider = new Mock<ISecondaryAuthenticationFactorProvider>();
        provider.SetupGet(item => item.Key).Returns(providerKey);
        provider.SetupGet(item => item.FactorType).Returns(factorType);
        return provider;
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

    private sealed class StaticMfaPolicyEvaluator(bool isRequired, IReadOnlyList<string> requiredFactors) : IMfaPolicyEvaluator
    {
        public Task<MfaPolicyEvaluation> EvaluateAsync(IUser user, AuthenticationContext context, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(isRequired
                ? new MfaPolicyEvaluation(true, new MfaRequirement(requiredFactors))
                : new MfaPolicyEvaluation(false));
        }
    }

    private sealed class CapturingMfaPolicyEvaluator : IMfaPolicyEvaluator
    {
        public AuthenticationContext? Context { get; private set; }

        public Task<MfaPolicyEvaluation> EvaluateAsync(IUser user, AuthenticationContext context, CancellationToken cancellationToken = default)
        {
            Context = context;
            return Task.FromResult(new MfaPolicyEvaluation(false));
        }
    }

    private sealed record BasicUser(Guid Id, string Email, bool IsActive) : IUser
    {
        public string? Name => null;
        public DateTimeOffset? EmailVerifiedAt => null;
    }

    private sealed class InMemoryUserCredentialStore : IUserRepository, ICredentialRepository
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

        public Task<AuthenticationSession?> MarkStepUpVerifiedAsync(Guid sessionId, Guid userId, DateTimeOffset verifiedAt, AuthenticationProviderKey verifiedProvider, string verifiedFactor, CancellationToken cancellationToken = default)
        {
            var session = Sessions.FirstOrDefault(s => s.Id == sessionId && s.UserId == userId && s.IsActive(verifiedAt));
            if (session == null) return Task.FromResult<AuthenticationSession?>(null);
            session.AdditionalVerificationAt = verifiedAt;
            session.AdditionalVerificationProvider = verifiedProvider;
            session.AdditionalVerificationFactor = verifiedFactor;
            return Task.FromResult<AuthenticationSession?>(session);
        }

        public Task<bool> RevokeSessionAsync(Guid sessionId, DateTimeOffset revokedAt, string? reason = null, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Revoke(s => s.Id == sessionId, revokedAt, reason) == 1);
        }

        public Task<int> RevokeSessionsForUserAsync(Guid userId, DateTimeOffset revokedAt, string? reason = null, TenantContext? tenant = null, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Revoke(s => s.UserId == userId, revokedAt, reason));
        }

        public Task<IReadOnlyList<AuthenticationSession>> ListSessionsForUserAsync(Guid userId, bool activeOnly, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IReadOnlyList<AuthenticationSession>>(Sessions.Where(s => s.UserId == userId && (!activeOnly || s.IsActive(now))).ToList().AsReadOnly());
        }

        public Task<bool> RevokeSessionByIdAsync(Guid sessionId, Guid userId, DateTimeOffset revokedAt, string? reason = null, TenantContext? tenant = null, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Revoke(s => s.Id == sessionId && s.UserId == userId, revokedAt, reason) == 1);
        }

        public Task<int> RevokeOtherSessionsForUserAsync(Guid userId, Guid excludedSessionId, DateTimeOffset revokedAt, string? reason = null, TenantContext? tenant = null, CancellationToken cancellationToken = default)
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
