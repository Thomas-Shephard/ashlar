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
    private static readonly string[] ExpectedPasswordCredential = ["Password"];
    private static readonly string[] ExpectedCustomFactor = ["custom_factor"];
    private readonly Guid _userId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private FakeTimeProvider _timeProvider;
    private InMemoryUserCredentialStore _userRepository;
    private InMemorySessionRepository _sessionRepository;
    private RecordingSecurityEventSink _events;
    private DurableSecurityMutationTestComposition _sessionComposition;
    private AccountSecurityService _service;

    [SetUp]
    public void SetUp()
    {
        _timeProvider = new FakeTimeProvider(new DateTimeOffset(2026, 5, 17, 12, 0, 0, TimeSpan.Zero));
        _userRepository = new InMemoryUserCredentialStore();
        _sessionRepository = new InMemorySessionRepository();
        _events = new RecordingSecurityEventSink();
        _sessionComposition = new DurableSecurityMutationTestComposition(_events, _sessionRepository, _userRepository);
        var sessionService = new AuthenticationSessionService(
            _sessionRepository,
            Mock.Of<Ashlar.Security.Tokens.ISecureTokenHasher>(h => h.HashToken(It.IsAny<string>()) == "hash"),
            Mock.Of<Ashlar.Security.Tokens.ISecureTokenGenerator>(g => g.GenerateToken(It.IsAny<int>()) == "token"),
            _sessionComposition.Transactions,
            new AuthenticationSessionServiceDependencies(TimeProvider: _timeProvider, SecurityEventSink: _sessionComposition.Events, UserRepository: _userRepository));
        _service = new AccountSecurityService(
            _userRepository,
            _userRepository,
            sessionService,
            new AuthenticationSessionReader(_sessionRepository, _timeProvider),
            _sessionComposition.Transactions,
            new PermissiveAccountSecurityGuard(),
            new AccountSecurityServiceDependencies(_timeProvider, _sessionComposition.Events, _events, ProviderRegistry: CreateDefaultProviderRegistry()));
    }

    [Test]
    public async Task SetUserAccountStateAsyncToDisabledShouldDeactivateUserRevokeSessionsAndAudit()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
        _sessionRepository.Sessions.Add(CreateSession(_userId));

        var result = await _service.SetUserAccountStateAsync(_userId, CreateStateRequest(UserAccountState.Disabled, "risk"));
        var disabledEvent = _events.Events.Single(e => e.EventType == AshlarSecurityEventTypes.UserAccountStateChanged);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(_userRepository.Users[_userId].CanSignIn(), Is.False);
            Assert.That(_sessionRepository.Sessions.Single().RevokedAt, Is.EqualTo(_timeProvider.GetUtcNow()));
            Assert.That(result.Value?.SessionsRevoked, Is.EqualTo(1));
            Assert.That(result.Value?.PreviousState, Is.EqualTo(UserAccountState.Active));
            Assert.That(result.Value?.CurrentState, Is.EqualTo(UserAccountState.Disabled));
            Assert.That(disabledEvent.ActorUserId.HasValue, Is.True);
            Assert.That(disabledEvent.Properties?["from_account_state"], Is.EqualTo("active"));
            Assert.That(disabledEvent.Properties?["to_account_state"], Is.EqualTo("disabled"));
        }
    }

    [Test]
    public async Task SetUserAccountStateAsyncToDisabledShouldRevokeRememberedMfaDevices()
    {
        var tenantId = Guid.NewGuid();
        var request = CreateRequest("account-disabled", tenantId);
        var rememberedDevices = new TestRememberedMfaDeviceMutationExecutor();
        rememberedDevices.RevokeAllResult = 2;
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active, TenantId = tenantId };
        var service = new AccountSecurityService(
            _userRepository,
            _userRepository,
            new TestAuthenticationSessionMutationExecutor(),
            new TestAuthenticationSessionReader(),
            _sessionComposition.Transactions,
            new PermissiveAccountSecurityGuard(),
            new AccountSecurityServiceDependencies(_timeProvider, _sessionComposition.Events, _events, RememberedMfaDeviceService: rememberedDevices));

        var result = await service.SetUserAccountStateAsync(
            _userId,
            new SetUserAccountStateRequest(UserAccountState.Disabled, request.Audit, request.Tenant, request.Reason));
        var accountStateChangedEvent = _events.Events.Single(e => e.EventType == AshlarSecurityEventTypes.UserAccountStateChanged);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.RememberedMfaDevicesRevoked, Is.EqualTo(2));
            Assert.That(accountStateChangedEvent.Properties?["remembered_mfa_devices_revoked"], Is.EqualTo("2"));
        }

        using (Assert.EnterMultipleScope())
        {
            Assert.That(rememberedDevices.RevokeAllCalls, Is.EqualTo(1));
            Assert.That(rememberedDevices.LastRequest?.Tenant, Is.EqualTo(request.Tenant));
            Assert.That(rememberedDevices.LastRequest?.Reason, Is.EqualTo("account-disabled"));
            Assert.That(rememberedDevices.LastRequest?.Audit, Is.EqualTo(request.Audit));
        }
    }

    [TestCase(UserAccountState.Disabled)]
    [TestCase(UserAccountState.Locked)]
    [TestCase(UserAccountState.Suspended)]
    public async Task SetUserAccountStateAsyncShouldTransitionActiveUserToNonActiveState(UserAccountState targetState)
    {
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
        _sessionRepository.Sessions.Add(CreateSession(_userId));

        var result = await _service.SetUserAccountStateAsync(_userId, CreateStateRequest(targetState, "security-review"));
        var stateChangedEvent = _events.Events.Single(e => e.EventType == AshlarSecurityEventTypes.UserAccountStateChanged);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(_userRepository.Users[_userId].AccountState, Is.EqualTo(targetState));
            Assert.That(_sessionRepository.Sessions.Single().RevocationReason, Is.EqualTo("security-review"));
            Assert.That(result.Value?.UserChanged, Is.True);
            Assert.That(result.Value?.SessionsRevoked, Is.EqualTo(1));
            Assert.That(result.Value?.PreviousState, Is.EqualTo(UserAccountState.Active));
            Assert.That(result.Value?.CurrentState, Is.EqualTo(targetState));
            Assert.That(stateChangedEvent.Properties?["from_account_state"], Is.EqualTo("active"));
            Assert.That(stateChangedEvent.Properties?["to_account_state"], Is.EqualTo(targetState.ToStorageValue()));
            Assert.That(stateChangedEvent.Properties?["remembered_mfa_devices_revoked"], Is.EqualTo("0"));
        }
    }

    [Test]
    public async Task SetUserAccountStateAsyncShouldReturnUserNotFoundForMissingUser()
    {
        var result = await _service.SetUserAccountStateAsync(_userId, CreateStateRequest(UserAccountState.Locked));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(_events.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.UserAccountStateChanged));
            Assert.That(_events.Events.Single().Properties?["to_account_state"], Is.EqualTo("locked"));
        }
    }

    [Test]
    public async Task SetUserAccountStateAsyncShouldReturnTenantMismatchForTenantMismatch()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active, TenantId = Guid.NewGuid() };
        _sessionRepository.Sessions.Add(CreateSession(_userId));
        var requestedTenantId = Guid.NewGuid();

        var result = await _service.SetUserAccountStateAsync(_userId, CreateStateRequest(UserAccountState.Suspended, tenantId: requestedTenantId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            Assert.That(_userRepository.Users[_userId].AccountState, Is.EqualTo(UserAccountState.Active));
            Assert.That(_sessionRepository.Sessions.Single().RevokedAt, Is.Null);
            Assert.That(_events.Events.Single().TenantId, Is.EqualTo(requestedTenantId));
            Assert.That(_events.Events.Single().Properties?["to_account_state"], Is.EqualTo("suspended"));
        }
    }

    [TestCase(UserAccountState.Disabled)]
    [TestCase(UserAccountState.Locked)]
    [TestCase(UserAccountState.Suspended)]
    public async Task SetUserAccountStateAsyncShouldReactivateNonActiveUserWithoutRevokingSessionsOrCredentials(UserAccountState previousState)
    {
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = previousState };
        _sessionRepository.Sessions.Add(CreateSession(_userId));
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));

        var result = await _service.SetUserAccountStateAsync(_userId, CreateStateRequest(UserAccountState.Active));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(_userRepository.Users[_userId].AccountState, Is.EqualTo(UserAccountState.Active));
            Assert.That(_sessionRepository.Sessions.Single().RevokedAt, Is.Null);
            Assert.That(_userRepository.Credentials.Single().RevokedAt, Is.Null);
            Assert.That(result.Value?.SessionsRevoked, Is.Zero);
            Assert.That(result.Value?.CredentialsRevoked, Is.Zero);
            Assert.That(result.Value?.PreviousState, Is.EqualTo(previousState));
            Assert.That(result.Value?.CurrentState, Is.EqualTo(UserAccountState.Active));
        }
    }

    [Test]
    public async Task SetUserAccountStateAsyncShouldRespectExplicitNoRevocationBehavior()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
        var sessionService = new TestAuthenticationSessionMutationExecutor();
        var rememberedDevices = new TestRememberedMfaDeviceMutationExecutor();
        var request = CreateStateRequest(UserAccountState.Suspended, revokeSessionsAndRememberedMfaDevices: false);
        var service = new AccountSecurityService(
            _userRepository,
            _userRepository,
            sessionService,
            new TestAuthenticationSessionReader(),
            _sessionComposition.Transactions,
            new PermissiveAccountSecurityGuard(),
            new AccountSecurityServiceDependencies(_timeProvider, _sessionComposition.Events, _events, RememberedMfaDeviceService: rememberedDevices));

        var result = await service.SetUserAccountStateAsync(_userId, request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(_userRepository.Users[_userId].AccountState, Is.EqualTo(UserAccountState.Suspended));
            Assert.That(result.Value?.SessionsRevoked, Is.Zero);
            Assert.That(result.Value?.RememberedMfaDevicesRevoked, Is.Zero);
        }

        using (Assert.EnterMultipleScope())
        {
            Assert.That(sessionService.RevokeCalls, Is.Zero);
            Assert.That(rememberedDevices.RevokeAllCalls, Is.Zero);
        }
    }

    [Test]
    public async Task SetUserAccountStateAsyncShouldNotRevokeCredentialsWhenTransitioningToNonActiveState()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));

        var result = await _service.SetUserAccountStateAsync(_userId, CreateStateRequest(UserAccountState.Locked));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.CredentialsRevoked, Is.Zero);
            Assert.That(_userRepository.Credentials.Single().RevokedAt, Is.Null);
        }
    }

    [Test]
    public async Task SetUserAccountStateAsyncToDisabledShouldUseSessionServiceNotifications()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
        _sessionRepository.Sessions.Add(CreateSession(_userId));
        var notifications = new Mock<ISecurityNotificationService>();
        var sessionService = new AuthenticationSessionService(
            _sessionRepository,
            Mock.Of<Ashlar.Security.Tokens.ISecureTokenHasher>(h => h.HashToken(It.IsAny<string>()) == "hash"),
            Mock.Of<Ashlar.Security.Tokens.ISecureTokenGenerator>(g => g.GenerateToken(It.IsAny<int>()) == "token"),
            _sessionComposition.Transactions,
            new AuthenticationSessionServiceDependencies(
                TimeProvider: _timeProvider,
                SecurityEventSink: _sessionComposition.Events,
                UserRepository: _userRepository,
                NotificationService: notifications.Object));
        var service = new AccountSecurityService(
            _userRepository,
            _userRepository,
            sessionService,
            new TestAuthenticationSessionReader(),
            _sessionComposition.Transactions,
            new PermissiveAccountSecurityGuard(),
            new AccountSecurityServiceDependencies(_timeProvider, _sessionComposition.Events, _events));

        var result = await service.SetUserAccountStateAsync(_userId, CreateStateRequest(UserAccountState.Disabled, "risk"));

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
    public async Task SetUserAccountStateAsyncToDisabledShouldReturnGuardFailureWhenGuardRejectsOperation()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
        var service = new AccountSecurityService(
            _userRepository,
            _userRepository,
            new TestAuthenticationSessionMutationExecutor(),
            new TestAuthenticationSessionReader(),
            _sessionComposition.Transactions,
            new RejectingAccountSecurityGuard(),
            new AccountSecurityServiceDependencies(_timeProvider, _sessionComposition.Events, _events));

        var result = await service.SetUserAccountStateAsync(_userId, CreateStateRequest(UserAccountState.Disabled));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(new AshlarFailureCode("guard_rejected")));
            Assert.That(_userRepository.Users[_userId].CanSignIn(), Is.True);
            Assert.That(_events.Events.Single().FailureReason, Is.EqualTo("guard_rejected"));
        }
    }

    [Test]
    public async Task SetUserAccountStateAsyncToDisabledShouldReturnUserNotFoundForMissingUser()
    {
        var result = await _service.SetUserAccountStateAsync(_userId, CreateStateRequest(UserAccountState.Disabled));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(_events.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.UserAccountStateChanged));
        }
    }

    [Test]
    public async Task SetUserAccountStateAsyncToDisabledShouldReturnTenantMismatchForTenantMismatch()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active, TenantId = Guid.NewGuid() };
        _sessionRepository.Sessions.Add(CreateSession(_userId));
        var requestedTenantId = Guid.NewGuid();

        var result = await _service.SetUserAccountStateAsync(_userId, CreateStateRequest(UserAccountState.Disabled, tenantId: requestedTenantId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            Assert.That(_userRepository.Users[_userId].CanSignIn(), Is.True);
            Assert.That(_sessionRepository.Sessions.Single().RevokedAt, Is.Null);
            Assert.That(_events.Events.Single().FailureReason, Is.EqualTo(AshlarFailureCodes.TenantMismatch.Value));
            Assert.That(_events.Events.Single().TenantId, Is.EqualTo(requestedTenantId));
        }
    }

    [Test]
    public async Task SetUserAccountStateAsyncToDisabledShouldAllowMatchingTenant()
    {
        var tenantId = Guid.NewGuid();
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active, TenantId = tenantId };

        var result = await _service.SetUserAccountStateAsync(_userId, CreateStateRequest(UserAccountState.Disabled, tenantId: tenantId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(_userRepository.Users[_userId].CanSignIn(), Is.False);
            Assert.That(_events.Events.Any(e => e.EventType == AshlarSecurityEventTypes.UserAccountStateChanged && e.TenantId == tenantId), Is.True);
        }
    }

    [Test]
    public async Task SetUserAccountStateAsyncToDisabledShouldReturnTenantMismatchWhenTenantScopeTargetsGlobalUser()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };

        var result = await _service.SetUserAccountStateAsync(_userId, CreateStateRequest(UserAccountState.Disabled, tenantId: Guid.NewGuid()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            Assert.That(_userRepository.Users[_userId].CanSignIn(), Is.True);
        }
    }

    [Test]
    public async Task SetUserAccountStateAsyncToDisabledShouldTreatMissingTenantAsGlobalOnly()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active, TenantId = Guid.NewGuid() };

        var result = await _service.SetUserAccountStateAsync(_userId, CreateStateRequest(UserAccountState.Disabled));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            Assert.That(_userRepository.Users[_userId].CanSignIn(), Is.True);
            Assert.That(_events.Events.Single().TenantId, Is.Null);
            Assert.That(_events.Events.Single().FailureReason, Is.EqualTo(AshlarFailureCodes.TenantMismatch.Value));
        }
    }

    [Test]
    public async Task SetUserAccountStateAsyncToDisabledShouldAllowExplicitGlobalTenantForGlobalUser()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };

        var result = await _service.SetUserAccountStateAsync(_userId, new SetUserAccountStateRequest(UserAccountState.Disabled, new AuditContext(Guid.NewGuid()), TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(_userRepository.Users[_userId].CanSignIn(), Is.False);
        }
    }

    [Test]
    public async Task SetUserAccountStateAsyncToDisabledShouldNoopForAlreadyDisabledUserWithoutRevokingSessions()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Disabled };
        var sessionService = new TestAuthenticationSessionMutationExecutor();
        var rememberedDevices = new TestRememberedMfaDeviceMutationExecutor();
        var service = new AccountSecurityService(
            _userRepository,
            _userRepository,
            sessionService,
            new AuthenticationSessionReader(_sessionRepository, _timeProvider),
            _sessionComposition.Transactions,
            new PermissiveAccountSecurityGuard(),
            new AccountSecurityServiceDependencies(_timeProvider, _sessionComposition.Events, _events, RememberedMfaDeviceService: rememberedDevices));

        var result = await service.SetUserAccountStateAsync(_userId, CreateStateRequest(UserAccountState.Disabled));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.UserChanged, Is.False);
            Assert.That(result.Value?.SessionsRevoked, Is.Zero);
            Assert.That(result.Value?.RememberedMfaDevicesRevoked, Is.Zero);
        }

        using (Assert.EnterMultipleScope())
        {
            Assert.That(sessionService.RevokeCalls, Is.Zero);
            Assert.That(rememberedDevices.RevokeAllCalls, Is.Zero);
        }
    }

    [Test]
    public async Task SetUserAccountStateAsyncToDisabledShouldUseValidationErrorWhenGuardFailureHasNoDetails()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
        var service = new AccountSecurityService(
            _userRepository,
            _userRepository,
            new TestAuthenticationSessionMutationExecutor(),
            new TestAuthenticationSessionReader(),
            _sessionComposition.Transactions,
            new EmptyFailureAccountSecurityGuard(),
            new AccountSecurityServiceDependencies(_timeProvider, _sessionComposition.Events, _events));

        var result = await service.SetUserAccountStateAsync(_userId, CreateStateRequest(UserAccountState.Disabled));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(_events.Events.Single().FailureReason, Is.EqualTo(AshlarFailureCodes.ValidationError.Value));
        }
    }

    [Test]
    public async Task SetUserAccountStateAsyncToActiveShouldReactivateWithoutRevokingCredentials()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Disabled };
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));

        var result = await _service.SetUserAccountStateAsync(_userId, CreateStateRequest(UserAccountState.Active));
        var reactivatedEvent = _events.Events.Single(e => e.EventType == AshlarSecurityEventTypes.UserAccountStateChanged);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(_userRepository.Users[_userId].CanSignIn(), Is.True);
            Assert.That(_userRepository.Credentials.Single().RevokedAt, Is.Null);
            Assert.That(result.Value?.PreviousState, Is.EqualTo(UserAccountState.Disabled));
            Assert.That(result.Value?.CurrentState, Is.EqualTo(UserAccountState.Active));
            Assert.That(reactivatedEvent.Properties?["from_account_state"], Is.EqualTo("disabled"));
            Assert.That(reactivatedEvent.Properties?["to_account_state"], Is.EqualTo("active"));
        }
    }

    [Test]
    public async Task SetUserAccountStateAsyncToActiveShouldReturnUserNotFoundForMissingUser()
    {
        var result = await _service.SetUserAccountStateAsync(_userId, CreateStateRequest(UserAccountState.Active));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(_events.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.UserAccountStateChanged));
        }
    }

    [Test]
    public async Task SetUserAccountStateAsyncToActiveShouldReturnTenantMismatchForTenantMismatch()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Disabled, TenantId = Guid.NewGuid() };

        var result = await _service.SetUserAccountStateAsync(_userId, CreateStateRequest(UserAccountState.Active, tenantId: Guid.NewGuid()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            Assert.That(_userRepository.Users[_userId].CanSignIn(), Is.False);
        }
    }

    [Test]
    public async Task SetUserAccountStateAsyncToActiveShouldNoopForActiveUser()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };

        var result = await _service.SetUserAccountStateAsync(_userId, CreateStateRequest(UserAccountState.Active, "manual-review"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.UserChanged, Is.False);
            Assert.That(_events.Events.Single().Properties?["reason"], Is.EqualTo("manual-review"));
            Assert.That(_events.Events.Single().Properties?["from_account_state"], Is.EqualTo("active"));
            Assert.That(_events.Events.Single().Properties?["to_account_state"], Is.EqualTo("active"));
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
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active, TenantId = Guid.NewGuid() };
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
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
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
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));

        var result = await _service.RevokeCredentialsAsync(_userId, AuthenticationProviderKey.Local, CreateRequest("rotation"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.CredentialsRevoked, Is.EqualTo(1));
            Assert.That(_userRepository.MutationLockCalls, Is.EqualTo(1));
            Assert.That(_userRepository.Credentials.Single().RevokedAt, Is.Not.Null);
            Assert.That(_events.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.UserCredentialsRevoked));
        }
    }

    [Test]
    public async Task RevokeCredentialsAsyncShouldPreserveLastPrimarySignInMethodWhenRequested()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));

        var result = await _service.RevokeCredentialsAsync(
            _userId,
            AuthenticationProviderKey.Local,
            CreateRequest(preservePrimarySignInMethod: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.LastPrimarySignInMethod));
            Assert.That(_userRepository.MutationLockCalls, Is.EqualTo(1));
            Assert.That(_userRepository.Credentials.Single().RevokedAt, Is.Null);
            Assert.That(_events.Events.Single().FailureReason, Is.EqualTo(AshlarFailureCodes.LastPrimarySignInMethodValue));
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
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active, TenantId = Guid.NewGuid() };
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
    public async Task RevokeCredentialsAsyncShouldFailWithoutMutationWhenUserLeavesScopeAfterLock()
    {
        var tenantId = Guid.NewGuid();
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active, TenantId = tenantId };
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));
        _userRepository.OnMutationLock = () => _userRepository.Users[_userId].TenantId = Guid.NewGuid();

        var result = await _service.RevokeCredentialsAsync(_userId, AuthenticationProviderKey.Local, CreateRequest(tenantId: tenantId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            Assert.That(_userRepository.Credentials.Single().RevokedAt, Is.Null);
        }
    }

    [Test]
    public async Task RevokeCredentialsAsyncShouldRecognizeEveryBuiltInPrimaryProviderType()
    {
        var providers = new[]
        {
            AuthenticationProviderKey.Local,
            AuthenticationProviderKey.EmailCode,
            AuthenticationProviderKey.MagicLink,
            AuthenticationProviderKey.Passkey,
            new AuthenticationProviderKey(ProviderType.OAuth, "github"),
            new AuthenticationProviderKey(ProviderType.Oidc, "OIDC"),
            new AuthenticationProviderKey(ProviderType.Saml2, "enterprise-sso")
        };
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
        foreach (var provider in providers)
            _userRepository.Credentials.Add(CreateCredential(_userId, provider));

        foreach (var provider in providers[..^1])
        {
            var result = await _service.RevokeCredentialsAsync(_userId, provider, CreateRequest(preservePrimarySignInMethod: true));
            Assert.That(result.Succeeded, Is.True, provider.ToString());
        }
        Assert.That((await _service.RevokeCredentialsAsync(_userId, providers[^1], CreateRequest(preservePrimarySignInMethod: true))).FailureCode,
            Is.EqualTo(AshlarFailureCodes.LastPrimarySignInMethod));
    }

    [Test]
    public void RevokeCredentialsAsyncShouldRejectUninitializedProvider()
    {
        Assert.ThrowsAsync<ArgumentException>(() => _service.RevokeCredentialsAsync(_userId, default, CreateRequest()));
    }

    [Test]
    public void RevokeCredentialsAsyncShouldRejectUnknownProviderTypeBeforeMutation()
    {
        var provider = new AuthenticationProviderKey((ProviderType)ProviderType.StorageFallbackValue, "unknown");
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
        _userRepository.Credentials.Add(CreateCredential(_userId, provider));

        Assert.ThrowsAsync<ArgumentException>(() => _service.RevokeCredentialsAsync(_userId, provider, CreateRequest()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(_userRepository.Credentials.Single().RevokedAt, Is.Null);
            Assert.That(_events.Events, Is.Empty);
        }
    }

    [Test]
    public void RevokeCredentialsAsyncShouldRejectInternalProviderBeforeMutation()
    {
        var provider = new AuthenticationProviderKey(ProviderType.Internal, "password-reset");
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
        _userRepository.Credentials.Add(CreateCredential(_userId, provider));

        Assert.ThrowsAsync<ArgumentException>(() => _service.RevokeCredentialsAsync(_userId, provider, CreateRequest()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(_userRepository.Credentials.Single().RevokedAt, Is.Null);
            Assert.That(_events.Events, Is.Empty);
        }
    }

    [Test]
    public async Task ResetMfaAsyncShouldRevokeTotpAndRecoveryCodeCredentialsOnly()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
        _userRepository.Credentials.Add(CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.Mfa, "totp")));
        _userRepository.Credentials.Add(CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.RecoveryCode, "RecoveryCode")));
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));

        var result = await _service.ResetMfaAsync(_userId, CreateRequest("lost-device"));
        var resetEvent = _events.Events.Single(e => e.EventType == AshlarSecurityEventTypes.UserMfaReset);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.CredentialsRevoked, Is.EqualTo(2));
            Assert.That(result.Value?.RememberedMfaDevicesRevoked, Is.Zero);
            Assert.That(_userRepository.Credentials.Count(c => c.RevokedAt.HasValue), Is.EqualTo(2));
            Assert.That(_userRepository.Credentials.Single(c => c.ProviderType == ProviderType.Local).RevokedAt, Is.Null);
            Assert.That(resetEvent.Properties?["credentials_revoked"], Is.EqualTo("2"));
            Assert.That(resetEvent.Properties?["remembered_mfa_devices_revoked"], Is.EqualTo("0"));
        }
    }

    [Test]
    public async Task ResetMfaAsyncShouldReportRememberedMfaDevicesRevoked()
    {
        var tenantId = Guid.NewGuid();
        var request = CreateRequest("mfa-reset", tenantId);
        var rememberedDevices = new TestRememberedMfaDeviceMutationExecutor();
        rememberedDevices.RevokeAllResult = 3;
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active, TenantId = tenantId };
        var service = new AccountSecurityService(
            _userRepository,
            _userRepository,
            new TestAuthenticationSessionMutationExecutor(),
            new TestAuthenticationSessionReader(),
            _sessionComposition.Transactions,
            new PermissiveAccountSecurityGuard(),
            new AccountSecurityServiceDependencies(_timeProvider, _sessionComposition.Events, _events, RememberedMfaDeviceService: rememberedDevices));

        var result = await service.ResetMfaAsync(_userId, request);
        var resetEvent = _events.Events.Single(e => e.EventType == AshlarSecurityEventTypes.UserMfaReset);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.RememberedMfaDevicesRevoked, Is.EqualTo(3));
            Assert.That(resetEvent.Properties?["remembered_mfa_devices_revoked"], Is.EqualTo("3"));
        }

        using (Assert.EnterMultipleScope())
        {
            Assert.That(rememberedDevices.RevokeAllCalls, Is.EqualTo(1));
            Assert.That(rememberedDevices.LastRequest?.Tenant, Is.EqualTo(request.Tenant));
            Assert.That(rememberedDevices.LastRequest?.Reason, Is.EqualTo("mfa-reset"));
            Assert.That(rememberedDevices.LastRequest?.Audit, Is.EqualTo(request.Audit));
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
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active, TenantId = Guid.NewGuid() };
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
    public async Task ResetMfaAsyncShouldFailWithoutMutationWhenUserDisappearsAfterLock()
    {
        var tenantId = Guid.NewGuid();
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active, TenantId = tenantId };
        _userRepository.Credentials.Add(CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.Mfa, "totp")));
        _userRepository.OnMutationLock = () => _userRepository.Users.Remove(_userId);

        var result = await _service.ResetMfaAsync(_userId, CreateRequest(tenantId: tenantId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(_userRepository.Credentials.Single().RevokedAt, Is.Null);
        }
    }

    [Test]
    public async Task ResetMfaAsyncShouldUseConfiguredProviderKeys()
    {
        var totpProvider = new AuthenticationProviderKey(ProviderType.Mfa, "custom-totp");
        var recoveryProvider = new AuthenticationProviderKey(ProviderType.RecoveryCode, "custom-recovery");
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
        _userRepository.Credentials.Add(CreateCredential(_userId, totpProvider));
        _userRepository.Credentials.Add(CreateCredential(_userId, recoveryProvider));
        var service = new AccountSecurityService(
            _userRepository,
            _userRepository,
            new TestAuthenticationSessionMutationExecutor(),
            new TestAuthenticationSessionReader(),
            _sessionComposition.Transactions,
            new PermissiveAccountSecurityGuard(),
            new AccountSecurityServiceDependencies(
                _timeProvider,
                _sessionComposition.Events,
                _events,
                Options.Create(new TotpOptions { ProviderKey = totpProvider }),
                Options.Create(new RecoveryCodeOptions { ProviderKey = recoveryProvider })));

        var result = await service.ResetMfaAsync(_userId, CreateRequest());

        Assert.That(result.Value?.CredentialsRevoked, Is.EqualTo(2));
    }

    [Test]
    public async Task SetUserAccountStateAsyncToDisabledShouldSupportUsersWithoutTenantInterface()
    {
        var repository = new Mock<IUserRepository>();
        repository
            .Setup(r => r.GetUserByIdAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new BasicUser(_userId, "basic@example.com", UserAccountState.Active));
        var credentials = Mock.Of<ICredentialRepository>();
        var composition = new DurableSecurityMutationTestComposition(_events, repository.Object, credentials);
        var service = new AccountSecurityService(
            repository.Object,
            credentials,
            new TestAuthenticationSessionMutationExecutor(),
            new TestAuthenticationSessionReader(),
            composition.Transactions,
            new PermissiveAccountSecurityGuard(),
            new AccountSecurityServiceDependencies(SecurityEventSink: composition.Events));

        var result = await service.SetUserAccountStateAsync(_userId, CreateStateRequest(UserAccountState.Disabled));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            repository.Verify(r => r.UpdateUserAsync(It.Is<IUser>(u => ((ITenantUser)u).TenantId == null), It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [Test]
    public async Task SetUserAccountStateAsyncToDisabledShouldReturnTenantMismatchForTenantScopedRequestWhenUserHasNoTenantInterface()
    {
        var repository = new Mock<IUserRepository>();
        repository
            .Setup(r => r.GetUserByIdAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new BasicUser(_userId, "basic@example.com", UserAccountState.Active));
        var credentials = Mock.Of<ICredentialRepository>();
        var composition = new DurableSecurityMutationTestComposition(_events, repository.Object, credentials);
        var service = new AccountSecurityService(
            repository.Object,
            credentials,
            new TestAuthenticationSessionMutationExecutor(),
            new TestAuthenticationSessionReader(),
            composition.Transactions,
            new PermissiveAccountSecurityGuard(),
            new AccountSecurityServiceDependencies(_timeProvider, composition.Events, _events));

        var result = await service.SetUserAccountStateAsync(_userId, CreateStateRequest(UserAccountState.Disabled, tenantId: Guid.NewGuid()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldReturnNonSecretSummary()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active, EmailVerifiedAt = _timeProvider.GetUtcNow() };
        var localCredential = CreateCredential(_userId, AuthenticationProviderKey.Local);
        localCredential.CredentialValue = "secret";
        var mfaCredential = CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.Mfa, "totp"));
        mfaCredential.CredentialValue = "secret";
        _userRepository.Credentials.Add(localCredential);
        _userRepository.Credentials.Add(mfaCredential);
        _sessionRepository.Sessions.Add(CreateSession(_userId));
        await _events.RecordAsync(new AshlarSecurityEvent { Id = Guid.NewGuid(), EventType = "test", UserId = _userId, OccurredAt = _timeProvider.GetUtcNow() });

        var result = await _service.GetUserSecurityPostureAsync(_userId, new AccountSecurityPostureRequest(RecentSecurityEventWindow: TimeSpan.FromDays(1)));
        _events.CountOverride = -1;
        var hostileCount = await _service.GetUserSecurityPostureAsync(
            _userId, new AccountSecurityPostureRequest(RecentSecurityEventWindow: TimeSpan.FromDays(1)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.CanSignIn, Is.True);
            Assert.That(result.Value?.IsEmailVerified, Is.True);
            Assert.That(result.Value?.IsMfaConfigured, Is.True);
            Assert.That(result.Value?.ActiveSessionCount, Is.EqualTo(1));
            Assert.That(result.Value?.RecentSecurityEventCount, Is.EqualTo(1));
            Assert.That(hostileCount.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(result.Value?.GetConfiguredCredentials(), Has.Count.EqualTo(2));
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldClassifyEmailSignInOnly()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };

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
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
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
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
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
    public async Task GetUserSecurityPostureAsyncShouldNotTreatRememberedMfaDevicesAsCredentialsOrFactors()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));
        var rememberedDevice = CreateRememberedMfaDevice(_userId);
        var service = CreateService(
            new StaticMfaPolicyEvaluator(true, []),
            new AuthenticationProviderRegistry(
            [
                CreatePrimaryProvider(AuthenticationProviderKey.Local).Object,
                CreateSecondaryProvider(new AuthenticationProviderKey(ProviderType.Mfa, rememberedDevice.DisplayName!), "remembered_device").Object
            ]));

        var result = await service.GetUserSecurityPostureAsync(_userId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(rememberedDevice.UserId, Is.EqualTo(_userId));
            Assert.That(rememberedDevice, Is.Not.InstanceOf<UserCredential>());
            Assert.That(rememberedDevice, Is.Not.InstanceOf<IAuthenticationProvider>());
            Assert.That(rememberedDevice, Is.Not.InstanceOf<ISecondaryAuthenticationFactorProvider>());
            Assert.That(result.Value?.CredentialInventory.Select(item => item.DisplayName), Is.EqualTo(ExpectedPasswordCredential));
            Assert.That(result.Value?.AdditionalVerificationFactors, Is.Empty);
            Assert.That(result.Value?.IsMfaConfigured, Is.False);
            Assert.That(result.Value?.Policy.HasUsableAdditionalVerificationFactor, Is.False);
            Assert.That(result.Value?.Policy.IsReadyForAdditionalVerification, Is.False);
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldTreatPasskeyAsPrimaryAndNotImplicitTwoFactorPolicy()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
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
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
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
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
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
    public async Task GetUserSecurityPostureAsyncShouldAllowRecoveryCodesAsBackupForRequiredTotp()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));
        _userRepository.Credentials.Add(CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.RecoveryCode, "RecoveryCode")));
        var recoveryProvider = CreateBackupProvider(
            new AuthenticationProviderKey(ProviderType.RecoveryCode, "RecoveryCode"),
            AuthenticationFactorTypes.RecoveryCode,
            factorType => AuthenticationFactorTypes.Matches(AuthenticationFactorTypes.Totp, factorType));
        var service = CreateService(
            new StaticMfaPolicyEvaluator(true, [AuthenticationFactorTypes.Totp]),
            CreateDefaultProviderRegistry(includeRecoveryCodeProvider: false, recoveryProvider.Object));

        var result = await service.GetUserSecurityPostureAsync(_userId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value?.Policy.IsAdditionalVerificationRequired, Is.True);
            Assert.That(result.Value?.Policy.HasUsableAdditionalVerificationFactor, Is.True);
            Assert.That(result.Value?.Policy.IsReadyForAdditionalVerification, Is.True);
            Assert.That(result.Value?.Policy.MissingRequiredFactorTypes, Is.Empty);
            Assert.That(result.Value?.CanSignIn, Is.True);
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldReportMissingTotpWhenRecoveryCodeProviderIsNotRegistered()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));
        _userRepository.Credentials.Add(CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.RecoveryCode, "RecoveryCode")));
        var service = CreateService(
            new StaticMfaPolicyEvaluator(true, [AuthenticationFactorTypes.Totp]),
            includeDefaultProviderRegistry: false);

        var result = await service.GetUserSecurityPostureAsync(_userId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value?.Policy.IsReadyForAdditionalVerification, Is.False);
            Assert.That(result.Value?.Policy.MissingRequiredFactorTypes, Is.EqualTo(new[] { AuthenticationFactorTypes.Totp }));
            Assert.That(result.Value?.CanSignIn, Is.False);
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldReportMissingTotpWhenBackupProviderCannotSatisfyIt()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));
        _userRepository.Credentials.Add(CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.RecoveryCode, "RecoveryCode")));
        var recoveryProvider = CreateBackupProvider(
            new AuthenticationProviderKey(ProviderType.RecoveryCode, "RecoveryCode"),
            AuthenticationFactorTypes.RecoveryCode,
            factorType => AuthenticationFactorTypes.Matches(AuthenticationFactorTypes.Passkey, factorType));
        var service = CreateService(
            new StaticMfaPolicyEvaluator(true, [AuthenticationFactorTypes.Totp]),
            CreateDefaultProviderRegistry(includeRecoveryCodeProvider: false, recoveryProvider.Object));

        var result = await service.GetUserSecurityPostureAsync(_userId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value?.Policy.IsReadyForAdditionalVerification, Is.False);
            Assert.That(result.Value?.Policy.MissingRequiredFactorTypes, Is.EqualTo(new[] { AuthenticationFactorTypes.Totp }));
            Assert.That(result.Value?.CanSignIn, Is.False);
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldAllowPasskeyAsAdditionalVerificationWhenPolicyRequiresIt()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
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
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
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
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
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
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));
        _userRepository.Credentials.Add(CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.Mfa, "totp")));
        var service = CreateService(new StaticMfaPolicyEvaluator(true, [AuthenticationFactorTypes.Totp]));

        var result = await service.GetUserSecurityPostureAsync(_userId);

        Assert.That(result.Value?.Policy.AllowedFactorTypes, Is.Empty);
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldReportDisabledUserCannotSignIn()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Disabled };
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));

        var result = await _service.GetUserSecurityPostureAsync(_userId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value?.CanSignIn, Is.False);
            Assert.That(result.Value?.CanSignIn, Is.False);
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldClassifyUnknownProviderSafely()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
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
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "", AccountState = UserAccountState.Active };
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
            new TestAuthenticationSessionMutationExecutor(),
            new TestAuthenticationSessionReader(),
            _sessionComposition.Transactions,
            new PermissiveAccountSecurityGuard(),
            new AccountSecurityServiceDependencies(_timeProvider, _sessionComposition.Events, _events));
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "", AccountState = UserAccountState.Active };
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
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "", AccountState = UserAccountState.Active };
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
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "", AccountState = UserAccountState.Active };
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
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
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
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
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
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active, TenantId = tenantId };
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));
        var evaluator = new CapturingMfaPolicyEvaluator();
        var service = CreateService(evaluator);

        var result = await service.GetUserSecurityPostureAsync(_userId, new AccountSecurityPostureRequest(new TenantContext(tenantId)));

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
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
        _userRepository.Credentials.Add(CreateCredential(_userId, configuredTotp));
        _userRepository.Credentials.Add(CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.Mfa, "totp")));
        var service = new AccountSecurityService(
            _userRepository,
            _userRepository,
            new TestAuthenticationSessionMutationExecutor(),
            new TestAuthenticationSessionReader(),
            _sessionComposition.Transactions,
            new PermissiveAccountSecurityGuard(),
            new AccountSecurityServiceDependencies(
                _timeProvider,
                _sessionComposition.Events,
                _events,
                Options.Create(new TotpOptions { ProviderKey = configuredTotp }),
                ProviderRegistry: registry));

        var result = await service.GetUserSecurityPostureAsync(_userId);

        Assert.That(result.Value?.AdditionalVerificationFactors.Single().DisplayName, Is.EqualTo("Authenticator app"));
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldKeepUnavailableCredentialsInInventoryOnly()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
        var revokedPasskey = CreateCredential(_userId, AuthenticationProviderKey.Passkey);
        revokedPasskey.Status = CredentialStatus.Revoked;
        revokedPasskey.RevokedAt = _timeProvider.GetUtcNow();
        var expiredTotp = CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.Mfa, "totp"),
            createdAt: _timeProvider.GetUtcNow().AddHours(-1),
            expiresAt: _timeProvider.GetUtcNow().AddMinutes(-1));
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
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = " ", AccountState = UserAccountState.Active };
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
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active, TenantId = Guid.NewGuid() };

        var result = await _service.GetUserSecurityPostureAsync(_userId, new AccountSecurityPostureRequest(new TenantContext(Guid.NewGuid())));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
        }
    }

    [Test]
    public async Task GetUserSecurityPostureAsyncShouldOmitEventCountWhenWindowOrRepositoryMissing()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
        _userRepository.Credentials.Add(CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.RecoveryCode, "RecoveryCode")));
        var sessionService = new TestAuthenticationSessionMutationExecutor();
        var service = new AccountSecurityService(
            _userRepository,
            _userRepository,
            sessionService,
            new TestAuthenticationSessionReader(),
            _sessionComposition.Transactions,
            new PermissiveAccountSecurityGuard(),
            new AccountSecurityServiceDependencies(_timeProvider, _sessionComposition.Events, ProviderRegistry: CreateDefaultProviderRegistry()));

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
            Assert.Throws<ArgumentNullException>(() => _ = new AccountSecurityService(null!, _userRepository, new TestAuthenticationSessionMutationExecutor(), new TestAuthenticationSessionReader(), AshlarDurableTransactionProvider.Create(new NullTransactionProvider()), new PermissiveAccountSecurityGuard(), new AccountSecurityServiceDependencies()));
            Assert.Throws<ArgumentNullException>(() => _ = new AccountSecurityService(_userRepository, null!, new TestAuthenticationSessionMutationExecutor(), new TestAuthenticationSessionReader(), AshlarDurableTransactionProvider.Create(new NullTransactionProvider()), new PermissiveAccountSecurityGuard(), new AccountSecurityServiceDependencies()));
            Assert.Throws<ArgumentNullException>(() => _ = new AccountSecurityService(_userRepository, _userRepository, null!, new TestAuthenticationSessionReader(), AshlarDurableTransactionProvider.Create(new NullTransactionProvider()), new PermissiveAccountSecurityGuard(), new AccountSecurityServiceDependencies()));
            Assert.Throws<ArgumentNullException>(() => _ = new AccountSecurityService(_userRepository, _userRepository, new TestAuthenticationSessionMutationExecutor(), null!, AshlarDurableTransactionProvider.Create(new NullTransactionProvider()), new PermissiveAccountSecurityGuard(), new AccountSecurityServiceDependencies()));
            Assert.Throws<ArgumentNullException>(() => _ = new AccountSecurityService(_userRepository, _userRepository, new TestAuthenticationSessionMutationExecutor(), new TestAuthenticationSessionReader(), null!, new PermissiveAccountSecurityGuard(), new AccountSecurityServiceDependencies()));
            Assert.Throws<ArgumentNullException>(() => _ = new AccountSecurityService(_userRepository, _userRepository, new TestAuthenticationSessionMutationExecutor(), new TestAuthenticationSessionReader(), _sessionComposition.Transactions, null!, new AccountSecurityServiceDependencies(SecurityEventSink: _sessionComposition.Events)));
            Assert.Throws<ArgumentNullException>(() => _ = new AccountSecurityService(_userRepository, _userRepository, new TestAuthenticationSessionMutationExecutor(), new TestAuthenticationSessionReader(), AshlarDurableTransactionProvider.Create(new NullTransactionProvider()), new PermissiveAccountSecurityGuard(), null!));
            Assert.Throws<ArgumentException>(() => _ = new AccountSecurityService(_userRepository, _userRepository, new TestAuthenticationSessionMutationExecutor(), new TestAuthenticationSessionReader(), AshlarDurableTransactionProvider.Create(new NullTransactionProvider()), new PermissiveAccountSecurityGuard(), new AccountSecurityServiceDependencies(SecurityEventSink: new SecurityEventFanOutSink())));
        }
    }

    [Test]
    public void OperationsShouldValidateUserIdAndAuditRequest()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentException>(() => _service.SetUserAccountStateAsync(Guid.Empty, CreateStateRequest(UserAccountState.Disabled)));
            Assert.ThrowsAsync<ArgumentNullException>(() => _service.SetUserAccountStateAsync(_userId, null!));
            Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => _service.SetUserAccountStateAsync(_userId, CreateStateRequest((UserAccountState)999)));
            Assert.ThrowsAsync<ArgumentException>(() => _service.RevokeSessionsAsync(Guid.Empty, CreateRequest()));
            Assert.ThrowsAsync<ArgumentNullException>(() => _service.RevokeSessionsAsync(_userId, null!));
            Assert.ThrowsAsync<ArgumentException>(() => _service.ResetMfaAsync(Guid.Empty, CreateRequest()));
            Assert.ThrowsAsync<ArgumentNullException>(() => _service.ResetMfaAsync(_userId, null!));
            Assert.ThrowsAsync<ArgumentException>(() => _service.GetUserSecurityPostureAsync(Guid.Empty));
        }
    }

    [Test]
    public async Task MutatingOperationsShouldPreserveExplicitAllTenantScope()
    {
        var tenantId = Guid.NewGuid();
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active, TenantId = tenantId };
        _sessionRepository.Sessions.Add(CreateSession(_userId, tenantId));
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));
        _userRepository.Credentials.Add(CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.Mfa, "totp")));
        _userRepository.Credentials.Add(CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.RecoveryCode, "RecoveryCode")));

        var stateResult = await _service.SetUserAccountStateAsync(_userId, CreateStateRequest(UserAccountState.Suspended, includeAllTenants: true));
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active, TenantId = tenantId };
        var sessionsResult = await _service.RevokeSessionsAsync(_userId, CreateRequest(includeAllTenants: true));
        var credentialsResult = await _service.RevokeCredentialsAsync(_userId, AuthenticationProviderKey.Local, CreateRequest(includeAllTenants: true));
        var mfaResult = await _service.ResetMfaAsync(_userId, CreateRequest(includeAllTenants: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(stateResult.Succeeded, Is.True);
            Assert.That(sessionsResult.Succeeded, Is.True);
            Assert.That(credentialsResult.Succeeded, Is.True);
            Assert.That(mfaResult.Succeeded, Is.True);
            Assert.That(_events.Events.Single(e => e.EventType == AshlarSecurityEventTypes.UserAccountStateChanged).TenantId, Is.EqualTo(tenantId));
            Assert.That(_events.Events.Where(e => e.EventType == AshlarSecurityEventTypes.SessionsRevokedForUser), Has.All.Matches<AshlarSecurityEvent>(securityEvent => securityEvent.TenantId == tenantId));
            Assert.That(_events.Events.Single(e => e.EventType == AshlarSecurityEventTypes.UserCredentialsRevoked).TenantId, Is.EqualTo(tenantId));
            Assert.That(_events.Events.Single(e => e.EventType == AshlarSecurityEventTypes.UserMfaReset).TenantId, Is.EqualTo(tenantId));
        }
    }

    [Test]
    public async Task MutatingOperationsShouldReturnUserNotFoundForAllTenantMissingUser()
    {
        var result = await _service.SetUserAccountStateAsync(_userId, CreateStateRequest(UserAccountState.Disabled, includeAllTenants: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(_events.Events.Single().TenantId, Is.Null);
        }
    }

    [Test]
    public async Task MutatingOperationsShouldKeepGlobalAuditTenantForAllTenantGlobalUser()
    {
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
        _sessionRepository.Sessions.Add(CreateSession(_userId));
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));
        _userRepository.Credentials.Add(CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.Mfa, "totp")));
        _userRepository.Credentials.Add(CreateCredential(_userId, new AuthenticationProviderKey(ProviderType.RecoveryCode, "RecoveryCode")));

        await _service.SetUserAccountStateAsync(_userId, CreateStateRequest(UserAccountState.Suspended, includeAllTenants: true));
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
        await _service.RevokeSessionsAsync(_userId, CreateRequest(includeAllTenants: true));
        await _service.RevokeCredentialsAsync(_userId, AuthenticationProviderKey.Local, CreateRequest(includeAllTenants: true));
        await _service.ResetMfaAsync(_userId, CreateRequest(includeAllTenants: true));

        Assert.That(_events.Events, Has.All.Matches<AshlarSecurityEvent>(securityEvent => securityEvent.TenantId == null));
    }

    [Test]
    public async Task AllTenantAuditTenantShouldStayGlobalForUserWithoutTenantOwnership()
    {
        var userRepository = new Mock<IUserRepository>();
        userRepository
            .Setup(r => r.GetUserByIdAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new BasicUser(_userId, "user@example.com", UserAccountState.Active));
        var credentials = Mock.Of<ICredentialRepository>();
        var composition = new DurableSecurityMutationTestComposition(_events, userRepository.Object, credentials);
        var service = new AccountSecurityService(
            userRepository.Object,
            credentials,
            new TestAuthenticationSessionMutationExecutor(),
            new TestAuthenticationSessionReader(),
            composition.Transactions,
            new PermissiveAccountSecurityGuard(),
            new AccountSecurityServiceDependencies(_timeProvider, composition.Events, _events));

        var result = await service.SetUserAccountStateAsync(_userId, CreateStateRequest(UserAccountState.Active, includeAllTenants: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(_events.Events.Single().TenantId, Is.Null);
        }
    }

    [Test]
    public async Task GuardFailureAfterAllTenantUserResolutionShouldUseResolvedUserTenant()
    {
        var tenantId = Guid.NewGuid();
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active, TenantId = tenantId };
        var service = new AccountSecurityService(
            _userRepository,
            _userRepository,
            new TestAuthenticationSessionMutationExecutor(),
            new TestAuthenticationSessionReader(),
            _sessionComposition.Transactions,
            new RejectingAccountSecurityGuard(),
            new AccountSecurityServiceDependencies(_timeProvider, _sessionComposition.Events, _events));

        var result = await service.SetUserAccountStateAsync(_userId, CreateStateRequest(UserAccountState.Disabled, includeAllTenants: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(new AshlarFailureCode("guard_rejected")));
            Assert.That(_events.Events.Single().TenantId, Is.EqualTo(tenantId));
        }
    }

    [Test]
    public void AccountSecurityOperationRequestShouldRejectMissingAndConflictingScope()
    {
        var audit = new AuditContext(Guid.NewGuid(), "127.0.0.1", "agent", "corr");

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new AccountSecurityOperationRequest(null!, TenantContext.Global));
            Assert.Throws<ArgumentNullException>(() => _ = new SetUserAccountStateRequest(UserAccountState.Disabled, null!, TenantContext.Global));
            Assert.Throws<ArgumentException>(() => _ = new AccountSecurityOperationRequest(audit));
            Assert.Throws<ArgumentException>(() => _ = new AccountSecurityOperationRequest(audit, TenantContext.Global, IncludeAllTenants: true));
            Assert.Throws<ArgumentException>(() => _ = new SetUserAccountStateRequest(UserAccountState.Disabled, audit));
            Assert.Throws<ArgumentException>(() => _ = new SetUserAccountStateRequest(UserAccountState.Disabled, audit, TenantContext.Global, IncludeAllTenants: true));
        }
    }

    private static AccountSecurityOperationRequest CreateRequest(string? reason = null, Guid? tenantId = null, bool includeAllTenants = false,
        bool preservePrimarySignInMethod = false)
    {
        var tenant = includeAllTenants
            ? null
            : tenantId.HasValue ? new TenantContext(tenantId) : TenantContext.Global;
        return new AccountSecurityOperationRequest(new AuditContext(Guid.NewGuid(), "127.0.0.1", "agent", "corr"), tenant, reason, includeAllTenants,
            preservePrimarySignInMethod);
    }

    private static SetUserAccountStateRequest CreateStateRequest(UserAccountState accountState, string? reason = null, Guid? tenantId = null, bool revokeSessionsAndRememberedMfaDevices = true, bool includeAllTenants = false)
    {
        var tenant = includeAllTenants
            ? null
            : tenantId.HasValue ? new TenantContext(tenantId) : TenantContext.Global;
        return new SetUserAccountStateRequest(
            accountState,
            new AuditContext(Guid.NewGuid(), "127.0.0.1", "agent", "corr"),
            tenant,
            reason,
            revokeSessionsAndRememberedMfaDevices,
            includeAllTenants);
    }

    private AuthenticationSession CreateSession(Guid userId, Guid? tenantId = null)
    {
        return new AuthenticationSession
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            TenantId = tenantId,
            TokenHash = Guid.NewGuid().ToString("N"),
            CreatedAt = _timeProvider.GetUtcNow(),
            ExpiresAt = _timeProvider.GetUtcNow().AddHours(1)
        };
    }

    private AccountSecurityService CreateService(
        IMfaPolicyEvaluator? mfaPolicyEvaluator = null,
        IAuthenticationProviderRegistry? providerRegistry = null,
        bool includeDefaultProviderRegistry = true,
        IRememberedMfaDeviceMutationExecutor? rememberedMfaDevices = null,
        IAuthenticationSessionInventoryReader? sessionReader = null)
    {
        return new AccountSecurityService(
            _userRepository,
            _userRepository,
            new TestAuthenticationSessionMutationExecutor(),
            sessionReader ?? new TestAuthenticationSessionReader(),
            _sessionComposition.Transactions,
            new PermissiveAccountSecurityGuard(),
            new AccountSecurityServiceDependencies(
                _timeProvider,
                _sessionComposition.Events,
                _events,
                MfaPolicyEvaluator: mfaPolicyEvaluator,
                ProviderRegistry: providerRegistry ?? (includeDefaultProviderRegistry ? CreateDefaultProviderRegistry() : null),
                RememberedMfaDeviceService: rememberedMfaDevices));
    }

    private static AuthenticationProviderRegistry CreateDefaultProviderRegistry(
        bool includeRecoveryCodeProvider = true,
        params IAuthenticationProvider[] additionalProviders)
    {
        var providers = new List<IAuthenticationProvider>
        {
            CreatePrimaryProvider(AuthenticationProviderKey.Local).Object,
            CreatePrimaryProvider(AuthenticationProviderKey.EmailCode).Object,
            CreatePrimaryProvider(AuthenticationProviderKey.MagicLink).Object,
            CreatePrimaryProvider(new AuthenticationProviderKey(ProviderType.OAuth, "github")).Object,
            CreatePrimaryProvider(new AuthenticationProviderKey(ProviderType.Oidc, "OIDC")).Object,
            CreatePrimaryProvider(new AuthenticationProviderKey(ProviderType.Saml2, "enterprise-sso")).Object,
            CreateSecondaryProvider(new AuthenticationProviderKey(ProviderType.Mfa, "totp"), AuthenticationFactorTypes.Totp).Object,
            CreatePasskeyProvider().Object
        };

        if (includeRecoveryCodeProvider)
        {
            providers.Add(CreateSecondaryProvider(new AuthenticationProviderKey(ProviderType.RecoveryCode, "RecoveryCode"), AuthenticationFactorTypes.RecoveryCode).Object);
        }

        providers.AddRange(additionalProviders);
        return new AuthenticationProviderRegistry(
            providers);
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
        provider.As<ISecondaryAuthenticationFactorProvider>()
            .Setup(item => item.CanSatisfyFactor(It.IsAny<string>()))
            .Returns<string>(requiredFactor => AuthenticationFactorTypes.Matches(AuthenticationFactorTypes.Passkey, requiredFactor));
        return provider;
    }

    private static Mock<ISecondaryAuthenticationFactorProvider> CreateSecondaryProvider(AuthenticationProviderKey providerKey, string factorType)
    {
        var provider = new Mock<ISecondaryAuthenticationFactorProvider>();
        provider.SetupGet(item => item.Key).Returns(providerKey);
        provider.SetupGet(item => item.FactorType).Returns(factorType);
        provider.Setup(item => item.CanSatisfyFactor(It.IsAny<string>()))
            .Returns<string>(requiredFactor => AuthenticationFactorTypes.Matches(factorType, requiredFactor));
        return provider;
    }

    private static Mock<IBackupAuthenticationFactorProvider> CreateBackupProvider(
        AuthenticationProviderKey providerKey,
        string factorType,
        Predicate<string> backupPolicy)
    {
        var provider = new Mock<IBackupAuthenticationFactorProvider>();
        provider.SetupGet(item => item.Key).Returns(providerKey);
        provider.SetupGet(item => item.FactorType).Returns(factorType);
        provider.Setup(item => item.CanSatisfyFactor(It.IsAny<string>()))
            .Returns<string>(requiredFactor => AuthenticationFactorTypes.Matches(factorType, requiredFactor));
        provider.Setup(item => item.CanSatisfyBackupFactor(It.IsAny<string>()))
            .Returns<string>(requiredFactor => backupPolicy(requiredFactor));
        return provider;
    }

    private UserCredential CreateCredential(Guid userId, AuthenticationProviderKey provider,
        Guid? credentialId = null, CredentialStatus status = CredentialStatus.Active,
        ProviderType? providerType = null, string? providerName = null,
        DateTimeOffset? createdAt = null, DateTimeOffset? expiresAt = null)
    {
        return new UserCredential
        {
            Id = credentialId ?? Guid.NewGuid(),
            UserId = userId,
            ProviderType = providerType ?? provider.Type,
            ProviderName = providerName ?? provider.Name,
            ProviderKey = Guid.NewGuid().ToString("N"),
            Version = "v1",
            Status = status,
            CreatedAt = createdAt ?? _timeProvider.GetUtcNow(),
            ExpiresAt = expiresAt
        };
    }

    private RememberedMfaDevice CreateRememberedMfaDevice(Guid userId)
    {
        return new RememberedMfaDevice
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            TokenSelector = "selector",
            TokenHash = "hash",
            DisplayName = "remembered laptop",
            CreatedAt = _timeProvider.GetUtcNow(),
            ExpiresAt = _timeProvider.GetUtcNow().AddDays(30)
        };
    }

    private sealed class RecordingSecurityEventSink : ISecurityEventSink, IUserSecurityEventSummaryRepository
    {
        public List<AshlarSecurityEvent> Events { get; } = [];
        public int? CountOverride { get; set; }

        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            Events.Add(securityEvent);
            return Task.CompletedTask;
        }

        public Task<int> CountSecurityEventsForUserAsync(Guid userId, DateTimeOffset since, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(CountOverride
                ?? Events.Count(e => e.UserId == userId && e.OccurredAt >= since));
        }
    }

    private sealed class RejectingAccountSecurityGuard : IAccountSecurityGuard
    {
        public Task<Result> CanChangeAccountStateAsync(IUser user, UserAccountState targetState, AccountSecurityGuardContext request, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Result.Failure(new AshlarFailureCode("guard_rejected")));
        }
    }

    private sealed class EmptyFailureAccountSecurityGuard : IAccountSecurityGuard
    {
        public Task<Result> CanChangeAccountStateAsync(IUser user, UserAccountState targetState, AccountSecurityGuardContext request, CancellationToken cancellationToken = default)
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

    private sealed record BasicUser(Guid Id, string DisplayEmail, UserAccountState AccountState) : IUser
    {
        public string? Name => null;
        public DateTimeOffset? EmailVerifiedAt => null;
    }

    private sealed class InMemoryUserCredentialStore : IUserRepository, ICredentialRepository
    {
        public bool ReturnAllCredentials { get; set; }
        public bool ReturnNullCredentials { get; set; }

        public Action? OnMutationLock { get; set; }
        public int MutationLockCalls { get; private set; }
        public Task AcquireUserMutationLockAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            MutationLockCalls++;
            OnMutationLock?.Invoke();
            return Task.CompletedTask;
        }

        public Dictionary<Guid, User> Users { get; } = [];
        public List<UserCredential> Credentials { get; } = [];

        public Task<IUser?> GetUserByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default)
        {
            var normalizedEmail = IdentityNormalization.NormalizeEmail(email);
            return Task.FromResult<IUser?>(Users.Values.FirstOrDefault(user =>
                IdentityNormalization.NormalizeEmail(user.DisplayEmail) == normalizedEmail
                && user.TenantId == tenantId));
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
            if (ReturnNullCredentials) return Task.FromResult<IReadOnlyList<UserCredential>>(null!);
            return Task.FromResult<IReadOnlyList<UserCredential>>(Credentials.Where(c => (ReturnAllCredentials || c.UserId == userId) && (!activeOnly || c.RevokedAt == null)).ToList().AsReadOnly());
        }

        public Task CreateUserAsync(IUser user, CancellationToken cancellationToken = default)
        {
            Users[user.Id] = new User { Id = user.Id, DisplayEmail = user.DisplayEmail, AccountState = user.AccountState, Name = user.Name, TenantId = (user as ITenantUser)?.TenantId, EmailVerifiedAt = user.EmailVerifiedAt };
            return Task.CompletedTask;
        }

        public Task UpdateUserAsync(IUser user, CancellationToken cancellationToken = default)
        {
            Users[user.Id] = new User { Id = user.Id, DisplayEmail = user.DisplayEmail, AccountState = user.AccountState, Name = user.Name, TenantId = (user as ITenantUser)?.TenantId, EmailVerifiedAt = user.EmailVerifiedAt };
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

    private sealed class TestAuthenticationSessionMutationExecutor : IAuthenticationSessionMutationExecutor
    {
        public int RevokeCalls { get; private set; }
        public int RevokeResult { get; set; }

        public Task<int> RevokeSessionsForUserAsync(Guid userId, RevokeAuthenticationSessionsForUserRequest request, CancellationToken cancellationToken = default) { RevokeCalls++; return Task.FromResult(RevokeResult); }
        public Task<bool> RevokeSessionForUserAsync(Guid userId, RevokeAuthenticationSessionRequest request, CancellationToken cancellationToken = default) => Task.FromResult(false);
        public Task<int> RevokeOtherSessionsAsync(Guid userId, RevokeOtherAuthenticationSessionsRequest request, CancellationToken cancellationToken = default) => Task.FromResult(0);
    }

    private sealed class TestAuthenticationSessionReader(bool fail = false) : IAuthenticationSessionInventoryReader
    {
        public Task<Result<IReadOnlyList<AuthenticationSessionSummary>>> ListSessionsAsync(ValidatedAuthenticationSession session, ListAuthenticationSessionsRequest request, CancellationToken cancellationToken = default) =>
            Task.FromResult(Result.Success<IReadOnlyList<AuthenticationSessionSummary>>([]));

        public Task<Result<IReadOnlyList<AuthenticationSessionSummary>>> ListSessionsForUserAsync(Guid userId, Guid? tenantId, ListAuthenticationSessionsRequest request, CancellationToken cancellationToken = default) =>
            Task.FromResult(fail
                ? Result.Failure<IReadOnlyList<AuthenticationSessionSummary>>(AshlarFailureCodes.TenantMismatch)
                : Result.Success<IReadOnlyList<AuthenticationSessionSummary>>([]));
    }

    [Test]
    public async Task PublicPostureReadDerivesIdentityFromActiveValidatedSession()
    {
        _userRepository.Users[_userId] = new User
        {
            Id = _userId,
            DisplayEmail = "user@example.com",
            AccountState = UserAccountState.Active
        };
        var session = CreateSession(_userId);
        var capability = ValidateAuthenticationSessionResult.Success(session).ValidatedSession!;

        var inactive = await ((IAccountSecurityService)_service).GetSecurityPostureAsync(capability);
        _sessionRepository.Sessions.Add(session);
        var result = await ((IAccountSecurityService)_service).GetSecurityPostureAsync(capability);
        var zeroWindow = await ((IAccountSecurityService)_service).GetSecurityPostureAsync(capability, TimeSpan.Zero);
        var overflowingWindow = await ((IAccountSecurityService)_service).GetSecurityPostureAsync(capability, TimeSpan.MaxValue);
        _userRepository.Users[_userId] = new User
        {
            Id = _userId,
            DisplayEmail = "user@example.com",
            AccountState = UserAccountState.Disabled
        };
        var disabled = await ((IAccountSecurityService)_service).GetSecurityPostureAsync(capability);
        var methods = typeof(IAccountSecurityService).GetMethods().Select(method => method.Name);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value?.UserId, Is.EqualTo(_userId));
            Assert.That(inactive.FailureCode, Is.EqualTo(AshlarFailureCodes.SessionNotFoundOrInactive));
            Assert.That(zeroWindow.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(overflowingWindow.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(disabled.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFoundOrUnavailable));
            Assert.That(methods, Does.Not.Contain("GetUserSecurityPostureAsync"));
        }
    }

    [Test]
    public async Task RevokeCredentialsAsyncShouldAuditPostureFailureWhenPreservingPrimaryMethod()
    {
        _userRepository.Users[_userId] = new User
        {
            Id = _userId,
            DisplayEmail = "user@example.com",
            AccountState = UserAccountState.Active
        };
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local));
        _userRepository.ReturnNullCredentials = true;

        var result = await _service.RevokeCredentialsAsync(
            _userId,
            AuthenticationProviderKey.Local,
            CreateRequest(preservePrimarySignInMethod: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(_userRepository.Credentials.Single().RevokedAt, Is.Null);
            Assert.That(_events.Events.Single().FailureReason, Is.EqualTo(AshlarFailureCodes.UserNotFound.Value));
        }
    }

    [Test]
    public async Task InternalPostureReadRejectsHostileSessionInventory()
    {
        _userRepository.Users[_userId] = new User
        {
            Id = _userId,
            DisplayEmail = "user@example.com",
            AccountState = UserAccountState.Active
        };

        var result = await CreateService(sessionReader: new TestAuthenticationSessionReader(fail: true))
            .GetUserSecurityPostureAsync(_userId);

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
    }

    [Test]
    public async Task InternalPostureReadRejectsHostileCredentialInventory()
    {
        _userRepository.Users[_userId] = new User
        {
            Id = _userId,
            DisplayEmail = "user@example.com",
            AccountState = UserAccountState.Active
        };
        _userRepository.ReturnAllCredentials = true;
        _userRepository.Credentials.Add(CreateCredential(Guid.NewGuid(), AuthenticationProviderKey.Local));

        var result = await _service.GetUserSecurityPostureAsync(_userId);

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
    }

    [Test]
    public async Task InternalPostureReadRejectsMalformedCredentialInventory()
    {
        _userRepository.Users[_userId] = new User
        {
            Id = _userId,
            DisplayEmail = "user@example.com",
            AccountState = UserAccountState.Active
        };
        _userRepository.ReturnNullCredentials = true;
        var nullInventory = await _service.GetUserSecurityPostureAsync(_userId);
        _userRepository.ReturnNullCredentials = false;
        _userRepository.Credentials.Add(CreateCredential(
            _userId, AuthenticationProviderKey.Local, Guid.Empty));
        var emptyId = await _service.GetUserSecurityPostureAsync(_userId);

        _userRepository.Credentials.Clear();
        _userRepository.Credentials.Add(CreateCredential(
            _userId, AuthenticationProviderKey.Local, status: (CredentialStatus)int.MaxValue));
        var invalidStatus = await _service.GetUserSecurityPostureAsync(_userId);

        _userRepository.Credentials.Clear();
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local,
            providerType: (ProviderType)ProviderType.StorageFallbackValue));
        var fallbackType = await _service.GetUserSecurityPostureAsync(_userId);

        _userRepository.Credentials.Clear();
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local,
            providerName: " "));
        var blankName = await _service.GetUserSecurityPostureAsync(_userId);

        _userRepository.Credentials.Clear();
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local,
            createdAt: _timeProvider.GetUtcNow().AddMinutes(1)));
        var futureCreated = await _service.GetUserSecurityPostureAsync(_userId);

        _userRepository.Credentials.Clear();
        var createdAt = _timeProvider.GetUtcNow();
        _userRepository.Credentials.Add(CreateCredential(_userId, AuthenticationProviderKey.Local,
            createdAt: createdAt, expiresAt: createdAt));
        var impossibleExpiry = await _service.GetUserSecurityPostureAsync(_userId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(nullInventory.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(emptyId.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(invalidStatus.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(fallbackType.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(blankName.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(futureCreated.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(impossibleExpiry.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
        }
    }

    [Test]
    public async Task InternalPostureReadRejectsNullMfaPolicyEvaluation()
    {
        _userRepository.Users[_userId] = new User
        {
            Id = _userId,
            DisplayEmail = "user@example.com",
            AccountState = UserAccountState.Active
        };
        var evaluator = new Mock<IMfaPolicyEvaluator>();
        evaluator.Setup(item => item.EvaluateAsync(
                It.IsAny<IUser>(), It.IsAny<AuthenticationContext>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((MfaPolicyEvaluation)null!);

        var result = await CreateService(mfaPolicyEvaluator: evaluator.Object)
            .GetUserSecurityPostureAsync(_userId);

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
    }

    [Test]
    public async Task InternalPostureReadRejectsUndefinedUserAccountState()
    {
        _userRepository.Users[_userId] = new User
        {
            Id = _userId,
            DisplayEmail = "user@example.com",
            AccountState = (UserAccountState)int.MaxValue
        };

        var result = await _service.GetUserSecurityPostureAsync(_userId);

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
    }

    [Test]
    public async Task InternalPostureReadRejectsHostileUserResult()
    {
        _userRepository.Users[_userId] = new User
        {
            Id = Guid.NewGuid(),
            DisplayEmail = "other@example.com",
            AccountState = UserAccountState.Active
        };

        var result = await _service.GetUserSecurityPostureAsync(_userId);

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
    }

    [Test]
    public async Task RevokeRememberedMfaDeviceAsyncShouldValidateScopeAndDelegate()
    {
        var tenantId = Guid.NewGuid();
        var deviceId = Guid.NewGuid();
        var rememberedDevices = new TestRememberedMfaDeviceMutationExecutor { RevokeResult = true };
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active, TenantId = tenantId };
        var service = CreateService(rememberedMfaDevices: rememberedDevices);

        var defaultReasonResult = await service.RevokeRememberedMfaDeviceAsync(_userId, Guid.NewGuid(), CreateRequest(tenantId: tenantId));
        var result = await service.RevokeRememberedMfaDeviceAsync(_userId, deviceId, CreateRequest("cleanup", tenantId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value?.RememberedMfaDevicesRevoked, Is.EqualTo(1));
            Assert.That(defaultReasonResult.Succeeded, Is.True);
            Assert.That(rememberedDevices.LastDeviceId, Is.EqualTo(deviceId));
            Assert.That(rememberedDevices.LastDeviceRequest?.Tenant?.TenantId, Is.EqualTo(tenantId));
            Assert.ThrowsAsync<ArgumentException>(() => service.RevokeRememberedMfaDeviceAsync(_userId, Guid.Empty, CreateRequest()));
        }
    }

    [Test]
    public async Task RevokeRememberedMfaMutationsShouldHandleMissingUserAndMissingStore()
    {
        var rememberedDevices = new TestRememberedMfaDeviceMutationExecutor();
        var service = CreateService(rememberedMfaDevices: rememberedDevices);
        var missingOne = await service.RevokeRememberedMfaDeviceAsync(_userId, Guid.NewGuid(), CreateRequest());
        var missingAll = await service.RevokeRememberedMfaDevicesAsync(_userId, CreateRequest());
        _userRepository.Users[_userId] = new User { Id = _userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };
        var noStoreOne = await _service.RevokeRememberedMfaDeviceAsync(_userId, Guid.NewGuid(), CreateRequest());
        var noStoreAll = await _service.RevokeRememberedMfaDevicesAsync(_userId, CreateRequest());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missingOne.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(missingAll.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(noStoreOne.Value?.RememberedMfaDevicesRevoked, Is.Zero);
            Assert.That(noStoreAll.Value?.RememberedMfaDevicesRevoked, Is.Zero);
            Assert.That(rememberedDevices.RevokeCalls, Is.Zero);
        }
    }

    private sealed class TestRememberedMfaDeviceMutationExecutor : IRememberedMfaDeviceMutationExecutor
    {
        public int RevokeCalls { get; private set; }
        public bool RevokeResult { get; set; }
        public Guid? LastDeviceId { get; private set; }
        public RevokeRememberedMfaDeviceRequest? LastDeviceRequest { get; private set; }
        public int RevokeAllCalls { get; private set; }
        public int RevokeAllResult { get; set; }
        public RevokeAllRememberedMfaDevicesRequest? LastRequest { get; private set; }

        public Task<bool> RevokeAsync(Guid userId, RevokeRememberedMfaDeviceRequest request, CancellationToken cancellationToken = default)
        {
            RevokeCalls++;
            LastDeviceId = request.DeviceId;
            LastDeviceRequest = request;
            return Task.FromResult(RevokeResult);
        }
        public Task<int> RevokeAllAsync(Guid userId, RevokeAllRememberedMfaDevicesRequest request, CancellationToken cancellationToken = default) { RevokeAllCalls++; LastRequest = request; return Task.FromResult(RevokeAllResult); }
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

        public Task<int> RevokeSessionsForUserAsync(Guid userId, DateTimeOffset revokedAt, string? reason, TenantContext? tenant, bool includeAllTenants, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Revoke(s => s.UserId == userId, revokedAt, reason));
        }

        public Task<IReadOnlyList<AuthenticationSession>> ListSessionsForUserAsync(Guid userId, bool activeOnly, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IReadOnlyList<AuthenticationSession>>(Sessions.Where(s => s.UserId == userId && (!activeOnly || s.IsActive(now))).ToList().AsReadOnly());
        }

        public Task<bool> RevokeSessionByIdAsync(Guid sessionId, Guid userId, DateTimeOffset revokedAt, string? reason = null, TenantContext? tenant = null, bool includeAllTenants = false, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Revoke(s => s.Id == sessionId && s.UserId == userId, revokedAt, reason) == 1);
        }

        public Task<int> RevokeOtherSessionsForUserAsync(Guid userId, Guid excludedSessionId, DateTimeOffset revokedAt, string? reason = null, TenantContext? tenant = null, bool includeAllTenants = false, CancellationToken cancellationToken = default)
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

internal static class AccountSecurityServiceTestExtensions
{
    public static Task<Result<AccountSecurityPosture>> GetUserSecurityPostureAsync(
        this AccountSecurityService service, Guid userId,
        AccountSecurityPostureRequest? request = null, CancellationToken cancellationToken = default) =>
        ((IAccountSecurityPostureReader)service).GetUserSecurityPostureAsync(
            userId, request ?? new AccountSecurityPostureRequest(), cancellationToken);
}
