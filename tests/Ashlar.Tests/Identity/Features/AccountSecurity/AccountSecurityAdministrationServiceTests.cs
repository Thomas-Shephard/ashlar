using Ashlar.Auditing;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Identity.Features.AccountSecurity;

internal sealed class AccountSecurityAdministrationServiceTests
{
    private readonly Guid _actorId = Guid.NewGuid();
    private readonly Guid _targetId = Guid.NewGuid();
    private readonly Guid _sessionId = Guid.NewGuid();
    private readonly TenantContext _tenant = new(Guid.NewGuid());
    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 7, 9, 12, 0, 0, TimeSpan.Zero));
    private FakeExecutor _executor = null!;
    private Mock<IAccountSecurityOperationAuthorizer> _authorizer = null!;
    private RecordingSecurityEventSink _events = null!;
    private AccountSecurityAdministrationService _service = null!;

    [SetUp]
    public void SetUp()
    {
        _executor = new FakeExecutor();
        _authorizer = new Mock<IAccountSecurityOperationAuthorizer>(MockBehavior.Strict);
        _events = new RecordingSecurityEventSink();
        _service = new AccountSecurityAdministrationService(_executor, _authorizer.Object, _time, _events);
    }

    [Test]
    public async Task ActorAuditMismatchFailsBeforeAuthorizationOrMutation()
    {
        var request = CreateRequest(auditActorId: Guid.NewGuid());

        var result = await _service.RevokeSessionsAsync(request);

        _authorizer.VerifyNoOtherCalls();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(_executor.CallCount, Is.Zero);
            Assert.That(_events.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.SessionsRevokedForUser));
        }
    }

    [Test]
    public async Task MissingAuditActorFailsBeforeAuthorizationOrMutation()
    {
        var baseRequest = CreateRequest();
        var request = new AccountSecurityAdministrationRequest(
            baseRequest.TargetUserId, new AccountSecurityActorContext(baseRequest.ActorUserId, baseRequest.ActorTenant,
                baseRequest.CurrentSessionId, baseRequest.FreshMfaProof, new AuditContext()), baseRequest.Tenant);

        var result = await _service.RevokeSessionsAsync(request);

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        _authorizer.VerifyNoOtherCalls();
        Assert.That(_executor.CallCount, Is.Zero);
    }

    [TestCase(ProofProblem.MissingSession)]
    [TestCase(ProofProblem.WrongActor)]
    [TestCase(ProofProblem.WrongTenant)]
    [TestCase(ProofProblem.Stale)]
    public async Task InvalidProofFailsBeforeAuthorizationOrMutation(ProofProblem problem)
    {
        var request = CreateRequest(problem);

        var result = await _service.RevokeSessionsAsync(request);

        Assert.That(result.Succeeded, Is.False);
        _authorizer.VerifyNoOtherCalls();
        Assert.That(_executor.CallCount, Is.Zero);
    }

    [Test]
    public async Task DeniedAuthorizationFailsBeforeMutationAndCarriesExactScope()
    {
        var request = CreateRequest(includeAllTenants: true, targetTenant: null);
        _authorizer
            .Setup(x => x.AuthorizeAsync(
                It.Is<AccountSecurityAuthorizationContext>(context =>
                    context.ActorUserId == _actorId
                    && context.TargetUserId == _targetId
                    && context.IncludeAllTenants
                    && context.TargetTenant == null
                    && context.CurrentSessionId == _sessionId
                    && context.Operation == AccountSecurityOperation.ResetMfa),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var result = await _service.ResetMfaAsync(request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(_executor.CallCount, Is.Zero);
            Assert.That(_events.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.UserMfaReset));
        }
        _authorizer.Verify(x => x.AuthorizeAsync(It.IsAny<AccountSecurityAuthorizationContext>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task CredentialAuthorizationReceivesProviderBeforeMutation()
    {
        var provider = AuthenticationProviderKey.Local;
        var baseRequest = CreateRequest();
        var request = new RevokeAccountCredentialsRequest(
            baseRequest.TargetUserId,
            provider,
            ToActor(baseRequest),
            baseRequest.Tenant,
            preservePrimarySignInMethod: true);
        _authorizer
            .Setup(x => x.AuthorizeAsync(
                It.Is<AccountSecurityAuthorizationContext>(context =>
                    context.Operation == AccountSecurityOperation.RevokeCredentials
                    && context.Provider == provider
                    && context.PreservePrimarySignInMethod),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var result = await _service.RevokeCredentialsAsync(request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(_executor.CallCount, Is.Zero);
        }
        _authorizer.Verify(x => x.AuthorizeAsync(
            It.Is<AccountSecurityAuthorizationContext>(context => context.PreservePrimarySignInMethod),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task AccountStateAuthorizationReceivesStateAndRevocationChoice()
    {
        var baseRequest = CreateRequest();
        var request = new SetUserAccountStateAdministrationRequest(
            baseRequest.TargetUserId,
            UserAccountState.Disabled,
            ToActor(baseRequest),
            baseRequest.Tenant,
            revokeSessionsAndRememberedMfaDevices: false);
        _authorizer
            .Setup(x => x.AuthorizeAsync(
                It.Is<AccountSecurityAuthorizationContext>(context =>
                    context.Operation == AccountSecurityOperation.SetAccountState
                    && context.AccountState == UserAccountState.Disabled
                    && context.RevokeSessionsAndRememberedMfaDevices == false),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var result = await _service.SetUserAccountStateAsync(request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(_executor.CallCount, Is.Zero);
        }
    }

    [Test]
    public async Task AuthorizedRequestDelegatesOnlyAfterValidation()
    {
        var request = CreateRequest();
        var expected = Result.Success(new AccountSecurityOperationResult(_targetId, SessionsRevoked: 2));
        _authorizer.Setup(x => x.AuthorizeAsync(It.IsAny<AccountSecurityAuthorizationContext>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);
        _executor.Result = expected;

        var result = await _service.RevokeSessionsAsync(request);

        Assert.That(result, Is.SameAs(expected));
        using (Assert.EnterMultipleScope())
        {
            Assert.That(_executor.CallCount, Is.EqualTo(1));
            Assert.That(_executor.UserId, Is.EqualTo(_targetId));
            Assert.That(_executor.Request?.Audit, Is.EqualTo(request.Audit));
            Assert.That(_executor.Request?.Tenant, Is.EqualTo(_tenant));
        }
    }

    [Test]
    public async Task AuthorizedOperationsDelegateCompleteRequests()
    {
        var request = CreateRequest();
        var provider = new AuthenticationProviderKey(ProviderType.Oidc, "example");
        _authorizer.Setup(x => x.AuthorizeAsync(It.IsAny<AccountSecurityAuthorizationContext>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);
        _executor.Result = Result.Success(new AccountSecurityOperationResult(_targetId));

        await _service.SetUserAccountStateAsync(new SetUserAccountStateAdministrationRequest(
            _targetId, UserAccountState.Disabled, ToActor(request), _tenant,
            reason: "state", revokeSessionsAndRememberedMfaDevices: false));
        using (Assert.EnterMultipleScope())
        {
            Assert.That(_executor.Operation, Is.EqualTo(AccountSecurityOperation.SetAccountState));
            Assert.That(_executor.StateRequest?.AccountState, Is.EqualTo(UserAccountState.Disabled));
            Assert.That(_executor.StateRequest?.RevokeSessionsAndRememberedMfaDevices, Is.False);
        }

        await _service.RevokeCredentialsAsync(new RevokeAccountCredentialsRequest(
            _targetId, provider, ToActor(request), _tenant));
        using (Assert.EnterMultipleScope())
        {
            Assert.That(_executor.Operation, Is.EqualTo(AccountSecurityOperation.RevokeCredentials));
            Assert.That(_executor.Provider, Is.EqualTo(provider));
        }

        await _service.ResetMfaAsync(request);
        Assert.That(_executor.Operation, Is.EqualTo(AccountSecurityOperation.ResetMfa));

        var deviceId = Guid.NewGuid();
        await _service.RevokeRememberedMfaDeviceAsync(new RevokeRememberedMfaDeviceAdministrationRequest(
            deviceId, _targetId, ToActor(request), _tenant));
        using (Assert.EnterMultipleScope())
        {
            Assert.That(_executor.Operation, Is.EqualTo(AccountSecurityOperation.RevokeRememberedMfaDevice));
            Assert.That(_executor.DeviceId, Is.EqualTo(deviceId));
        }

        await _service.RevokeRememberedMfaDevicesAsync(request);
        Assert.That(_executor.Operation, Is.EqualTo(AccountSecurityOperation.RevokeRememberedMfaDevices));
    }

    [Test]
    public void AdministrationRequestsRejectIncompleteOrConflictingSecurityContext()
    {
        var proof = new FreshMfaVerificationProof(_actorId, _tenant.TenantId, _sessionId, _time.GetUtcNow(), _time.GetUtcNow().AddMinutes(5));
        var audit = new AuditContext(_actorId);

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentException>(() => new AccountSecurityAdministrationRequest(Guid.Empty, new AccountSecurityActorContext(_actorId, _tenant, _sessionId, proof, audit), _tenant));
            Assert.Throws<ArgumentException>(() => new AccountSecurityActorContext(Guid.Empty, _tenant, _sessionId, proof, audit));
            Assert.Throws<ArgumentException>(() => new AccountSecurityActorContext(_actorId, _tenant, Guid.Empty, proof, audit));
            Assert.Throws<ArgumentNullException>(() => new AccountSecurityActorContext(_actorId, null!, _sessionId, proof, audit));
            Assert.Throws<ArgumentNullException>(() => new AccountSecurityActorContext(_actorId, _tenant, _sessionId, null!, audit));
            Assert.Throws<ArgumentNullException>(() => new AccountSecurityActorContext(_actorId, _tenant, _sessionId, proof, null!));
            Assert.Throws<ArgumentNullException>(() => new AccountSecurityAdministrationRequest(_targetId, null!, _tenant));
            Assert.Throws<ArgumentException>(() => new AccountSecurityAdministrationRequest(_targetId, new AccountSecurityActorContext(_actorId, _tenant, _sessionId, proof, audit)));
            Assert.Throws<ArgumentException>(() => new AccountSecurityAdministrationRequest(_targetId, new AccountSecurityActorContext(_actorId, _tenant, _sessionId, proof, audit), _tenant, includeAllTenants: true));
            Assert.Throws<ArgumentOutOfRangeException>(() => new SetUserAccountStateAdministrationRequest(
                _targetId, (UserAccountState)int.MaxValue, new AccountSecurityActorContext(_actorId, _tenant, _sessionId, proof, audit), _tenant));
            Assert.Throws<ArgumentException>(() => new RevokeAccountCredentialsRequest(
                _targetId, default, new AccountSecurityActorContext(_actorId, _tenant, _sessionId, proof, audit), _tenant));
            Assert.Throws<ArgumentException>(() => new RevokeAccountCredentialsRequest(
                _targetId, new AuthenticationProviderKey(ProviderType.Internal, "internal"), new AccountSecurityActorContext(_actorId, _tenant, _sessionId, proof, audit), _tenant));
            Assert.Throws<ArgumentException>(() => new RevokeRememberedMfaDeviceAdministrationRequest(
                Guid.Empty, _targetId, new AccountSecurityActorContext(_actorId, _tenant, _sessionId, proof, audit), _tenant));
        }
    }

    [Test]
    public void AdministrationServiceRejectsNullRequests()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentNullException>(() => _service.SetUserAccountStateAsync(null!));
            Assert.ThrowsAsync<ArgumentNullException>(() => _service.RevokeSessionsAsync(null!));
            Assert.ThrowsAsync<ArgumentNullException>(() => _service.RevokeCredentialsAsync(null!));
            Assert.ThrowsAsync<ArgumentNullException>(() => _service.ResetMfaAsync(null!));
            Assert.ThrowsAsync<ArgumentNullException>(() => _service.RevokeRememberedMfaDeviceAsync(null!));
            Assert.ThrowsAsync<ArgumentNullException>(() => _service.RevokeRememberedMfaDevicesAsync(null!));
        }
    }

    [Test]
    public void PublicReadAndAdministrationSurfacesDoNotExposeRawTargetMutationMethods()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(typeof(IAccountSecurityService).GetMethods().Select(method => method.Name), Is.EqualTo(["GetUserSecurityPostureAsync"]));
            Assert.That(typeof(IAccountSecurityAdministrationService).GetMethods().All(method => method.GetParameters()[0].ParameterType != typeof(Guid)), Is.True);
        }
    }

    private AccountSecurityAdministrationRequest CreateRequest(
        ProofProblem problem = ProofProblem.None,
        Guid? auditActorId = null,
        bool includeAllTenants = false,
        TenantContext? targetTenant = null)
    {
        var proof = new FreshMfaVerificationProof(
            problem == ProofProblem.WrongActor ? Guid.NewGuid() : _actorId,
            problem == ProofProblem.WrongTenant ? Guid.NewGuid() : _tenant.TenantId,
            _sessionId,
            _time.GetUtcNow().AddMinutes(-1),
            problem == ProofProblem.Stale ? _time.GetUtcNow() : _time.GetUtcNow().AddMinutes(5));
        return new AccountSecurityAdministrationRequest(
            _targetId,
            new AccountSecurityActorContext(_actorId, _tenant,
                problem == ProofProblem.MissingSession ? Guid.NewGuid() : _sessionId,
                proof, new AuditContext(auditActorId ?? _actorId)),
            targetTenant ?? (includeAllTenants ? null : _tenant),
            includeAllTenants);
    }

    private static AccountSecurityActorContext ToActor(AccountSecurityAdministrationRequest request) =>
        new(request.ActorUserId, request.ActorTenant, request.CurrentSessionId, request.FreshMfaProof, request.Audit);

    internal enum ProofProblem
    {
        None,
        MissingSession,
        WrongActor,
        WrongTenant,
        Stale
    }

    private sealed class FakeExecutor : IAccountSecurityMutationExecutor
    {
        public int CallCount { get; private set; }
        public Guid UserId { get; private set; }
        public AccountSecurityOperationRequest? Request { get; private set; }
        public AccountSecurityOperation Operation { get; private set; }
        public AuthenticationProviderKey? Provider { get; private set; }
        public SetUserAccountStateRequest? StateRequest { get; private set; }
        public Guid? DeviceId { get; private set; }
        public Result<AccountSecurityOperationResult> Result { get; set; } = Ashlar.Result.Failure<AccountSecurityOperationResult>(AshlarFailureCodes.ValidationError);

        public Task<Result<AccountSecurityOperationResult>> RevokeSessionsAsync(Guid userId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default)
        {
            CallCount++;
            Operation = AccountSecurityOperation.RevokeSessions;
            UserId = userId;
            Request = request;
            return Task.FromResult(Result);
        }

        public Task<Result<AccountSecurityOperationResult>> SetUserAccountStateAsync(Guid userId, SetUserAccountStateRequest request, CancellationToken cancellationToken = default)
        {
            Record(userId, request, AccountSecurityOperation.SetAccountState);
            StateRequest = request;
            return Task.FromResult(Result);
        }

        public Task<Result<AccountSecurityOperationResult>> RevokeCredentialsAsync(Guid userId, AuthenticationProviderKey provider, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default)
        {
            Record(userId, request, AccountSecurityOperation.RevokeCredentials);
            Provider = provider;
            return Task.FromResult(Result);
        }

        public Task<Result<AccountSecurityOperationResult>> ResetMfaAsync(Guid userId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default)
        {
            Record(userId, request, AccountSecurityOperation.ResetMfa);
            return Task.FromResult(Result);
        }

        public Task<Result<AccountSecurityOperationResult>> RevokeRememberedMfaDeviceAsync(Guid userId, Guid deviceId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default)
        {
            Record(userId, request, AccountSecurityOperation.RevokeRememberedMfaDevice);
            DeviceId = deviceId;
            return Task.FromResult(Result);
        }

        public Task<Result<AccountSecurityOperationResult>> RevokeRememberedMfaDevicesAsync(Guid userId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default)
        {
            Record(userId, request, AccountSecurityOperation.RevokeRememberedMfaDevices);
            return Task.FromResult(Result);
        }

        private void Record(Guid userId, AccountSecurityOperationRequest request, AccountSecurityOperation operation)
        {
            CallCount++;
            UserId = userId;
            Request = request;
            Operation = operation;
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
