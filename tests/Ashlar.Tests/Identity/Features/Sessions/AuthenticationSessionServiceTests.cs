using Ashlar.Auditing;
using Ashlar.Identity.Notifications;
using Ashlar.Security.Tokens;
using Ashlar.Testing;
using System.Text.Json;
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
            .ReturnsAsync((Guid userId, CancellationToken _) => new User { Id = userId, DisplayEmail = "user@example.com" });

        _service = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(TimeProvider: _timeProvider, UserRepository: _userRepositoryMock.Object));
    }

    [Test]
    public void PublicSessionServiceShouldNotExposeRawUserIdSessionCreation()
    {
        var rawCreate = typeof(IAuthenticationSessionService).GetMethods()
            .Where(method => method.Name == nameof(IAuthenticationSessionService.CreateSessionAsync))
            .Any(method => method.GetParameters().FirstOrDefault()?.ParameterType == typeof(Guid));

        Assert.That(rawCreate, Is.False);
    }

    [Test]
    public void PublicSessionServiceShouldNotExposeRawUserIdStepUpMarking()
    {
        var rawMark = typeof(IAuthenticationSessionService).GetMethods()
            .Where(method => method.Name == nameof(IAuthenticationSessionService.MarkStepUpVerifiedAsync))
            .Any(method => method.GetParameters().FirstOrDefault()?.ParameterType == typeof(Guid));

        Assert.That(rawMark, Is.False);
    }

    [Test]
    public void CreateSessionAsyncShouldRejectResultWithoutAshlarIssuanceProofBeforeMutation()
    {
        var result = new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, new User { Id = Guid.NewGuid(), DisplayEmail = "user@example.com" });

        Assert.ThrowsAsync<AshlarOperationException>(() => _service.CreateSessionAsync(result, new CreateAuthenticationSessionRequest()));
        _repositoryMock.Verify(r => r.CreateSessionAsync(It.IsAny<AuthenticationSession>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public void CreateSessionAsyncShouldRejectFailedOrIncompleteAuthenticationResultsBeforeMutation()
    {
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "user@example.com" };
        var failed = new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, user)
        {
            SessionIssuanceProof = AuthenticationSessionIssuanceProof.Instance
        };
        var missingUser = new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, null)
        {
            SessionIssuanceProof = AuthenticationSessionIssuanceProof.Instance
        };
        var emptyUserId = new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, new User { Id = Guid.Empty, DisplayEmail = "user@example.com" })
        {
            SessionIssuanceProof = AuthenticationSessionIssuanceProof.Instance
        };

        Assert.ThrowsAsync<AshlarOperationException>(() => _service.CreateSessionAsync(failed, new CreateAuthenticationSessionRequest()));
        Assert.ThrowsAsync<AshlarOperationException>(() => _service.CreateSessionAsync(missingUser, new CreateAuthenticationSessionRequest()));
        Assert.ThrowsAsync<AshlarOperationException>(() => _service.CreateSessionAsync(emptyUserId, new CreateAuthenticationSessionRequest()));
        _repositoryMock.Verify(r => r.CreateSessionAsync(It.IsAny<AuthenticationSession>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task CreateSessionAsyncShouldIssueSessionForAshlarAuthenticationResult()
    {
        var userId = Guid.NewGuid();
        var result = new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, new User { Id = userId, DisplayEmail = "user@example.com" })
        {
            SessionIssuanceProof = AuthenticationSessionIssuanceProof.Instance
        };

        var session = await _service.CreateSessionAsync(result, new CreateAuthenticationSessionRequest());

        Assert.That(session.Session.UserId, Is.EqualTo(userId));
    }

    [Test]
    public void RevokeIssuedSessionAsyncShouldRejectCallerConstructedSessionBeforeMutation()
    {
        var session = new CreatedAuthenticationSession(Guid.NewGuid(), Guid.NewGuid(), null, _timeProvider.GetUtcNow(),
            _timeProvider.GetUtcNow(), null, _timeProvider.GetUtcNow().AddHours(1), null, null, null);

        Assert.ThrowsAsync<AshlarOperationException>(() => _service.RevokeIssuedSessionAsync(
            new RevokeIssuedAuthenticationSessionRequest(session, new AuditContext(session.UserId))));
        _repositoryMock.Verify(r => r.RevokeSessionByIdAsync(It.IsAny<Guid>(), It.IsAny<Guid>(), It.IsAny<DateTimeOffset>(),
            It.IsAny<string?>(), It.IsAny<TenantContext?>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task RevokeIssuedSessionAsyncShouldRevokeAshlarIssuedSession()
    {
        var actor = Guid.NewGuid();
        var session = CreateSession(expiresAt: _timeProvider.GetUtcNow().AddHours(1), userId: actor);
        var issued = new CreatedAuthenticationSession(session.Id, actor, null, session.CreatedAt, session.AuthenticatedAt,
            session.PrimaryProvider, session.ExpiresAt, session.IpAddress, session.UserAgent, session.Metadata)
        {
            RollbackToken = "raw-token"
        };
        _repositoryMock.Setup(r => r.GetSessionByTokenHashAsync("hashed:raw-token", It.IsAny<CancellationToken>())).ReturnsAsync(session);
        _repositoryMock.Setup(r => r.RevokeSessionByIdAsync(session.Id, actor, _timeProvider.GetUtcNow(), "rollback", TenantContext.Global, false, It.IsAny<CancellationToken>())).ReturnsAsync(true);

        var revoked = await _service.RevokeIssuedSessionAsync(new RevokeIssuedAuthenticationSessionRequest(issued, new AuditContext(actor), "rollback"));

        Assert.That(revoked, Is.True);
    }

    [Test]
    public async Task RevokeSessionForCurrentUserAsyncShouldValidateAuthorizeAndRevoke()
    {
        var actor = Guid.NewGuid();
        var currentSession = Guid.NewGuid();
        var targetSession = Guid.NewGuid();
        var tenant = TenantContext.Global;
        var audit = new AuditContext(actor);
        var proof = CreateProof(actor, currentSession);
        var authorizer = new Mock<IAccountSecurityOperationAuthorizer>();
        authorizer.Setup(a => a.AuthorizeAsync(It.IsAny<AccountSecurityAuthorizationContext>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);
        var service = new AuthenticationSessionService(
            _repositoryMock.Object, _tokenHasherMock.Object, new FixedSessionTokenGenerator("raw-token"), new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(_userRepositoryMock.Object, TimeProvider: _timeProvider, OperationAuthorizer: authorizer.Object));
        _repositoryMock.Setup(r => r.RevokeSessionByIdAsync(targetSession, actor, _timeProvider.GetUtcNow(), "cleanup", tenant, false, It.IsAny<CancellationToken>())).ReturnsAsync(true);

        var revoked = await service.RevokeSessionForCurrentUserAsync(
            new RevokeOwnAuthenticationSessionRequest(actor, tenant, currentSession, proof, audit, targetSession, "cleanup"));

        Assert.That(revoked, Is.True);
        authorizer.Verify(a => a.AuthorizeAsync(It.Is<AccountSecurityAuthorizationContext>(c =>
            c.ActorUserId == actor && c.TargetUserId == actor && c.TargetSessionId == targetSession &&
            c.Operation == AccountSecurityOperation.RevokeOwnSession), It.IsAny<CancellationToken>()), Times.Once);
    }

    private FreshMfaVerificationProof CreateProof(Guid userId, Guid sessionId)
    {
        var now = _timeProvider.GetUtcNow();
        var session = new AuthenticationSession
        {
            Id = sessionId,
            UserId = userId,
            TokenHash = "hash",
            CreatedAt = now.AddMinutes(-1),
            AdditionalVerificationAt = now,
            ExpiresAt = now.AddHours(1)
        };
        return new StepUpAuthenticationService(_timeProvider)
            .CreateFreshMfaProof(new ValidatedAuthenticationSession(session), new StepUpRequirement(TimeSpan.FromMinutes(5), Purpose: AuthenticationSessionService.SelfServiceProofPurpose)).Value!;
    }

    [Test]
    public void RevokeSessionForCurrentUserAsyncShouldRejectInvalidBoundaryInputs()
    {
        var actor = Guid.NewGuid();
        var session = Guid.NewGuid();
        var audit = new AuditContext(actor);
        var proof = new FreshMfaVerificationProof(actor, null, session, _timeProvider.GetUtcNow(), _timeProvider.GetUtcNow().AddMinutes(5), AuthenticationSessionService.SelfServiceProofPurpose);

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentNullException>(() => _service.RevokeSessionForCurrentUserAsync(null!));
            Assert.ThrowsAsync<ArgumentException>(() => _service.RevokeSessionForCurrentUserAsync(new(actor, TenantContext.Global, session, proof, audit, Guid.Empty)));
            Assert.ThrowsAsync<ArgumentException>(() => _service.RevokeSessionForCurrentUserAsync(new(actor, TenantContext.Global, session, proof, audit, Guid.NewGuid(), new string('x', 513))));
            Assert.ThrowsAsync<ArgumentException>(() => _service.RevokeSessionForCurrentUserAsync(new(Guid.Empty, TenantContext.Global, session, proof, audit, Guid.NewGuid())));
            Assert.ThrowsAsync<ArgumentNullException>(() => _service.RevokeSessionForCurrentUserAsync(new(actor, null!, session, proof, audit, Guid.NewGuid())));
            Assert.ThrowsAsync<ArgumentException>(() => _service.RevokeSessionForCurrentUserAsync(new(actor, TenantContext.Global, Guid.Empty, proof, audit, Guid.NewGuid())));
            Assert.ThrowsAsync<ArgumentNullException>(() => _service.RevokeSessionForCurrentUserAsync(new(actor, TenantContext.Global, session, null!, audit, Guid.NewGuid())));
            Assert.ThrowsAsync<ArgumentNullException>(() => _service.RevokeSessionForCurrentUserAsync(new(actor, TenantContext.Global, session, proof, null!, Guid.NewGuid())));
            Assert.ThrowsAsync<AshlarOperationException>(() => _service.RevokeSessionForCurrentUserAsync(new(actor, TenantContext.Global, session, proof, new AuditContext(Guid.NewGuid()), Guid.NewGuid())));
            Assert.ThrowsAsync<AshlarOperationException>(() => _service.RevokeSessionForCurrentUserAsync(new(actor, TenantContext.Global, session, proof, new AuditContext(), Guid.NewGuid())));
            Assert.ThrowsAsync<AshlarOperationException>(() => _service.RevokeSessionForCurrentUserAsync(new(actor, TenantContext.Global, session,
                new FreshMfaVerificationProof(actor, null, session, _timeProvider.GetUtcNow().AddMinutes(-10), _timeProvider.GetUtcNow().AddMinutes(-5), AuthenticationSessionService.SelfServiceProofPurpose), audit, Guid.NewGuid())));
            Assert.ThrowsAsync<AshlarOperationException>(() => _service.RevokeSessionForCurrentUserAsync(new(actor, TenantContext.Global, session,
                new FreshMfaVerificationProof(actor, null, session, _timeProvider.GetUtcNow(), _timeProvider.GetUtcNow().AddMinutes(5), "totp-management"), audit, Guid.NewGuid())));
            Assert.ThrowsAsync<AshlarOperationException>(() => _service.RevokeSessionForCurrentUserAsync(new(actor, TenantContext.Global, session, proof, audit, Guid.NewGuid())));
        }
        _repositoryMock.Verify(r => r.RevokeSessionByIdAsync(It.IsAny<Guid>(), It.IsAny<Guid>(), It.IsAny<DateTimeOffset>(),
            It.IsAny<string?>(), It.IsAny<TenantContext?>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public void RevokeSessionForCurrentUserAsyncShouldAuditAuthorizationDenialOnceWithoutMutation()
    {
        var actor = Guid.NewGuid();
        var currentSession = Guid.NewGuid();
        var targetSession = Guid.NewGuid();
        var audit = new AuditContext(actor, CorrelationId: "revoke-denied");
        var proof = new FreshMfaVerificationProof(actor, null, currentSession, _timeProvider.GetUtcNow(), _timeProvider.GetUtcNow().AddMinutes(5), AuthenticationSessionService.SelfServiceProofPurpose);
        var events = new Mock<ISecurityEventSink>();
        var authorizer = new Mock<IAccountSecurityOperationAuthorizer>();
        authorizer.Setup(a => a.AuthorizeAsync(It.IsAny<AccountSecurityAuthorizationContext>(), It.IsAny<CancellationToken>())).ReturnsAsync(false);
        var service = new AuthenticationSessionService(
            _repositoryMock.Object, _tokenHasherMock.Object, new FixedSessionTokenGenerator("raw-token"), new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(_userRepositoryMock.Object, TimeProvider: _timeProvider,
                SecurityEventSink: events.Object, OperationAuthorizer: authorizer.Object));

        Assert.ThrowsAsync<AshlarOperationException>(() => service.RevokeSessionForCurrentUserAsync(
            new RevokeOwnAuthenticationSessionRequest(actor, TenantContext.Global, currentSession, proof, audit, targetSession)));

        events.Verify(s => s.RecordAsync(It.Is<AshlarSecurityEvent>(e =>
            e.EventType == AshlarSecurityEventTypes.SessionRevoked && e.Outcome == SecurityEventOutcomes.Failure &&
            e.UserId == actor && e.ActorUserId == actor && e.SessionId == targetSession &&
            e.CorrelationId == "revoke-denied" && e.FailureReason == AshlarFailureCodes.ValidationErrorValue),
            It.IsAny<CancellationToken>()), Times.Once);
        _repositoryMock.Verify(r => r.RevokeSessionByIdAsync(It.IsAny<Guid>(), It.IsAny<Guid>(), It.IsAny<DateTimeOffset>(),
            It.IsAny<string?>(), It.IsAny<TenantContext?>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public void RevokeOtherSessionsForCurrentUserAsyncShouldAuditAuthorizationDenialOnceWithoutMutation()
    {
        var actor = Guid.NewGuid();
        var currentSession = Guid.NewGuid();
        var audit = new AuditContext(actor);
        var proof = new FreshMfaVerificationProof(actor, null, currentSession, _timeProvider.GetUtcNow(), _timeProvider.GetUtcNow().AddMinutes(5), AuthenticationSessionService.SelfServiceProofPurpose);
        var events = new Mock<ISecurityEventSink>();
        var authorizer = new Mock<IAccountSecurityOperationAuthorizer>();
        authorizer.Setup(a => a.AuthorizeAsync(It.IsAny<AccountSecurityAuthorizationContext>(), It.IsAny<CancellationToken>())).ReturnsAsync(false);
        var service = new AuthenticationSessionService(
            _repositoryMock.Object, _tokenHasherMock.Object, new FixedSessionTokenGenerator("raw-token"), new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(_userRepositoryMock.Object, TimeProvider: _timeProvider,
                SecurityEventSink: events.Object, OperationAuthorizer: authorizer.Object));

        Assert.ThrowsAsync<AshlarOperationException>(() => service.RevokeOtherSessionsForCurrentUserAsync(
            new RevokeOwnOtherAuthenticationSessionsRequest(actor, TenantContext.Global, currentSession, proof, audit)));

        events.Verify(s => s.RecordAsync(It.Is<AshlarSecurityEvent>(e =>
            e.EventType == AshlarSecurityEventTypes.SessionsRevokedForUser && e.Outcome == SecurityEventOutcomes.Failure &&
            e.UserId == actor && e.ActorUserId == actor && e.SessionId == null), It.IsAny<CancellationToken>()), Times.Once);
        _repositoryMock.Verify(r => r.RevokeOtherSessionsForUserAsync(It.IsAny<Guid>(), It.IsAny<Guid>(), It.IsAny<DateTimeOffset>(),
            It.IsAny<string?>(), It.IsAny<TenantContext?>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public void RevokeSessionForCurrentUserAsyncShouldAuditBoundValidationDenialsOnceWithoutMutation()
    {
        var actor = Guid.NewGuid();
        var currentSession = Guid.NewGuid();
        var targetSession = Guid.NewGuid();
        var events = new Mock<ISecurityEventSink>();
        var service = new AuthenticationSessionService(
            _repositoryMock.Object, _tokenHasherMock.Object, new FixedSessionTokenGenerator("raw-token"), new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(_userRepositoryMock.Object, TimeProvider: _timeProvider, SecurityEventSink: events.Object));
        var expiredProof = new FreshMfaVerificationProof(actor, null, currentSession,
            _timeProvider.GetUtcNow().AddMinutes(-10), _timeProvider.GetUtcNow().AddMinutes(-5), AuthenticationSessionService.SelfServiceProofPurpose);

        Assert.ThrowsAsync<AshlarOperationException>(() => service.RevokeSessionForCurrentUserAsync(
            new RevokeOwnAuthenticationSessionRequest(actor, TenantContext.Global, currentSession, expiredProof,
                new AuditContext(actor, CorrelationId: "expired"), targetSession)));
        events.Verify(s => s.RecordAsync(It.Is<AshlarSecurityEvent>(e => e.ActorUserId == actor &&
            e.SessionId == targetSession && e.CorrelationId == "expired" && e.FailureReason == AshlarFailureCodes.StepUpExpiredValue),
            It.IsAny<CancellationToken>()), Times.Once);

        events.Invocations.Clear();
        var validProof = new FreshMfaVerificationProof(actor, null, currentSession, _timeProvider.GetUtcNow(), _timeProvider.GetUtcNow().AddMinutes(5), AuthenticationSessionService.SelfServiceProofPurpose);
        Assert.ThrowsAsync<AshlarOperationException>(() => service.RevokeSessionForCurrentUserAsync(
            new RevokeOwnAuthenticationSessionRequest(actor, TenantContext.Global, currentSession, validProof,
                new AuditContext(Guid.NewGuid(), IpAddress: "untrusted", CorrelationId: "mismatch"), targetSession)));
        events.Verify(s => s.RecordAsync(It.Is<AshlarSecurityEvent>(e => e.ActorUserId == actor && e.IpAddress == null &&
            e.SessionId == targetSession && e.CorrelationId == null && e.FailureReason == AshlarFailureCodes.ValidationErrorValue),
            It.IsAny<CancellationToken>()), Times.Once);

        events.Invocations.Clear();
        Assert.ThrowsAsync<AshlarOperationException>(() => service.RevokeOtherSessionsForCurrentUserAsync(
            new RevokeOwnOtherAuthenticationSessionsRequest(actor, TenantContext.Global, currentSession, expiredProof,
                new AuditContext(actor, CorrelationId: "other-expired"))));
        events.Verify(s => s.RecordAsync(It.Is<AshlarSecurityEvent>(e => e.EventType == AshlarSecurityEventTypes.SessionsRevokedForUser &&
            e.ActorUserId == actor && e.SessionId == null && e.CorrelationId == "other-expired" &&
            e.FailureReason == AshlarFailureCodes.StepUpExpiredValue), It.IsAny<CancellationToken>()), Times.Once);

        events.Invocations.Clear();
        Assert.ThrowsAsync<AshlarOperationException>(() => service.RevokeOtherSessionsForCurrentUserAsync(
            new RevokeOwnOtherAuthenticationSessionsRequest(actor, TenantContext.Global, currentSession, validProof,
                new AuditContext(Guid.NewGuid(), IpAddress: "untrusted"))));
        events.Verify(s => s.RecordAsync(It.Is<AshlarSecurityEvent>(e => e.EventType == AshlarSecurityEventTypes.SessionsRevokedForUser &&
            e.ActorUserId == actor && e.SessionId == null && e.IpAddress == null && e.CorrelationId == null &&
            e.FailureReason == AshlarFailureCodes.ValidationErrorValue), It.IsAny<CancellationToken>()), Times.Once);
        _repositoryMock.Verify(r => r.RevokeSessionByIdAsync(It.IsAny<Guid>(), It.IsAny<Guid>(), It.IsAny<DateTimeOffset>(),
            It.IsAny<string?>(), It.IsAny<TenantContext?>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
        _repositoryMock.Verify(r => r.RevokeOtherSessionsForUserAsync(It.IsAny<Guid>(), It.IsAny<Guid>(), It.IsAny<DateTimeOffset>(),
            It.IsAny<string?>(), It.IsAny<TenantContext?>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public void CreateSessionAsyncShouldValidateAshlarAuthenticationResultRequestBeforeMutation()
    {
        var result = new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, new User { Id = Guid.NewGuid(), DisplayEmail = "user@example.com" })
        {
            SessionIssuanceProof = AuthenticationSessionIssuanceProof.Instance
        };

        Assert.ThrowsAsync<ArgumentNullException>(() => _service.CreateSessionAsync(result, null!));
        Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => _service.CreateSessionAsync(result, new CreateAuthenticationSessionRequest(Lifetime: TimeSpan.Zero)));
        _repositoryMock.Verify(r => r.CreateSessionAsync(It.IsAny<AuthenticationSession>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task CreateSessionAsyncShouldOmitOptionalSessionContextForAshlarAuthenticationResultWhenDisabled()
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
        var result = new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, new User { Id = Guid.NewGuid(), DisplayEmail = "user@example.com" })
        {
            SessionIssuanceProof = AuthenticationSessionIssuanceProof.Instance
        };

        AuthenticationSession? storedSession = null;
        _repositoryMock
            .Setup(r => r.CreateSessionAsync(It.IsAny<AuthenticationSession>(), It.IsAny<CancellationToken>()))
            .Callback<AuthenticationSession, CancellationToken>((session, _) => storedSession = session)
            .Returns(Task.CompletedTask);

        await service.CreateSessionAsync(
            result,
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
    public async Task MarkStepUpVerifiedAsyncShouldRejectResultWithoutAshlarStepUpProofBeforeMutation()
    {
        var result = new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, new User { Id = Guid.NewGuid(), DisplayEmail = "user@example.com" }, FreshMfaSatisfied: true);

        var mark = await _service.MarkStepUpVerifiedAsync(result, new MarkSessionStepUpVerifiedRequest
        {
            SessionId = Guid.NewGuid(),
            VerifiedProvider = AuthenticationProviderKey.Passkey,
            VerifiedFactor = "passkey"
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(mark.Succeeded, Is.False);
            Assert.That(mark.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            _repositoryMock.Verify(r => r.MarkStepUpVerifiedAsync(It.IsAny<Guid>(), It.IsAny<Guid>(), It.IsAny<DateTimeOffset>(), It.IsAny<AuthenticationProviderKey>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task MarkStepUpVerifiedAsyncShouldRejectIncompleteStepUpResultsBeforeMutation()
    {
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "user@example.com" };
        var failed = new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, user, FreshMfaSatisfied: true)
        {
            StepUpSessionMarkingProof = StepUpSessionMarkingProof.Instance
        };
        var missingUser = new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, null, FreshMfaSatisfied: true)
        {
            StepUpSessionMarkingProof = StepUpSessionMarkingProof.Instance
        };
        var emptyUserId = new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, new User { Id = Guid.Empty, DisplayEmail = "user@example.com" }, FreshMfaSatisfied: true)
        {
            StepUpSessionMarkingProof = StepUpSessionMarkingProof.Instance
        };
        var staleMfa = new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, user)
        {
            StepUpSessionMarkingProof = StepUpSessionMarkingProof.Instance
        };
        var request = new MarkSessionStepUpVerifiedRequest
        {
            SessionId = Guid.NewGuid(),
            VerifiedProvider = AuthenticationProviderKey.Passkey,
            VerifiedFactor = "passkey"
        };

        var failedMark = await _service.MarkStepUpVerifiedAsync(failed, request);
        var missingUserMark = await _service.MarkStepUpVerifiedAsync(missingUser, request);
        var emptyUserIdMark = await _service.MarkStepUpVerifiedAsync(emptyUserId, request);
        var staleMfaMark = await _service.MarkStepUpVerifiedAsync(staleMfa, request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(failedMark.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            Assert.That(missingUserMark.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            Assert.That(emptyUserIdMark.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            Assert.That(staleMfaMark.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            _repositoryMock.Verify(r => r.MarkStepUpVerifiedAsync(It.IsAny<Guid>(), It.IsAny<Guid>(), It.IsAny<DateTimeOffset>(), It.IsAny<AuthenticationProviderKey>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task MarkStepUpVerifiedAsyncShouldUpdateSessionForAshlarStepUpResult()
    {
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var session = new AuthenticationSession
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            TokenHash = "hash",
            TenantId = tenantId,
            CreatedAt = _timeProvider.GetUtcNow().AddMinutes(-5),
            ExpiresAt = _timeProvider.GetUtcNow().AddHours(1)
        };
        var provider = new AuthenticationProviderKey(ProviderType.Mfa, "totp");
        _repositoryMock
            .Setup(r => r.MarkStepUpVerifiedAsync(session.Id, userId, _timeProvider.GetUtcNow(), provider, "totp", It.IsAny<CancellationToken>()))
            .ReturnsAsync(session);
        var result = new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, new User { Id = userId, DisplayEmail = "user@example.com", TenantId = tenantId }, FreshMfaSatisfied: true)
        {
            StepUpSessionMarkingProof = StepUpSessionMarkingProof.Instance
        };

        var mark = await _service.MarkStepUpVerifiedAsync(result, new MarkSessionStepUpVerifiedRequest
        {
            SessionId = session.Id,
            VerifiedProvider = provider,
            VerifiedFactor = "totp",
            Tenant = new TenantContext(tenantId)
        });

        Assert.That(mark.Value, Is.EqualTo(session));
    }

    [TestCase(false)]
    [TestCase(true)]
    public async Task MarkStepUpVerifiedAsyncShouldRejectTenantMismatchForAshlarStepUpResultBeforeMutation(bool requestedTenantIsNull)
    {
        var provider = new AuthenticationProviderKey(ProviderType.Mfa, "totp");
        var result = new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, new User { Id = Guid.NewGuid(), DisplayEmail = "user@example.com", TenantId = Guid.NewGuid() }, FreshMfaSatisfied: true)
        {
            StepUpSessionMarkingProof = StepUpSessionMarkingProof.Instance
        };

        var mark = await _service.MarkStepUpVerifiedAsync(result, new MarkSessionStepUpVerifiedRequest
        {
            SessionId = Guid.NewGuid(),
            VerifiedProvider = provider,
            VerifiedFactor = "totp",
            Tenant = requestedTenantIsNull ? null : new TenantContext(Guid.NewGuid())
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(mark.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            _repositoryMock.Verify(r => r.MarkStepUpVerifiedAsync(It.IsAny<Guid>(), It.IsAny<Guid>(), It.IsAny<DateTimeOffset>(), It.IsAny<AuthenticationProviderKey>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public void MarkStepUpVerifiedAsyncShouldValidateAshlarStepUpResultRequestBeforeMutation()
    {
        var provider = new AuthenticationProviderKey(ProviderType.Mfa, "totp");
        var result = new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, new User { Id = Guid.NewGuid(), DisplayEmail = "user@example.com" }, FreshMfaSatisfied: true)
        {
            StepUpSessionMarkingProof = StepUpSessionMarkingProof.Instance
        };

        Assert.ThrowsAsync<ArgumentNullException>(() => _service.MarkStepUpVerifiedAsync(result, null!));
        Assert.ThrowsAsync<ArgumentException>(() => _service.MarkStepUpVerifiedAsync(result, new MarkSessionStepUpVerifiedRequest
        {
            SessionId = Guid.Empty,
            VerifiedProvider = provider,
            VerifiedFactor = "totp"
        }));
        _repositoryMock.Verify(r => r.MarkStepUpVerifiedAsync(It.IsAny<Guid>(), It.IsAny<Guid>(), It.IsAny<DateTimeOffset>(), It.IsAny<AuthenticationProviderKey>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task CreateSessionAsyncShouldReturnRawTokenAndStoreOnlyTokenHash()
    {
        AuthenticationSession? storedSession = null;
        _repositoryMock
            .Setup(r => r.CreateSessionAsync(It.IsAny<AuthenticationSession>(), It.IsAny<CancellationToken>()))
            .Callback<AuthenticationSession, CancellationToken>((session, _) => storedSession = session)
            .Returns(Task.CompletedTask);

        var result = await _service.CreateSessionForAuthenticatedUserAsync(Guid.NewGuid(), new CreateAuthenticationSessionRequest());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Token, Is.EqualTo("raw-token"));
            Assert.That(result.Session.Id, Is.EqualTo(storedSession?.Id));
            Assert.That(result.Session.ExpiresAt, Is.EqualTo(storedSession?.ExpiresAt));
            Assert.That(storedSession?.TokenHash, Is.EqualTo("hashed:raw-token"));
            Assert.That(storedSession?.TokenHash, Is.Not.EqualTo(result.Token));
        }
    }

    [Test]
    public async Task CreateSessionAsyncResultShouldNotExposeTokenHash()
    {
        var result = await _service.CreateSessionForAuthenticatedUserAsync(Guid.NewGuid(), new CreateAuthenticationSessionRequest());
        var json = JsonSerializer.Serialize(result);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Session.GetType().GetProperty("TokenHash"), Is.Null);
            Assert.That(json, Does.Not.Contain("TokenHash"));
            Assert.That(json, Does.Not.Contain("hashed:raw-token"));
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

        await _service.CreateSessionForAuthenticatedUserAsync(Guid.NewGuid(), new CreateAuthenticationSessionRequest());

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

        await _service.CreateSessionForAuthenticatedUserAsync(Guid.NewGuid(), new CreateAuthenticationSessionRequest(Lifetime: TimeSpan.FromHours(2)));

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

        await _service.CreateSessionForAuthenticatedUserAsync(
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

        await _service.CreateSessionForAuthenticatedUserAsync(
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
    public void AuthenticationSessionServiceInterfaceShouldNotExposeRawTargetRevocation()
    {
        var methodNames = typeof(IAuthenticationSessionService).GetMethods().Select(method => method.Name).ToArray();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(methodNames, Does.Not.Contain("RevokeSessionsForUserAsync"));
            Assert.That(methodNames, Does.Not.Contain("RevokeSessionForUserAsync"));
            Assert.That(methodNames, Does.Not.Contain("RevokeOtherSessionsAsync"));
            Assert.That(methodNames, Does.Contain(nameof(IAuthenticationSessionService.RevokeSessionForCurrentUserAsync)));
            Assert.That(methodNames, Does.Contain(nameof(IAuthenticationSessionService.RevokeOtherSessionsForCurrentUserAsync)));
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

        await service.CreateSessionForAuthenticatedUserAsync(
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
        Assert.ThrowsAsync<ArgumentException>(() => _service.CreateSessionForAuthenticatedUserAsync(Guid.Empty, new CreateAuthenticationSessionRequest()));
    }

    [Test]
    public void CreateSessionAsyncShouldRejectNullRequest()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(() => _service.CreateSessionForAuthenticatedUserAsync(Guid.NewGuid(), null!));
    }

    [Test]
    public void CreateSessionAsyncShouldRejectNonPositiveRequestedLifetime()
    {
        Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            _service.CreateSessionForAuthenticatedUserAsync(Guid.NewGuid(), new CreateAuthenticationSessionRequest(Lifetime: TimeSpan.Zero)));
    }

    [Test]
    public void CreateSessionAsyncShouldRejectUnconfiguredPrimaryProvider()
    {
        var request = new CreateAuthenticationSessionRequest(
            PrimaryProvider: new AuthenticationProviderKey((ProviderType)ProviderType.StorageFallbackValue, "unknown"));

        Assert.ThrowsAsync<ArgumentException>(() => _service.CreateSessionForAuthenticatedUserAsync(Guid.NewGuid(), request));
    }

    [Test]
    public void CreateSessionAsyncShouldRejectTooLongIpAddress()
    {
        Assert.ThrowsAsync<ArgumentException>(() =>
            _service.CreateSessionForAuthenticatedUserAsync(Guid.NewGuid(), new CreateAuthenticationSessionRequest(IpAddress: new string('1', 46))));
    }

    [Test]
    public void CreateSessionAsyncShouldRejectTooLongUserAgent()
    {
        Assert.ThrowsAsync<ArgumentException>(() =>
            _service.CreateSessionForAuthenticatedUserAsync(Guid.NewGuid(), new CreateAuthenticationSessionRequest(UserAgent: new string('a', 513))));
    }

    [Test]
    public void CreateSessionAsyncShouldRejectTooLongMetadata()
    {
        Assert.ThrowsAsync<ArgumentException>(() =>
            _service.CreateSessionForAuthenticatedUserAsync(Guid.NewGuid(), new CreateAuthenticationSessionRequest(Metadata: new string('m', 8193))));
    }

    [Test]
    public async Task CreateSessionAsyncShouldSucceedForTenantUserWithMatchingTenant()
    {
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        _userRepositoryMock
            .Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "tenant@example.com", TenantId = tenantId });

        var result = await _service.CreateSessionForAuthenticatedUserAsync(userId, new CreateAuthenticationSessionRequest(TenantId: tenantId));

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
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "global@example.com", TenantId = null });

        var result = await _service.CreateSessionForAuthenticatedUserAsync(userId, new CreateAuthenticationSessionRequest(TenantId: null));

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
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "tenant@example.com", TenantId = userTenantId });

        var exception = Assert.ThrowsAsync<AshlarOperationException>(async () =>
            await _service.CreateSessionForAuthenticatedUserAsync(userId, new CreateAuthenticationSessionRequest(TenantId: requestedTenantId)));

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
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "global@example.com", TenantId = null });

        var exception = Assert.ThrowsAsync<AshlarOperationException>(async () =>
            await _service.CreateSessionForAuthenticatedUserAsync(userId, new CreateAuthenticationSessionRequest(TenantId: Guid.NewGuid())));

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
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "tenant@example.com", TenantId = tenantId });
        var service = new AuthenticationSessionService(
            _repositoryMock.Object,
            tokenHasher.Object,
            tokenGenerator,
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(TimeProvider: _timeProvider, UserRepository: _userRepositoryMock.Object));

        var exception = Assert.ThrowsAsync<AshlarOperationException>(async () =>
            await service.CreateSessionForAuthenticatedUserAsync(userId, new CreateAuthenticationSessionRequest(TenantId: Guid.NewGuid())));

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
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "user@example.com", AccountState = accountState, TenantId = tenantId });
        var service = new AuthenticationSessionService(
            _repositoryMock.Object,
            tokenHasher.Object,
            tokenGenerator,
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(TimeProvider: _timeProvider, SecurityEventSink: sink, UserRepository: _userRepositoryMock.Object));

        var exception = Assert.ThrowsAsync<AshlarOperationException>(async () =>
            await service.CreateSessionForAuthenticatedUserAsync(userId, new CreateAuthenticationSessionRequest(
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
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "tenant@example.com", TenantId = userTenantId });
        var service = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(TimeProvider: _timeProvider, SecurityEventSink: sink, UserRepository: _userRepositoryMock.Object));

        Assert.ThrowsAsync<AshlarOperationException>(async () =>
            await service.CreateSessionForAuthenticatedUserAsync(userId, new CreateAuthenticationSessionRequest(TenantId: requestedTenantId)));

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
            await service.CreateSessionForAuthenticatedUserAsync(userId, new CreateAuthenticationSessionRequest(
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
        session.AdditionalVerificationAt = _timeProvider.GetUtcNow();
        _repositoryMock
            .Setup(r => r.GetSessionByTokenHashAsync("hashed:raw-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(session);
        _repositoryMock
            .Setup(r => r.UpdateSessionLastSeenAsync(session.Id, _timeProvider.GetUtcNow(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var result = await _service.ValidateSessionAsync("raw-token");
        var proof = new StepUpAuthenticationService(_timeProvider).CreateFreshMfaProof(
            result.ValidatedSession!, new StepUpRequirement(TimeSpan.FromMinutes(5)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Status, Is.EqualTo(AuthenticationSessionValidationStatus.Succeeded));
            Assert.That(result.ValidatedSession, Is.Not.Null);
            Assert.That(result.Session, Is.EqualTo(session));
            Assert.That(result.UserId, Is.EqualTo(session.UserId));
            Assert.That(proof.Value?.SessionId, Is.EqualTo(session.Id));
        }
    }

    [Test]
    public void RevokeCurrentSessionAsyncShouldRejectAuditMismatchBeforeValidationMutation()
    {
        var session = CreateSession(expiresAt: _timeProvider.GetUtcNow().AddHours(1));
        _repositoryMock
            .Setup(r => r.GetSessionByTokenHashAsync("hashed:raw-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(session);

        Assert.ThrowsAsync<AshlarOperationException>(() => _service.RevokeCurrentSessionAsync(
            new RevokeCurrentAuthenticationSessionRequest("raw-token", new AuditContext(Guid.NewGuid()))));
        using (Assert.EnterMultipleScope())
        {
            _repositoryMock.Verify(r => r.GetSessionByTokenHashAsync("hashed:raw-token", It.IsAny<CancellationToken>()), Times.Once);
            _repositoryMock.Verify(r => r.UpdateSessionLastSeenAsync(It.IsAny<Guid>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Never);
            _repositoryMock.Verify(r => r.RevokeSessionByIdAsync(It.IsAny<Guid>(), It.IsAny<Guid>(), It.IsAny<DateTimeOffset>(),
                It.IsAny<string?>(), It.IsAny<TenantContext?>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task RevokeCurrentSessionAsyncShouldReturnFalseForUnknownTokenAndRevokeTenantSession()
    {
        var actor = Guid.NewGuid();
        var tenantId = Guid.NewGuid();

        Assert.That(await _service.RevokeCurrentSessionAsync(
            new RevokeCurrentAuthenticationSessionRequest("unknown", new AuditContext(actor))), Is.False);

        var session = CreateSession(expiresAt: _timeProvider.GetUtcNow().AddHours(1), userId: actor, tenantId: tenantId);
        _repositoryMock.Setup(r => r.GetSessionByTokenHashAsync("hashed:raw-token", It.IsAny<CancellationToken>())).ReturnsAsync(session);
        _userRepositoryMock.Setup(r => r.GetUserByIdAsync(actor, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = actor, DisplayEmail = "tenant@example.com", TenantId = tenantId });
        _repositoryMock.Setup(r => r.RevokeSessionByIdAsync(session.Id, actor, _timeProvider.GetUtcNow(), null,
            It.Is<TenantContext>(t => t.TenantId == tenantId), false, It.IsAny<CancellationToken>())).ReturnsAsync(true);

        Assert.That(await _service.RevokeCurrentSessionAsync(
            new RevokeCurrentAuthenticationSessionRequest("raw-token", new AuditContext(actor))), Is.True);
    }

    [Test]
    public async Task ValidateSessionAsyncShouldSucceedForTenantUserWithMatchingTenantSession()
    {
        var tenantId = Guid.NewGuid();
        var session = CreateSession(expiresAt: _timeProvider.GetUtcNow().AddHours(1), userId: Guid.NewGuid(), tenantId: tenantId);
        _repositoryMock
            .Setup(r => r.GetSessionByTokenHashAsync("hashed:raw-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(session);
        _userRepositoryMock
            .Setup(r => r.GetUserByIdAsync(session.UserId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = session.UserId, DisplayEmail = "tenant@example.com", TenantId = tenantId });
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

    [TestCase(true, false)]
    [TestCase(true, true)]
    [TestCase(false, true)]
    public async Task ValidateSessionAsyncShouldFailWhenSessionTenantDoesNotMatchCurrentUserTenant(bool userHasTenant, bool sessionHasTenant)
    {
        var sink = new RecordingSecurityEventSink();
        var userTenantId = userHasTenant ? Guid.NewGuid() : (Guid?)null;
        var sessionTenantId = sessionHasTenant ? Guid.NewGuid() : (Guid?)null;
        var session = CreateSession(expiresAt: _timeProvider.GetUtcNow().AddHours(1), userId: Guid.NewGuid(), tenantId: sessionTenantId);
        _repositoryMock
            .Setup(r => r.GetSessionByTokenHashAsync("hashed:raw-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(session);
        _userRepositoryMock
            .Setup(r => r.GetUserByIdAsync(session.UserId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = session.UserId, DisplayEmail = "user@example.com", TenantId = userTenantId });
        var service = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(TimeProvider: _timeProvider, SecurityEventSink: sink, UserRepository: _userRepositoryMock.Object));

        var result = await service.ValidateSessionAsync("raw-token");

        using (Assert.EnterMultipleScope())
        {
            var securityEvent = sink.Events.Single();
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.Status, Is.EqualTo(AuthenticationSessionValidationStatus.Failed));
            Assert.That(result.Session, Is.EqualTo(session));
            Assert.That(result.UserId, Is.EqualTo(session.UserId));
            Assert.That(securityEvent.TenantId, Is.EqualTo(sessionTenantId));
            Assert.That(securityEvent.FailureReason, Is.EqualTo(AshlarFailureCodes.TenantMismatchValue));
        }

        _repositoryMock.Verify(r => r.UpdateSessionLastSeenAsync(It.IsAny<Guid>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Never);
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
            .ReturnsAsync(new User { Id = session.UserId, DisplayEmail = "user@example.com", AccountState = accountState });
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

        var result = await _service.MarkStepUpVerifiedForVerifiedUserAsync(userId, new MarkSessionStepUpVerifiedRequest
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

        var result = await _service.MarkStepUpVerifiedForVerifiedUserAsync(userId, new MarkSessionStepUpVerifiedRequest
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
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "user@example.com", AccountState = accountState, TenantId = tenantId });

        var result = await service.MarkStepUpVerifiedForVerifiedUserAsync(userId, new MarkSessionStepUpVerifiedRequest
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
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "user@example.com", AccountState = UserAccountState.Disabled });

        var result = await service.MarkStepUpVerifiedForVerifiedUserAsync(userId, new MarkSessionStepUpVerifiedRequest
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
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "tenant@example.com", TenantId = userTenantId });

        var result = await _service.MarkStepUpVerifiedForVerifiedUserAsync(userId, new MarkSessionStepUpVerifiedRequest
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
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "global@example.com" });

        var result = await _service.MarkStepUpVerifiedForVerifiedUserAsync(userId, new MarkSessionStepUpVerifiedRequest
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
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "tenant@example.com", TenantId = Guid.NewGuid() });

        await service.MarkStepUpVerifiedForVerifiedUserAsync(userId, new MarkSessionStepUpVerifiedRequest
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

        await service.MarkStepUpVerifiedForVerifiedUserAsync(userId, new MarkSessionStepUpVerifiedRequest
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
    public async Task MarkStepUpVerifiedAsyncShouldAuditUpdatedSessionTenant()
    {
        var sink = new RecordingSecurityEventSink();
        var service = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(TimeProvider: _timeProvider, SecurityEventSink: sink, UserRepository: _userRepositoryMock.Object));
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var session = CreateSession(expiresAt: _timeProvider.GetUtcNow().AddHours(1), userId: userId, tenantId: tenantId);
        _userRepositoryMock
            .Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "test@example.com", TenantId = tenantId });
        _repositoryMock
            .Setup(r => r.MarkStepUpVerifiedAsync(session.Id, userId, _timeProvider.GetUtcNow(), AuthenticationProviderKey.Passkey, "passkey", It.IsAny<CancellationToken>()))
            .ReturnsAsync(session);

        await service.MarkStepUpVerifiedForVerifiedUserAsync(userId, new MarkSessionStepUpVerifiedRequest
        {
            SessionId = session.Id,
            VerifiedProvider = AuthenticationProviderKey.Passkey,
            VerifiedFactor = "passkey",
            Tenant = new TenantContext(tenantId)
        });

        var securityEvent = sink.Events.Single(e => e.EventType == AshlarSecurityEventTypes.SessionStepUpVerified);
        Assert.That(securityEvent.TenantId, Is.EqualTo(tenantId));
    }

    [Test]
    public async Task MarkStepUpVerifiedAsyncShouldAuditMissingSessionWithRequestedTenant()
    {
        var sink = new RecordingSecurityEventSink();
        var service = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(TimeProvider: _timeProvider, SecurityEventSink: sink, UserRepository: _userRepositoryMock.Object));
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        _userRepositoryMock
            .Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "test@example.com", TenantId = tenantId });
        _repositoryMock
            .Setup(r => r.MarkStepUpVerifiedAsync(sessionId, userId, _timeProvider.GetUtcNow(), AuthenticationProviderKey.Passkey, "passkey", It.IsAny<CancellationToken>()))
            .ReturnsAsync((AuthenticationSession?)null);

        await service.MarkStepUpVerifiedForVerifiedUserAsync(userId, new MarkSessionStepUpVerifiedRequest
        {
            SessionId = sessionId,
            VerifiedProvider = AuthenticationProviderKey.Passkey,
            VerifiedFactor = "passkey",
            Tenant = new TenantContext(tenantId)
        });

        var securityEvent = sink.Events.Single(e => e.EventType == AshlarSecurityEventTypes.SessionStepUpVerified);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(securityEvent.Outcome, Is.EqualTo(SecurityEventOutcomes.Failure));
            Assert.That(securityEvent.TenantId, Is.EqualTo(tenantId));
            Assert.That(securityEvent.FailureReason, Is.EqualTo(AshlarFailureCodes.SessionNotFoundOrInactiveValue));
        }
    }

    [Test]
    public void MarkStepUpVerifiedAsyncShouldRejectInvalidInput()
    {
        var provider = new AuthenticationProviderKey(ProviderType.Mfa, "totp");

        Assert.ThrowsAsync<ArgumentException>(() => _service.MarkStepUpVerifiedForVerifiedUserAsync(Guid.Empty, new MarkSessionStepUpVerifiedRequest { SessionId = Guid.NewGuid(), VerifiedProvider = provider, VerifiedFactor = "totp" }));
        Assert.ThrowsAsync<ArgumentException>(() => _service.MarkStepUpVerifiedForVerifiedUserAsync(Guid.NewGuid(), new MarkSessionStepUpVerifiedRequest { SessionId = Guid.Empty, VerifiedProvider = provider, VerifiedFactor = "totp" }));
        Assert.ThrowsAsync<ArgumentException>(() => _service.MarkStepUpVerifiedForVerifiedUserAsync(Guid.NewGuid(), new MarkSessionStepUpVerifiedRequest { SessionId = Guid.NewGuid(), VerifiedProvider = default, VerifiedFactor = "totp" }));
        Assert.ThrowsAsync<ArgumentException>(() => _service.MarkStepUpVerifiedForVerifiedUserAsync(Guid.NewGuid(), new MarkSessionStepUpVerifiedRequest { SessionId = Guid.NewGuid(), VerifiedProvider = new AuthenticationProviderKey((ProviderType)ProviderType.StorageFallbackValue, "unknown"), VerifiedFactor = "totp" }));
        Assert.ThrowsAsync<ArgumentException>(() => _service.MarkStepUpVerifiedForVerifiedUserAsync(Guid.NewGuid(), new MarkSessionStepUpVerifiedRequest { SessionId = Guid.NewGuid(), VerifiedProvider = provider, VerifiedFactor = " " }));
        Assert.ThrowsAsync<ArgumentException>(() => _service.MarkStepUpVerifiedForVerifiedUserAsync(Guid.NewGuid(), new MarkSessionStepUpVerifiedRequest { SessionId = Guid.NewGuid(), VerifiedProvider = provider, VerifiedFactor = new string('x', 129) }));
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
            .Setup(r => r.RevokeSessionsForUserAsync(userId, now, "password-reset", TenantContext.Global, false, It.IsAny<CancellationToken>()))
            .ReturnsAsync(3);

        var request = new RevokeAuthenticationSessionsForUserRequest(new AuditContext(userId), TenantContext.Global, "password-reset");
        var revoked = await _service.RevokeSessionsForUserAsync(userId, request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revoked, Is.EqualTo(3));
            _repositoryMock.Verify(r => r.RevokeSessionsForUserAsync(userId, now, "password-reset", TenantContext.Global, false, It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [Test]
    public void RevokeSessionsForUserAsyncShouldRejectEmptyUserId()
    {
        Assert.ThrowsAsync<ArgumentException>(() => _service.RevokeSessionsForUserAsync(Guid.Empty, new RevokeAuthenticationSessionsForUserRequest(new AuditContext(Guid.NewGuid()), TenantContext.Global)));
    }

    [Test]
    public void RevokeSessionsForUserAsyncShouldRejectMissingAuditBeforeMutation()
    {
        Assert.ThrowsAsync<ArgumentNullException>(() => _service.RevokeSessionsForUserAsync(Guid.NewGuid(), new RevokeAuthenticationSessionsForUserRequest(null!, TenantContext.Global)));
        _repositoryMock.Verify(r => r.RevokeSessionsForUserAsync(It.IsAny<Guid>(), It.IsAny<DateTimeOffset>(), It.IsAny<string?>(), It.IsAny<TenantContext?>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public void RevokeSessionsForUserAsyncShouldRejectAmbiguousScopeBeforeMutation()
    {
        Assert.ThrowsAsync<ArgumentException>(() => _service.RevokeSessionsForUserAsync(Guid.NewGuid(), new RevokeAuthenticationSessionsForUserRequest(new AuditContext(Guid.NewGuid()), null)));
        _repositoryMock.Verify(r => r.RevokeSessionsForUserAsync(It.IsAny<Guid>(), It.IsAny<DateTimeOffset>(), It.IsAny<string?>(), It.IsAny<TenantContext?>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task RevokeSessionsForUserAsyncShouldNotifyAllSessionsRevoked()
    {
        var userId = Guid.NewGuid();
        var now = _timeProvider.GetUtcNow();
        var user = new User { Id = userId, DisplayEmail = "user@example.com" };
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
            .Setup(r => r.RevokeSessionsForUserAsync(userId, now, "password-reset", It.Is<TenantContext?>(t => t != null), false, It.IsAny<CancellationToken>()))
            .ReturnsAsync(2);
        userRepository
            .Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        await service.RevokeSessionsForUserAsync(userId, new RevokeAuthenticationSessionsForUserRequest(new AuditContext(userId), new TenantContext(Guid.NewGuid()), "password-reset"));

        notificationService.Verify(n => n.NotifyAsync(It.Is<SecurityNotification>(notification =>
            notification.Type == SecurityNotificationType.AllSessionsRevoked &&
            notification.RecipientEmail == user.DisplayEmail &&
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
            .Setup(r => r.RevokeSessionByIdAsync(sessionId, userId, now, "user-initiated", null, true, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var revoked = await _service.RevokeSessionForUserAsync(userId, new RevokeAuthenticationSessionRequest { SessionId = sessionId, Reason = "user-initiated", IncludeAllTenants = true, Audit = new AuditContext(userId) });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revoked, Is.True);
            _repositoryMock.Verify(r => r.RevokeSessionByIdAsync(sessionId, userId, now, "user-initiated", null, true, It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [Test]
    public async Task RevokeSessionForUserAsyncShouldNotifyWithAuditContext()
    {
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var secondSessionId = Guid.NewGuid();
        var now = _timeProvider.GetUtcNow();
        var user = new User { Id = userId, DisplayEmail = "user@example.com" };
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
            .Setup(r => r.RevokeSessionByIdAsync(sessionId, userId, now, null, It.Is<TenantContext?>(t => t != null), false, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
        _repositoryMock
            .Setup(r => r.RevokeSessionByIdAsync(secondSessionId, userId, now, null, null, true, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
        userRepository
            .Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var revoked = await service.RevokeSessionForUserAsync(userId, new RevokeAuthenticationSessionRequest { SessionId = sessionId, Tenant = new TenantContext(Guid.NewGuid()), Audit = audit });
        var secondRevoked = await service.RevokeSessionForUserAsync(userId, new RevokeAuthenticationSessionRequest { SessionId = secondSessionId, IncludeAllTenants = true, Audit = audit });

        Assert.That(revoked && secondRevoked, Is.True);
        notificationService.Verify(n => n.NotifyAsync(It.Is<SecurityNotification>(notification =>
            notification.Type == SecurityNotificationType.SessionRevoked &&
            notification.IpAddress == "203.0.113.60" &&
            notification.UserAgent == "session-agent"), It.IsAny<CancellationToken>()), Times.Exactly(2));
    }

    [Test]
    public void RevokeSessionForUserAsyncShouldRejectMissingAuditBeforeMutation()
    {
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var now = _timeProvider.GetUtcNow();
        Assert.ThrowsAsync<ArgumentNullException>(() => _service.RevokeSessionForUserAsync(userId, new RevokeAuthenticationSessionRequest { SessionId = sessionId, Tenant = TenantContext.Global }));
        _repositoryMock.Verify(r => r.RevokeSessionByIdAsync(It.IsAny<Guid>(), It.IsAny<Guid>(), It.IsAny<DateTimeOffset>(), It.IsAny<string?>(), It.IsAny<TenantContext?>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public void RevokeSessionForUserAsyncShouldRejectMissingScopeBeforeMutation()
    {
        Assert.ThrowsAsync<ArgumentException>(() => _service.RevokeSessionForUserAsync(
            Guid.NewGuid(),
            new RevokeAuthenticationSessionRequest { SessionId = Guid.NewGuid(), Audit = new AuditContext(Guid.NewGuid()) }));
        _repositoryMock.Verify(r => r.RevokeSessionByIdAsync(It.IsAny<Guid>(), It.IsAny<Guid>(), It.IsAny<DateTimeOffset>(), It.IsAny<string?>(), It.IsAny<TenantContext?>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
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
            new RevokeAuthenticationSessionRequest { SessionId = Guid.NewGuid(), Reason = new string('x', 513), Tenant = TenantContext.Global, Audit = new AuditContext(Guid.NewGuid()) }));
    }

    [Test]
    public async Task RevokeOtherSessionsAsyncShouldPassCurrentTimeAndReason()
    {
        var userId = Guid.NewGuid();
        var currentSessionId = Guid.NewGuid();
        var now = _timeProvider.GetUtcNow();
        _repositoryMock
            .Setup(r => r.RevokeOtherSessionsForUserAsync(userId, currentSessionId, now, "security-cleanup", null, true, It.IsAny<CancellationToken>()))
            .ReturnsAsync(5);

        var revoked = await _service.RevokeOtherSessionsAsync(userId, new RevokeOtherAuthenticationSessionsRequest { CurrentSessionId = currentSessionId, Reason = "security-cleanup", IncludeAllTenants = true, Audit = new AuditContext(userId) });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revoked, Is.EqualTo(5));
            _repositoryMock.Verify(r => r.RevokeOtherSessionsForUserAsync(userId, currentSessionId, now, "security-cleanup", null, true, It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [Test]
    public async Task RevokeOtherSessionsAsyncShouldAuditTenantScope()
    {
        var sink = new RecordingSecurityEventSink();
        var service = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(TimeProvider: _timeProvider, SecurityEventSink: sink, UserRepository: _userRepositoryMock.Object));
        var userId = Guid.NewGuid();
        var currentSessionId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        _repositoryMock
            .Setup(r => r.RevokeOtherSessionsForUserAsync(userId, currentSessionId, _timeProvider.GetUtcNow(), null, It.Is<TenantContext>(t => t.TenantId == tenantId), false, It.IsAny<CancellationToken>()))
            .ReturnsAsync(0);

        await service.RevokeOtherSessionsAsync(userId, new RevokeOtherAuthenticationSessionsRequest
        {
            CurrentSessionId = currentSessionId,
            Tenant = new TenantContext(tenantId),
            Audit = new AuditContext(userId)
        });

        var securityEvent = sink.Events.Single(e => e.EventType == AshlarSecurityEventTypes.SessionsRevokedForUser);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(securityEvent.TenantId, Is.EqualTo(tenantId));
            Assert.That(securityEvent.Properties?["scope"], Is.EqualTo("tenant"));
            Assert.That(securityEvent.Properties?["tenant_id"], Is.EqualTo(tenantId.ToString()));
        }
    }

    [Test]
    public async Task RevokeOtherSessionsAsyncShouldAuditGlobalScope()
    {
        var sink = new RecordingSecurityEventSink();
        var service = new AuthenticationSessionService(
            _repositoryMock.Object,
            _tokenHasherMock.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(TimeProvider: _timeProvider, SecurityEventSink: sink, UserRepository: _userRepositoryMock.Object));
        var userId = Guid.NewGuid();
        var currentSessionId = Guid.NewGuid();
        _repositoryMock
            .Setup(r => r.RevokeOtherSessionsForUserAsync(userId, currentSessionId, _timeProvider.GetUtcNow(), null, TenantContext.Global, false, It.IsAny<CancellationToken>()))
            .ReturnsAsync(0);

        await service.RevokeOtherSessionsAsync(userId, new RevokeOtherAuthenticationSessionsRequest
        {
            CurrentSessionId = currentSessionId,
            Tenant = TenantContext.Global,
            Audit = new AuditContext(userId)
        });

        var securityEvent = sink.Events.Single(e => e.EventType == AshlarSecurityEventTypes.SessionsRevokedForUser);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(securityEvent.TenantId, Is.Null);
            Assert.That(securityEvent.Properties?["scope"], Is.EqualTo("global"));
            Assert.That(securityEvent.Properties!.ContainsKey("tenant_id"), Is.False);
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
    public void RevokeOtherSessionsAsyncShouldRejectMissingScopeBeforeMutation()
    {
        Assert.ThrowsAsync<ArgumentException>(() => _service.RevokeOtherSessionsAsync(
            Guid.NewGuid(),
            new RevokeOtherAuthenticationSessionsRequest { CurrentSessionId = Guid.NewGuid(), Audit = new AuditContext(Guid.NewGuid()) }));
        _repositoryMock.Verify(r => r.RevokeOtherSessionsForUserAsync(It.IsAny<Guid>(), It.IsAny<Guid>(), It.IsAny<DateTimeOffset>(), It.IsAny<string?>(), It.IsAny<TenantContext?>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
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
            new RevokeOtherAuthenticationSessionsRequest { CurrentSessionId = Guid.NewGuid(), Reason = new string('x', 513), Tenant = TenantContext.Global, Audit = new AuditContext(Guid.NewGuid()) }));
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

    private AuthenticationSession CreateSession(DateTimeOffset expiresAt, DateTimeOffset? lastSeenAt = null, Guid? userId = null, Guid? tenantId = null)
    {
        return new AuthenticationSession
        {
            Id = Guid.NewGuid(),
            UserId = userId ?? Guid.NewGuid(),
            TenantId = tenantId,
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
