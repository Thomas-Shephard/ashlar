using Ashlar.Auditing;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Identity.Features.Administration;

internal sealed class AccountSecurityOperationBoundaryTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 18, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public void AllTenantResultValidationStillEnforcesExplicitUserFilter()
    {
        var userId = Guid.NewGuid();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(AdministrationScopeValidation.IncludesResult(null, true, Guid.NewGuid(), userId, userId), Is.True);
            Assert.That(AdministrationScopeValidation.IncludesResult(null, true, Guid.NewGuid(), userId, Guid.NewGuid()), Is.False);
            Assert.That(AdministrationScopeValidation.IncludesResult(null, true, Guid.NewGuid(), userId), Is.False);
        }
    }

    [Test]
    public void RequiredBoundaryDependenciesCannotBeNull()
    {
        var sessions = Mock.Of<IAuthenticationSessionRepository>();
        var authorizer = Mock.Of<IAccountSecurityOperationAuthorizer>();
        var sink = Mock.Of<IPersistentSecurityEventSink>();
        var clock = new FakeTimeProvider(Now);

        Assert.Throws<ArgumentNullException>(() => new AccountSecurityOperationBoundary(null!, authorizer, sink, clock));
        Assert.Throws<ArgumentNullException>(() => new AccountSecurityOperationBoundary(sessions, null!, sink, clock));
        Assert.Throws<ArgumentNullException>(() => new AccountSecurityOperationBoundary(sessions, authorizer, null!, clock));
        Assert.Throws<ArgumentNullException>(() => new AccountSecurityOperationBoundary(sessions, authorizer, sink, null!));
    }

    [Test]
    public void ActorContextRequiresAudit()
    {
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var proof = new FreshMfaVerificationProof(userId, null, sessionId, Now, Now.AddMinutes(5), AccountSecurityOperationBoundary.ProofPurpose);

        Assert.Throws<ArgumentNullException>(() => new AccountSecurityActorContext(userId, TenantContext.Global, sessionId, proof, null!));
        Assert.Throws<ArgumentNullException>(() => new AccountSecurityActorContext(userId, TenantContext.Global, sessionId, null!, new AuditContext(userId)));
    }

    [Test]
    public void SplitAdministrationReadersRejectNullActorBeforeProviderAccess()
    {
        var boundary = new AdminReadTestBoundary(Now);
        var users = new Mock<IUserAdministrationRepository>();
        var credentials = new Mock<ICredentialAdministrationRepository>();
        var sessions = new Mock<IAuthenticationSessionAdministrationRepository>();
        var userReader = new UserAdministrationReader(users.Object, new PostureReader(), boundary.Sessions,
            boundary.Authorizer, boundary.Sink, boundary.TimeProvider);
        var credentialReader = new CredentialAdministrationReader(credentials.Object, boundary.Sessions,
            boundary.Authorizer, boundary.Sink, boundary.TimeProvider);
        var sessionReader = new AuthenticationSessionAdministrationReader(sessions.Object, boundary.Sessions,
            boundary.Authorizer, boundary.Sink, boundary.TimeProvider);

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentNullException>(() => userReader.SearchUsersAsync(null!, new() { IncludeAllTenants = true }));
            Assert.ThrowsAsync<ArgumentNullException>(() => userReader.GetUserDetailAsync(null!, new(Guid.NewGuid(), TenantContext.Global)));
            Assert.ThrowsAsync<ArgumentNullException>(() => credentialReader.SearchCredentialsAsync(null!, new() { IncludeAllTenants = true }));
            Assert.ThrowsAsync<ArgumentNullException>(() => credentialReader.GetCredentialAsync(null!, new(Guid.NewGuid(), TenantContext.Global)));
            Assert.ThrowsAsync<ArgumentNullException>(() => sessionReader.SearchAuthenticationSessionsAsync(null!, new() { IncludeAllTenants = true }));
            Assert.ThrowsAsync<ArgumentNullException>(() => sessionReader.GetAuthenticationSessionAsync(null!, new(Guid.NewGuid(), TenantContext.Global)));
        }
        users.VerifyNoOtherCalls();
        credentials.VerifyNoOtherCalls();
        sessions.VerifyNoOtherCalls();
    }

    [Test]
    public async Task EveryAdminReadRejectsMismatchedAuditActorAndInvalidProof()
    {
        var boundary = new AdminReadTestBoundary(Now);
        var mismatched = new AccountSecurityActorContext(boundary.Actor.ActorUserId, boundary.Actor.ActorTenant,
            boundary.Actor.CurrentSessionId, boundary.Actor.FreshMfaProof, new AuditContext(Guid.NewGuid()));
        var missingAuditActor = new AccountSecurityActorContext(boundary.Actor.ActorUserId, boundary.Actor.ActorTenant,
            boundary.Actor.CurrentSessionId, boundary.Actor.FreshMfaProof, new AuditContext());
        var invalidProof = new AccountSecurityActorContext(boundary.Actor.ActorUserId, boundary.Actor.ActorTenant,
            boundary.Actor.CurrentSessionId,
            new FreshMfaVerificationProof(boundary.Actor.ActorUserId, null, boundary.Actor.CurrentSessionId,
                Now, Now.AddMinutes(5), "wrong-purpose"), boundary.Actor.Audit);

        AssertAllFailed(await InvokeAllAsync(mismatched, new AllowByScopeAuthorizer(), boundary.Sessions));
        AssertAllFailed(await InvokeAllAsync(missingAuditActor, new AllowByScopeAuthorizer(), boundary.Sessions));
        AssertAllFailed(await InvokeAllAsync(invalidProof, new AllowByScopeAuthorizer(), boundary.Sessions));

        var service = new CredentialAdministrationReader(Mock.Of<ICredentialAdministrationRepository>(),
            boundary.Sessions, boundary.Authorizer, boundary.Sink, boundary.TimeProvider);
        await service.SearchCredentialsAsync(mismatched, new SearchCredentialsRequest { Tenant = TenantContext.Global });
        Assert.That(boundary.Sink.Events.Single().ActorUserId, Is.EqualTo(boundary.Actor.ActorUserId));
    }

    [Test]
    public async Task EveryAdminReadRejectsRevokedSessionAndUnauthorizedScopes()
    {
        var boundary = new AdminReadTestBoundary(Now);
        var revoked = Mock.Of<IAuthenticationSessionRepository>(repository =>
            repository.GetSessionAsync(boundary.Actor.CurrentSessionId, It.IsAny<CancellationToken>()) ==
            Task.FromResult<AuthenticationSession?>(new AuthenticationSession
            {
                Id = boundary.Actor.CurrentSessionId,
                UserId = boundary.Actor.ActorUserId,
                TokenHash = "test",
                CreatedAt = Now,
                ExpiresAt = Now.AddMinutes(5),
                RevokedAt = Now
            }));

        AssertAllFailed(await InvokeAllAsync(boundary.Actor, new AllowByScopeAuthorizer(), revoked));
        AssertAllFailed(await InvokeAllAsync(boundary.Actor, new DenyAuthorizer(), boundary.Sessions),
            AshlarFailureCodes.AuthorizationDenied);
        AssertAllFailed(await InvokeAllAsync(boundary.Actor, new AllowByScopeAuthorizer(), boundary.Sessions, includeAllTenants: true),
            AshlarFailureCodes.AuthorizationDenied);
    }

    [Test]
    public async Task BroadSearchesCannotUseSelfTargetAuthorization()
    {
        var boundary = new AdminReadTestBoundary(Now);

        AssertAllFailed(await InvokeAllAsync(boundary.Actor,
            new DenyOtherTargetAuthorizer(boundary.Actor.ActorUserId), boundary.Sessions),
            AshlarFailureCodes.AuthorizationDenied);
    }

    [Test]
    public async Task EveryAdminReadAllowsAuthorizedTenantAndAllTenantScopesAndAudits()
    {
        var boundary = new AdminReadTestBoundary(Now);
        var tenant = await InvokeAllAsync(boundary.Actor, new AllowAuthorizer(), boundary.Sessions);
        var allTenants = await InvokeAllAsync(boundary.Actor, new AllowAuthorizer(), boundary.Sessions, includeAllTenants: true);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(tenant, Is.All.Null);
            Assert.That(allTenants, Is.All.Null);
        }
    }

    [Test]
    public async Task AdminReadsDurablyAuditNormalizedOutcomesAndFailClosed()
    {
        var boundary = new AdminReadTestBoundary(Now);
        var repository = new Mock<ICredentialAdministrationRepository>();
        repository.Setup(value => value.SearchCredentialsAsync(It.IsAny<SearchCredentialsRequest>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync([]);
        var service = new CredentialAdministrationReader(repository.Object, boundary.Sessions, boundary.Authorizer, boundary.Sink, boundary.TimeProvider);
        var request = new SearchCredentialsRequest { Tenant = TenantContext.Global };

        var result = await service.SearchCredentialsAsync(boundary.Actor, request);
        var deniedBoundary = new AdminReadTestBoundary(Now, authorized: false);
        var denied = await new CredentialAdministrationReader(repository.Object, deniedBoundary.Sessions, deniedBoundary.Authorizer,
            deniedBoundary.Sink, deniedBoundary.TimeProvider).SearchCredentialsAsync(deniedBoundary.Actor, request);
        var throwing = new CredentialAdministrationReader(repository.Object, boundary.Sessions, boundary.Authorizer,
            new ThrowingSink(), boundary.TimeProvider);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(boundary.Sink.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.AdministrationRead));
            Assert.That(boundary.Sink.Events.Single().Outcome, Is.EqualTo(SecurityEventOutcomes.Success));
            Assert.That(boundary.Sink.Events.Single().Properties!["operation"], Is.EqualTo(nameof(AccountSecurityOperation.SearchCredentials)));
            Assert.That(boundary.Sink.Events.Single().Properties!["scope"], Is.EqualTo("global"));
            Assert.That(denied.FailureCode, Is.EqualTo(AshlarFailureCodes.AuthorizationDenied));
            Assert.That(deniedBoundary.Sink.Events.Single().Outcome, Is.EqualTo(SecurityEventOutcomes.Failure));
            Assert.That(deniedBoundary.Sink.Events.Single().FailureReason, Is.EqualTo(AshlarFailureCodes.AuthorizationDeniedValue));
        }
        Assert.ThrowsAsync<InvalidOperationException>(async () => await throwing.SearchCredentialsAsync(boundary.Actor, request));
    }

    [Test]
    public void BoundaryFailuresAndAllTenantScopeAreDurablyAudited()
    {
        var boundary = new AdminReadTestBoundary(Now);
        var repository = new Mock<ICredentialAdministrationRepository>();
        repository.Setup(value => value.SearchCredentialsAsync(It.IsAny<SearchCredentialsRequest>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync([]);
        var sessions = new Mock<IAuthenticationSessionRepository>();
        sessions.Setup(value => value.GetSessionAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("session unavailable"));
        var proofSink = new AdminReadTestBoundary.RecordingSink();
        var proofFailure = new CredentialAdministrationReader(repository.Object, sessions.Object, boundary.Authorizer,
            proofSink, boundary.TimeProvider);
        var authorizationSink = new AdminReadTestBoundary.RecordingSink();
        var authorizationFailure = new CredentialAdministrationReader(repository.Object, boundary.Sessions,
            new ThrowingAuthorizer(), authorizationSink, boundary.TimeProvider);

        var allTenantsSink = new AdminReadTestBoundary.RecordingSink();
        var allTenants = new CredentialAdministrationReader(repository.Object, boundary.Sessions, boundary.Authorizer,
            allTenantsSink, boundary.TimeProvider);
        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<InvalidOperationException>(async () => await proofFailure.SearchCredentialsAsync(boundary.Actor,
                new SearchCredentialsRequest { Tenant = TenantContext.Global }));
            Assert.ThrowsAsync<InvalidOperationException>(async () => await authorizationFailure.SearchCredentialsAsync(boundary.Actor,
                new SearchCredentialsRequest { Tenant = TenantContext.Global }));
            Assert.That(proofSink.Events.Single().Outcome, Is.EqualTo(SecurityEventOutcomes.Failure));
            Assert.That(proofSink.Events.Single().ActorUserId, Is.Null);
            Assert.That(proofSink.Events.Single().SessionId, Is.Null);
            Assert.That(authorizationSink.Events.Single().Outcome, Is.EqualTo(SecurityEventOutcomes.Failure));
            Assert.That(authorizationSink.Events.Single().ActorUserId, Is.EqualTo(boundary.Actor.ActorUserId));
            Assert.That((allTenants.SearchCredentialsAsync(boundary.Actor, new SearchCredentialsRequest
            {
                IncludeAllTenants = true
            }).GetAwaiter().GetResult()).Succeeded, Is.True);
            Assert.That(allTenantsSink.Events.Single().Properties!["scope"], Is.EqualTo("all-tenants"));
        }
    }

    [Test]
    public async Task ItemLookupsReauthorizeTheResolvedOwnerWithoutRevealingDeniedTargets()
    {
        var boundary = new AdminReadTestBoundary(Now);
        var otherUser = Guid.NewGuid();
        var credentialId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var eventId = Guid.NewGuid();
        var authorizer = new AllowBroadDenyOtherTargetAuthorizer(boundary.Actor.ActorUserId);
        var credentials = new Mock<ICredentialAdministrationRepository>();
        credentials.Setup(repository => repository.GetCredentialAsync(It.IsAny<CredentialAdministrationLookupRequest>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new CredentialAdministrationSummary(credentialId, otherUser, null, AuthenticationProviderKey.Local,
                "primary", CredentialStatus.Active, true, Now, null, null, null, null));
        var sessions = new Mock<IAuthenticationSessionAdministrationRepository>();
        sessions.Setup(repository => repository.GetAuthenticationSessionAsync(It.IsAny<AuthenticationSessionAdministrationLookupRequest>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationSessionAdministrationSummary(sessionId, otherUser, null, Now, Now,
                AuthenticationProviderKey.Local, null, null, null, Now.AddMinutes(5), null, null, null, null, null, true));
        var events = new Mock<ISecurityEventAdministrationRepository>();
        events.Setup(repository => repository.GetSecurityEventAsync(It.IsAny<SecurityEventAdministrationLookupRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new SecurityEventSummary(eventId, "test", Now, otherUser, null, null, null, null, null, null, null,
                SecurityEventOutcomes.Success, null, null));

        var credential = await new CredentialAdministrationReader(credentials.Object, boundary.Sessions, authorizer, boundary.Sink, boundary.TimeProvider)
            .GetCredentialAsync(boundary.Actor, new CredentialAdministrationLookupRequest(credentialId, TenantContext.Global));
        var session = await new AuthenticationSessionAdministrationReader(sessions.Object, boundary.Sessions, authorizer, boundary.Sink, boundary.TimeProvider)
            .GetAuthenticationSessionAsync(boundary.Actor, new AuthenticationSessionAdministrationLookupRequest(sessionId, TenantContext.Global));
        var securityEvent = await new SecurityEventAdministrationService(events.Object, boundary.Sessions, authorizer, boundary.Sink, boundary.TimeProvider)
            .GetSecurityEventAsync(new SecurityEventAdministrationLookupRequest(eventId, TenantContext.Global, Actor: boundary.Actor));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(credential.FailureCode, Is.EqualTo(AshlarFailureCodes.CredentialNotFound));
            Assert.That(session.FailureCode, Is.EqualTo(AshlarFailureCodes.SessionNotFound));
            Assert.That(securityEvent.FailureCode, Is.EqualTo(AshlarFailureCodes.SecurityEventNotFound));
            Assert.That(boundary.Sink.Events, Has.Count.EqualTo(3));
            Assert.That(boundary.Sink.Events, Is.All.Matches<AshlarSecurityEvent>(audit => audit.Outcome == SecurityEventOutcomes.Failure));
            Assert.That(authorizer.Targets, Is.EqualTo(new[] { Guid.Empty, otherUser, Guid.Empty, otherUser, Guid.Empty, otherUser }));
        }
    }

    [Test]
    public async Task ItemLookupsRejectInitialAuthorizationAndUseSystemClockByDefault()
    {
        var boundary = new AdminReadTestBoundary(DateTimeOffset.UtcNow);
        var denied = new DenyAuthorizer();
        var credential = await new CredentialAdministrationReader(Mock.Of<ICredentialAdministrationRepository>(), boundary.Sessions, denied, boundary.Sink)
            .GetCredentialAsync(boundary.Actor, new CredentialAdministrationLookupRequest(Guid.NewGuid(), TenantContext.Global));
        var session = await new AuthenticationSessionAdministrationReader(Mock.Of<IAuthenticationSessionAdministrationRepository>(), boundary.Sessions, denied, boundary.Sink)
            .GetAuthenticationSessionAsync(boundary.Actor, new AuthenticationSessionAdministrationLookupRequest(Guid.NewGuid(), TenantContext.Global));
        var securityEvent = await new SecurityEventAdministrationService(Mock.Of<ISecurityEventAdministrationRepository>(), boundary.Sessions, denied, boundary.Sink)
            .GetSecurityEventAsync(new SecurityEventAdministrationLookupRequest(Guid.NewGuid(), TenantContext.Global, Actor: boundary.Actor));
        var user = await new UserAdministrationReader(Mock.Of<IUserAdministrationRepository>(), new PostureReader(), boundary.Sessions, denied, boundary.Sink)
            .GetUserDetailAsync(boundary.Actor, new UserAdministrationLookupRequest(Guid.NewGuid(), TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(credential.FailureCode, Is.EqualTo(AshlarFailureCodes.AuthorizationDenied));
            Assert.That(session.FailureCode, Is.EqualTo(AshlarFailureCodes.AuthorizationDenied));
            Assert.That(securityEvent.FailureCode, Is.EqualTo(AshlarFailureCodes.AuthorizationDenied));
            Assert.That(user.FailureCode, Is.EqualTo(AshlarFailureCodes.AuthorizationDenied));
        }
    }

    [Test]
    public void ItemLookupProviderFailuresAreDurablyAudited()
    {
        var boundary = new AdminReadTestBoundary(Now);
        var failure = new InvalidOperationException("provider failed");
        var users = new Mock<IUserAdministrationRepository>();
        users.Setup(repository => repository.GetUserSummaryAsync(It.IsAny<UserAdministrationLookupRequest>(), It.IsAny<CancellationToken>())).ThrowsAsync(failure);
        var credentials = new Mock<ICredentialAdministrationRepository>();
        credentials.Setup(repository => repository.GetCredentialAsync(It.IsAny<CredentialAdministrationLookupRequest>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ThrowsAsync(failure);
        var sessions = new Mock<IAuthenticationSessionAdministrationRepository>();
        sessions.Setup(repository => repository.GetAuthenticationSessionAsync(It.IsAny<AuthenticationSessionAdministrationLookupRequest>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ThrowsAsync(failure);
        var events = new Mock<ISecurityEventAdministrationRepository>();
        events.Setup(repository => repository.GetSecurityEventAsync(It.IsAny<SecurityEventAdministrationLookupRequest>(), It.IsAny<CancellationToken>())).ThrowsAsync(failure);
        var userId = Guid.NewGuid();
        var postureUsers = new Mock<IUserAdministrationRepository>();
        postureUsers.Setup(repository => repository.GetUserSummaryAsync(It.IsAny<UserAdministrationLookupRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new UserSummary(userId, "user@example.com", null, null, UserAccountState.Active, true, true, Now, null));
        var posture = new PostureReader(failure);

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<InvalidOperationException>(async () => await new UserAdministrationReader(users.Object, new PostureReader(), boundary.Sessions, boundary.Authorizer, boundary.Sink, boundary.TimeProvider)
                .GetUserDetailAsync(boundary.Actor, new UserAdministrationLookupRequest(Guid.NewGuid(), TenantContext.Global)));
            Assert.ThrowsAsync<InvalidOperationException>(async () => await new CredentialAdministrationReader(credentials.Object, boundary.Sessions, boundary.Authorizer, boundary.Sink, boundary.TimeProvider)
                .GetCredentialAsync(boundary.Actor, new CredentialAdministrationLookupRequest(Guid.NewGuid(), TenantContext.Global)));
            Assert.ThrowsAsync<InvalidOperationException>(async () => await new AuthenticationSessionAdministrationReader(sessions.Object, boundary.Sessions, boundary.Authorizer, boundary.Sink, boundary.TimeProvider)
                .GetAuthenticationSessionAsync(boundary.Actor, new AuthenticationSessionAdministrationLookupRequest(Guid.NewGuid(), TenantContext.Global)));
            Assert.ThrowsAsync<InvalidOperationException>(async () => await new SecurityEventAdministrationService(events.Object, boundary.Sessions, boundary.Authorizer, boundary.Sink, boundary.TimeProvider)
                .GetSecurityEventAsync(new SecurityEventAdministrationLookupRequest(Guid.NewGuid(), TenantContext.Global, Actor: boundary.Actor)));
            Assert.ThrowsAsync<InvalidOperationException>(async () => await new UserAdministrationReader(postureUsers.Object, posture, boundary.Sessions, boundary.Authorizer, boundary.Sink, boundary.TimeProvider)
                .GetUserDetailAsync(boundary.Actor, new UserAdministrationLookupRequest(userId, TenantContext.Global)));

            Assert.That(boundary.Sink.Events, Has.Count.EqualTo(5));
            Assert.That(boundary.Sink.Events, Is.All.Matches<AshlarSecurityEvent>(audit => audit.Outcome == SecurityEventOutcomes.Failure));
        }
    }

    private static async Task<IReadOnlyList<AshlarFailureCode?>> InvokeAllAsync(
        AccountSecurityActorContext? actor,
        IAccountSecurityOperationAuthorizer authorizer,
        IAuthenticationSessionRepository sessions,
        bool includeAllTenants = false)
    {
        var sink = new AdminReadTestBoundary.RecordingSink();
        var clock = new FakeTimeProvider(Now);
        var tenant = includeAllTenants ? null : TenantContext.Global;
        var userRepository = new Mock<IUserAdministrationRepository>();
        userRepository.Setup(repository => repository.SearchUsersAsync(It.IsAny<SearchUsersRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync([]);
        var credentialRepository = new Mock<ICredentialAdministrationRepository>();
        credentialRepository.Setup(repository => repository.SearchCredentialsAsync(It.IsAny<SearchCredentialsRequest>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync([]);
        var sessionRepository = new Mock<IAuthenticationSessionAdministrationRepository>();
        sessionRepository.Setup(repository => repository.SearchAuthenticationSessionsAsync(It.IsAny<SearchAuthenticationSessionsRequest>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync([]);
        var eventRepository = new Mock<ISecurityEventAdministrationRepository>();
        eventRepository.Setup(repository => repository.SearchSecurityEventsAsync(It.IsAny<SearchSecurityEventsRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync([]);
        var users = new UserAdministrationReader(userRepository.Object, new PostureReader(), sessions, authorizer, sink, clock);
        var credentials = new CredentialAdministrationReader(credentialRepository.Object, sessions, authorizer, sink, clock);
        var authenticationSessions = new AuthenticationSessionAdministrationReader(sessionRepository.Object, sessions, authorizer, sink, clock);
        var events = new SecurityEventAdministrationService(eventRepository.Object, sessions, authorizer, sink, clock);

        return
        [
            (await users.SearchUsersAsync(actor!, new SearchUsersRequest { Tenant = tenant, IncludeAllTenants = includeAllTenants })).FailureCode,
            (await credentials.SearchCredentialsAsync(actor!, new SearchCredentialsRequest { Tenant = tenant, IncludeAllTenants = includeAllTenants })).FailureCode,
            (await authenticationSessions.SearchAuthenticationSessionsAsync(actor!, new SearchAuthenticationSessionsRequest { Tenant = tenant, IncludeAllTenants = includeAllTenants })).FailureCode,
            (await events.SearchSecurityEventsAsync(new SearchSecurityEventsRequest { Actor = actor, Tenant = tenant, IncludeAllTenants = includeAllTenants })).FailureCode
        ];
    }

    private static void AssertAllFailed(IReadOnlyList<AshlarFailureCode?> failures,
        AshlarFailureCode? expected = null) =>
        Assert.That(failures, Is.All.EqualTo(expected ?? AshlarFailureCodes.ValidationError));

    private sealed class AllowAuthorizer : IAccountSecurityOperationAuthorizer
    {
        public ValueTask<bool> AuthorizeAsync(AccountSecurityAuthorizationContext context, CancellationToken cancellationToken = default) => ValueTask.FromResult(true);
    }

    private sealed class DenyAuthorizer : IAccountSecurityOperationAuthorizer
    {
        public ValueTask<bool> AuthorizeAsync(AccountSecurityAuthorizationContext context, CancellationToken cancellationToken = default) => ValueTask.FromResult(false);
    }

    private sealed class ThrowingAuthorizer : IAccountSecurityOperationAuthorizer
    {
        public ValueTask<bool> AuthorizeAsync(AccountSecurityAuthorizationContext context, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("authorization unavailable");
    }

    private sealed class AllowByScopeAuthorizer : IAccountSecurityOperationAuthorizer
    {
        public ValueTask<bool> AuthorizeAsync(AccountSecurityAuthorizationContext context, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(!context.IncludeAllTenants);
    }

    private sealed class DenyOtherTargetAuthorizer(Guid actorId) : IAccountSecurityOperationAuthorizer
    {
        public ValueTask<bool> AuthorizeAsync(AccountSecurityAuthorizationContext context, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(context.TargetUserId == actorId);
    }

    private sealed class AllowBroadDenyOtherTargetAuthorizer(Guid actorId) : IAccountSecurityOperationAuthorizer
    {
        public List<Guid> Targets { get; } = [];

        public ValueTask<bool> AuthorizeAsync(AccountSecurityAuthorizationContext context, CancellationToken cancellationToken = default)
        {
            Targets.Add(context.TargetUserId);
            return ValueTask.FromResult(context.TargetUserId == Guid.Empty || context.TargetUserId == actorId);
        }
    }

    private sealed class ThrowingSink : IPersistentSecurityEventSink
    {
        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("audit unavailable");
    }

    private sealed class PostureReader(Exception? failure = null) : IAccountSecurityPostureReader
    {
        public Task<Result<AccountSecurityPosture>> GetUserSecurityPostureAsync(
            Guid userId, AccountSecurityPostureRequest request, CancellationToken cancellationToken = default) =>
            failure == null
                ? Task.FromResult(Result.Failure<AccountSecurityPosture>(AshlarFailureCodes.UserNotFound))
                : Task.FromException<Result<AccountSecurityPosture>>(failure);
    }
}
