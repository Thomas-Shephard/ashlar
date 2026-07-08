using Ashlar.Auditing;
using Ashlar.Security.Encryption;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Identity.Features.Auditing;

internal sealed class SecurityAuditEventTests
{
    private static readonly DateTimeOffset TestTime = new(2025, 1, 1, 12, 0, 0, TimeSpan.Zero);
    private static readonly string[] ExpiredAndRevokedEventTypes =
    [
        AshlarSecurityEventTypes.SessionExpired,
        AshlarSecurityEventTypes.SessionRevoked
    ];
    private static readonly string[] ExpiredAndRevokedFailureReasons =
    [
        "session_expired",
        "session_revoked"
    ];

    [Test]
    public async Task SecurityEventEmitterPrefersExplicitAuditAndTenantMetadata()
    {
        var sink = new RecordingSecurityEventSink();
        var emitter = new SecurityEventEmitter(sink, new FakeTimeProvider(TestTime));
        var explicitTenantId = Guid.NewGuid();
        var contextTenantId = Guid.NewGuid();
        var actorUserId = Guid.NewGuid();
        var contextActorUserId = Guid.NewGuid();
        var audit = new AuditContext(actorUserId, "203.0.113.10", "audit-agent", "audit-corr", new Dictionary<string, string> { ["safe"] = "metadata" });

        await emitter.RecordAsync(new SecurityEventDescriptor
        {
            EventType = "test",
            Outcome = "success",
            TenantId = explicitTenantId,
            Audit = audit,
            Context = new AuthenticationContext(TenantId: contextTenantId, IpAddress: "198.51.100.10", UserAgent: "context-agent", CorrelationId: "context-corr", UserId: contextActorUserId)
        });

        var securityEvent = sink.Events.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(securityEvent.TenantId, Is.EqualTo(explicitTenantId));
            Assert.That(securityEvent.ActorUserId, Is.EqualTo(actorUserId));
            Assert.That(securityEvent.IpAddress, Is.EqualTo(audit.IpAddress));
            Assert.That(securityEvent.UserAgent, Is.EqualTo(audit.UserAgent));
            Assert.That(securityEvent.CorrelationId, Is.EqualTo(audit.CorrelationId));
            Assert.That(audit.Items, Is.Not.Null);
        }
    }

    [Test]
    public async Task SecurityEventEmitterFallsBackThroughContextAndDescriptorMetadata()
    {
        var sink = new RecordingSecurityEventSink();
        var emitter = new SecurityEventEmitter(sink, new FakeTimeProvider(TestTime));
        var contextTenantId = Guid.NewGuid();
        var contextActorUserId = Guid.NewGuid();

        await emitter.RecordAsync(new SecurityEventDescriptor
        {
            EventType = "context",
            Outcome = "success",
            Context = new AuthenticationContext(TenantId: contextTenantId, IpAddress: "198.51.100.20", UserAgent: "context-agent", CorrelationId: "context-corr", UserId: contextActorUserId)
        });

        await emitter.RecordAsync(new SecurityEventDescriptor
        {
            EventType = "descriptor",
            Outcome = "success",
            IpAddress = "192.0.2.20",
            UserAgent = "descriptor-agent",
            CorrelationId = "descriptor-corr"
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(sink.Events[0].TenantId, Is.EqualTo(contextTenantId));
            Assert.That(sink.Events[0].ActorUserId, Is.EqualTo(contextActorUserId));
            Assert.That(sink.Events[0].IpAddress, Is.EqualTo("198.51.100.20"));
            Assert.That(sink.Events[0].UserAgent, Is.EqualTo("context-agent"));
            Assert.That(sink.Events[0].CorrelationId, Is.EqualTo("context-corr"));
            Assert.That(sink.Events[1].TenantId, Is.Null);
            Assert.That(sink.Events[1].ActorUserId, Is.Null);
            Assert.That(sink.Events[1].IpAddress, Is.EqualTo("192.0.2.20"));
            Assert.That(sink.Events[1].UserAgent, Is.EqualTo("descriptor-agent"));
            Assert.That(sink.Events[1].CorrelationId, Is.EqualTo("descriptor-corr"));
        }
    }

    [Test]
    public async Task SuccessfulLoginEmitsSuccessEvent()
    {
        var sink = new RecordingSecurityEventSink();
        var (pipeline, _, credentialService, providerMock, provider, assertion, user, credential) = CreatePipeline(sink);
        var context = CreateContext();
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded);
        credentialService.ContextResolveResult = (user, credential, credential, false);
        providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(result);
        credentialService.UsageUpdateResult = CredentialUsageUpdateResult.NotNeeded;

        var response = await pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.True);
            Assert.That(sink.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.AuthenticationSucceeded));
            Assert.That(sink.Events.Single().UserId, Is.EqualTo(user.Id));
            Assert.That(sink.Events.Single().Provider, Is.EqualTo(AuthenticationProviderKey.Local));
            Assert.That(sink.Events.Single().IpAddress, Is.EqualTo("127.0.0.1"));
            Assert.That(sink.Events.Single().UserAgent, Is.EqualTo("agent"));
            Assert.That(sink.Events.Single().CorrelationId, Is.EqualTo("corr"));
            Assert.That(sink.Events.Single().Outcome, Is.EqualTo("success"));
        }
    }

    [Test]
    public async Task InvalidLoginEmitsFailureEvent()
    {
        var sink = new RecordingSecurityEventSink();
        var (pipeline, _, credentialService, providerMock, provider, assertion, user, credential) = CreatePipeline(sink);
        var context = CreateContext();
        credentialService.ContextResolveResult = (user, credential, credential, false);
        providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Failed));

        var response = await pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(sink.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.AuthenticationFailed));
            Assert.That(sink.Events.Single().FailureReason, Is.EqualTo("invalid_credentials"));
        }
    }

    [Test]
    public async Task MfaRequiredLoginDoesNotEmitFailureEvent()
    {
        var sink = new RecordingSecurityEventSink();
        var (pipeline, _, credentialService, providerMock, provider, assertion, user, credential) = CreatePipeline(sink);
        var context = CreateContext();
        credentialService.ContextResolveResult = (user, credential, credential, false);
        providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.MfaRequired));

        var response = await pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.MfaRequired));
            Assert.That(sink.Events, Is.Empty);
        }
    }

    [Test]
    public async Task DisabledUserLoginEmitsDisabledFailureEvent()
    {
        var sink = new RecordingSecurityEventSink();
        var (pipeline, _, credentialService, providerMock, provider, assertion, user, credential) = CreatePipeline(sink);
        user = new User { Id = user.Id, DisplayEmail = user.DisplayEmail, AccountState = UserAccountState.Disabled };
        var context = CreateContext();
        credentialService.ContextResolveResult = (user, credential, credential, false);
        providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded));

        var response = await pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Disabled));
            Assert.That(sink.Events.Single().FailureReason, Is.EqualTo("user_disabled"));
            Assert.That(sink.Events.Single().UserId, Is.EqualTo(user.Id));
        }
    }

    [Test]
    public async Task UnsupportedProviderLoginEmitsProviderUnsupportedEvent()
    {
        var sink = new RecordingSecurityEventSink();
        var registry = new Mock<IAuthenticationProviderRegistry>();
        var pipeline = new AuthenticationPipeline(
            registry.Object,
            new TestCredentialService(),
            new NullTransactionProvider(),
            AllowPrimaryAuthenticationRateLimiter.Instance,
            AllowAuthenticationFactorRateLimiter.Instance,
            new AuthenticationPipelineDependencies(sink, new FakeTimeProvider(TestTime)));
        var assertion = new TestAssertion(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));

        var response = await pipeline.LoginAsync(CreateContext(), assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(sink.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.AuthenticationFailed));
            Assert.That(sink.Events.Single().FailureReason, Is.EqualTo("provider_unsupported"));
            Assert.That(sink.Events.Single().Provider, Is.EqualTo(assertion.ProviderIdentity));
        }
    }

    [Test]
    public async Task CredentialLinkEmitsEventWithoutRawCredentialValue()
    {
        var sink = new RecordingSecurityEventSink();
        var repository = new Mock<IUserRepository>();
        var credentialRepository = new Mock<ICredentialRepository>();
        var protector = new Mock<ISecretProtector>();
        var service = new CredentialService(
            repository.Object,
            credentialRepository.Object,
            protector.Object,
            new NullTransactionProvider(),
            new CredentialServiceDependencies(TimeProvider: new FakeTimeProvider(TestTime), SecurityEventSink: sink));
        var userId = Guid.NewGuid();
        var assertion = new TestAssertion(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));
        var provider = new Mock<IPrimaryAuthenticationProvider>();
        provider.SetupGet(p => p.Key).Returns(assertion.ProviderIdentity);
        provider.Setup(p => p.GetProviderKey(assertion, userId)).Returns("provider-key");
        provider.Setup(p => p.PrepareCredentialValue(assertion, "raw-secret")).Returns("prepared-secret");
        provider.Setup(p => p.ProtectsCredentials).Returns(true);
        protector.Setup(p => p.Protect("prepared-secret")).Returns("protected-secret");
        repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "test@example.com" });
        repository.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Oidc, "Google", "provider-key", It.IsAny<CancellationToken>()))
            .ReturnsAsync((IUser?)null);

        await service.LinkCredentialAsync(userId, assertion, provider.Object, "raw-secret");

        var securityEvent = sink.Events.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(securityEvent.EventType, Is.EqualTo(AshlarSecurityEventTypes.CredentialLinked));
            Assert.That(securityEvent.UserId, Is.EqualTo(userId));
            Assert.That(securityEvent.Properties?.Values, Does.Not.Contain("raw-secret"));
            Assert.That(securityEvent.Properties?.Values, Does.Not.Contain("prepared-secret"));
            Assert.That(securityEvent.Properties?.Values, Does.Not.Contain("protected-secret"));
        }
    }

    [Test]
    public async Task CredentialConsumedEmitsEvent()
    {
        var sink = new RecordingSecurityEventSink();
        var repository = new Mock<IUserRepository>();
        var credentialRepository = new Mock<ICredentialRepository>();
        var service = new CredentialService(
            repository.Object,
            credentialRepository.Object,
            Mock.Of<ISecretProtector>(),
            new NullTransactionProvider(),
            new CredentialServiceDependencies(TimeProvider: new FakeTimeProvider(TestTime), SecurityEventSink: sink));
        var credential = CreateCredential(Guid.NewGuid());
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, IsCredentialConsumed: true);
        credentialRepository.Setup(r => r.ConsumeCredentialAsync(credential.Id, credential.Version, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var consumed = await service.UpdateCredentialUsageAsync(credential, credential, result, Mock.Of<IAuthenticationProvider>());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(consumed.CanProceed, Is.True);
            Assert.That(consumed.UpdatePersisted, Is.False);
            Assert.That(sink.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.CredentialConsumed));
            Assert.That(sink.Events.Single().Properties?.Values, Does.Not.Contain("raw-secret"));
        }
    }

    [Test]
    public async Task MissingCredentialResolutionDoesNotEmitAuditEvent()
    {
        var sink = new RecordingSecurityEventSink();
        var repository = new Mock<IUserRepository>();
        var credentialRepository = new Mock<ICredentialRepository>();
        var protector = new Mock<ISecretProtector>();
        protector.Setup(p => p.Protect(It.IsAny<string>())).Returns<string>(value => $"protected:{value}");
        protector.Setup(p => p.Unprotect(It.IsAny<string>())).Returns<string>(value => value);
        var service = new CredentialService(
            repository.Object,
            credentialRepository.Object,
            protector.Object,
            new NullTransactionProvider(),
            new CredentialServiceDependencies(TimeProvider: new FakeTimeProvider(TestTime), SecurityEventSink: sink));
        var userId = Guid.NewGuid();
        var provider = new Mock<IPrimaryAuthenticationProvider>();
        provider.SetupGet(p => p.Key).Returns(AuthenticationProviderKey.Local);
        provider.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), userId)).Returns("missing-key");
        provider.Setup(p => p.ProtectsCredentials).Returns(true);
        repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "test@example.com" });
        credentialRepository.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Local, AuthenticationProviderKey.Local.Name, "missing-key", It.IsAny<CancellationToken>()))
            .ReturnsAsync((UserCredential?)null);

        var (_, resolvedCredential, originalCredential, _) = await service.ResolveAsync(userId, new TestAssertion(AuthenticationProviderKey.Local), provider.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(resolvedCredential, Is.Null);
            Assert.That(originalCredential, Is.Null);
            Assert.That(sink.Events, Is.Empty);
        }
    }

    [Test]
    public async Task SessionCreateEmitsEventWithoutRawToken()
    {
        var sink = new RecordingSecurityEventSink();
        var service = CreateSessionService(sink, out var repository, out _);
        repository.Setup(r => r.CreateSessionAsync(It.IsAny<AuthenticationSession>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        var result = await service.CreateSessionForAuthenticatedUserAsync(
            Guid.NewGuid(),
            new CreateAuthenticationSessionRequest(IpAddress: "127.0.0.1", UserAgent: "agent"));

        var securityEvent = sink.Events.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(securityEvent.EventType, Is.EqualTo(AshlarSecurityEventTypes.SessionCreated));
            Assert.That(securityEvent.SessionId, Is.EqualTo(result.Session.Id));
            Assert.That(securityEvent.IpAddress, Is.EqualTo("127.0.0.1"));
            Assert.That(securityEvent.UserAgent, Is.EqualTo("agent"));
            Assert.That(securityEvent.Properties?.Values ?? Array.Empty<string>(), Does.Not.Contain(result.Token));
            Assert.That(result.Session.GetType().GetProperty("TokenHash"), Is.Null);
        }
    }

    [Test]
    public async Task SessionValidationSuccessEmitsEvent()
    {
        var sink = new RecordingSecurityEventSink();
        var service = CreateSessionService(sink, out var repository, out var timeProvider);
        var session = CreateSession(timeProvider.GetUtcNow().AddHours(1));
        repository.Setup(r => r.GetSessionByTokenHashAsync("hashed:raw-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(session);
        repository.Setup(r => r.UpdateSessionLastSeenAsync(session.Id, timeProvider.GetUtcNow(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var result = await service.ValidateSessionAsync("raw-token");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(sink.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.SessionValidated));
            Assert.That(sink.Events.Single().SessionId, Is.EqualTo(session.Id));
            Assert.That(sink.Events.Single().UserId, Is.EqualTo(session.UserId));
        }
    }

    [Test]
    public async Task SessionExpiredAndRevokedEmitAppropriateEvents()
    {
        var sink = new RecordingSecurityEventSink();
        var service = CreateSessionService(sink, out var repository, out var timeProvider);
        var expired = CreateSession(timeProvider.GetUtcNow());
        var revoked = CreateSession(timeProvider.GetUtcNow().AddHours(1));
        revoked.RevokedAt = timeProvider.GetUtcNow().AddMinutes(-1);
        repository.SetupSequence(r => r.GetSessionByTokenHashAsync("hashed:raw-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(expired)
            .ReturnsAsync(revoked);

        await service.ValidateSessionAsync("raw-token");
        await service.ValidateSessionAsync("raw-token");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(sink.Events.Select(e => e.EventType), Is.EqualTo(ExpiredAndRevokedEventTypes));
            Assert.That(sink.Events.Select(e => e.FailureReason), Is.EqualTo(ExpiredAndRevokedFailureReasons));
        }
    }

    [Test]
    public async Task RevokeSessionsForUserEmitsSuccessEventWhenNoSessionsAreRevoked()
    {
        var sink = new RecordingSecurityEventSink();
        var service = CreateSessionService(sink, out var repository, out var timeProvider);
        var userId = Guid.NewGuid();
        repository.Setup(r => r.RevokeSessionsForUserAsync(userId, timeProvider.GetUtcNow(), "password-reset", TenantContext.Global, false, It.IsAny<CancellationToken>()))
            .ReturnsAsync(0);

        var audit = new AuditContext(userId, "203.0.113.12", "audit-agent", "audit-correlation");
        var revoked = await service.RevokeSessionsForUserAsync(userId, new RevokeAuthenticationSessionsForUserRequest(audit, TenantContext.Global, "password-reset"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revoked, Is.Zero);
            Assert.That(sink.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.SessionsRevokedForUser));
            Assert.That(sink.Events.Single().UserId, Is.EqualTo(userId));
            Assert.That(sink.Events.Single().Outcome, Is.EqualTo("success"));
            Assert.That(sink.Events.Single().ActorUserId, Is.EqualTo(userId));
            Assert.That(sink.Events.Single().CorrelationId, Is.EqualTo("audit-correlation"));
            Assert.That(sink.Events.Single().Properties?["count"], Is.EqualTo("0"));
            Assert.That(sink.Events.Single().Properties?["scope"], Is.EqualTo("global"));
        }
    }

    [Test]
    public async Task AllTenantSessionRevocationAuditEventIncludesExplicitScope()
    {
        var sink = new RecordingSecurityEventSink();
        var service = CreateSessionService(sink, out var repository, out var timeProvider);
        var userId = Guid.NewGuid();
        repository.Setup(r => r.RevokeSessionsForUserAsync(userId, timeProvider.GetUtcNow(), "operator", null, true, It.IsAny<CancellationToken>()))
            .ReturnsAsync(3);

        await service.RevokeSessionsForUserAsync(userId, new RevokeAuthenticationSessionsForUserRequest(new AuditContext(userId), Tenant: null, Reason: "operator", IncludeAllTenants: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(sink.Events.Single().TenantId, Is.Null);
            Assert.That(sink.Events.Single().Properties?["scope"], Is.EqualTo("all_tenants"));
            Assert.That(sink.Events.Single().Properties?["count"], Is.EqualTo("3"));
        }
    }

    [Test]
    public async Task FailedSessionRevocationEmitsFailureEvent()
    {
        var sink = new RecordingSecurityEventSink();
        var service = CreateSessionService(sink, out var repository, out _);
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        repository.Setup(r => r.RevokeSessionByIdAsync(sessionId, userId, It.IsAny<DateTimeOffset>(), It.IsAny<string>(), null, true, It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var revoked = await service.RevokeSessionForUserAsync(userId, new RevokeAuthenticationSessionRequest { SessionId = sessionId, IncludeAllTenants = true, Audit = new AuditContext(userId) });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revoked, Is.False);
            Assert.That(sink.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.SessionRevoked));
            Assert.That(sink.Events.Single().UserId, Is.EqualTo(userId));
            Assert.That(sink.Events.Single().SessionId, Is.EqualTo(sessionId));
            Assert.That(sink.Events.Single().Outcome, Is.EqualTo("failure"));
            Assert.That(sink.Events.Single().Properties?["scope"], Is.EqualTo("all_tenants"));
        }
    }

    [Test]
    public async Task AuditSinkExceptionFailsLoginAndSessionValidation()
    {
        var sink = new ThrowingSecurityEventSink();
        var (pipeline, _, credentialService, providerMock, provider, assertion, user, credential) = CreatePipeline(sink);
        var context = CreateContext();
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded);
        credentialService.ContextResolveResult = (user, credential, credential, false);
        providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(result);
        credentialService.UsageUpdateResult = CredentialUsageUpdateResult.NotNeeded;

        var loginException = Assert.ThrowsAsync<InvalidOperationException>(async () => await pipeline.LoginAsync(context, assertion));

        var sessionService = CreateSessionService(sink, out var repository, out var timeProvider);
        var session = CreateSession(timeProvider.GetUtcNow().AddHours(1));
        repository.Setup(r => r.GetSessionByTokenHashAsync("hashed:raw-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(session);
        repository.Setup(r => r.UpdateSessionLastSeenAsync(session.Id, timeProvider.GetUtcNow(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var validationException = Assert.ThrowsAsync<InvalidOperationException>(async () => await sessionService.ValidateSessionAsync("raw-token"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(loginException?.Message, Is.EqualTo("audit store unavailable"));
            Assert.That(validationException?.Message, Is.EqualTo("audit store unavailable"));
        }
    }

    [Test]
    public void AuditSinkExceptionWithUninitializedProviderTypeFailsLogin()
    {
        var sink = new ThrowingSecurityEventSink();
        var registry = new Mock<IAuthenticationProviderRegistry>();
        var credentialService = new TestCredentialService();
        var providerMock = new Mock<IPrimaryAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(default(AuthenticationProviderKey));
        var assertion = new TestAssertion(default);
        IAuthenticationProvider? provider = providerMock.Object;
        registry.Setup(r => r.TryGetProvider(assertion, out provider)).Returns(true);
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var context = CreateContext();
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded);
        credentialService.ContextResolveResult = (user, credential, credential, false);
        providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(result);
        credentialService.UsageUpdateResult = CredentialUsageUpdateResult.NotNeeded;
        var pipeline = new AuthenticationPipeline(
            registry.Object,
            credentialService,
            new NullTransactionProvider(),
            AllowPrimaryAuthenticationRateLimiter.Instance,
            AllowAuthenticationFactorRateLimiter.Instance,
            new AuthenticationPipelineDependencies(sink, new FakeTimeProvider(TestTime)));

        var exception = Assert.ThrowsAsync<InvalidOperationException>(async () => await pipeline.LoginAsync(context, assertion));

        Assert.That(exception?.Message, Is.EqualTo("audit store unavailable"));
    }

    [Test]
    public void AuditSinkExceptionAfterCredentialLifecycleDoesNotBecomeLifecycleFailure()
    {
        var sink = new FailsFirstSecurityEventSink();
        var (pipeline, _, credentialService, providerMock, provider, assertion, user, credential) = CreatePipeline(sink);
        var context = CreateContext();
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded);
        credentialService.ContextResolveResult = (user, credential, credential, false);
        providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(result);
        credentialService.UsageUpdateResult = CredentialUsageUpdateResult.NotNeeded;

        var exception = Assert.ThrowsAsync<InvalidOperationException>(async () => await pipeline.LoginAsync(context, assertion));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exception?.Message, Is.EqualTo("first audit failed"));
            Assert.That(sink.Events, Has.Count.EqualTo(1));
            Assert.That(sink.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.AuthenticationSucceeded));
            Assert.That(sink.Events.Single().Properties, Is.Null);
        }
    }

    [Test]
    public void AuditSinkOperationCanceledExceptionFailsLoginWhenCancellationNotRequested()
    {
        var sinkMock = new Mock<ISecurityEventSink>();
        sinkMock.Setup(s => s.RecordAsync(It.IsAny<AshlarSecurityEvent>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new OperationCanceledException());

        var (pipeline, _, credentialService, providerMock, provider, assertion, user, credential) = CreatePipeline(sinkMock.Object);
        var context = CreateContext();
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded);
        credentialService.ContextResolveResult = (user, credential, credential, false);
        providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(result);
        credentialService.UsageUpdateResult = CredentialUsageUpdateResult.NotNeeded;

        var exception = Assert.ThrowsAsync<OperationCanceledException>(async () => await pipeline.LoginAsync(context, assertion));

        Assert.That(exception, Is.Not.Null);
    }

    [Test]
    public void AddAshlarIdentityRegistersFanOutAuditSinkByDefault()
    {
        var services = new ServiceCollection();

        services.AddAshlarIdentity();

        var descriptor = services.Single(d => d.ServiceType == typeof(ISecurityEventSink));
        Assert.That(descriptor.ImplementationType, Is.EqualTo(typeof(SecurityEventFanOutSink)));
    }

    private static (AuthenticationPipeline Pipeline, Mock<IAuthenticationProviderRegistry> Registry, TestCredentialService CredentialService, Mock<IPrimaryAuthenticationProvider> ProviderMock, IAuthenticationProvider Provider, TestAssertion Assertion, User User, UserCredential Credential) CreatePipeline(ISecurityEventSink sink)
    {
        var registry = new Mock<IAuthenticationProviderRegistry>();
        var credentialService = new TestCredentialService();
        var providerMock = new Mock<IPrimaryAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key).Returns(AuthenticationProviderKey.Local);
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        IAuthenticationProvider? provider = providerMock.Object;
        registry.Setup(r => r.TryGetProvider(assertion, out provider))
            .Returns(true);
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Local,
            ProviderName = AuthenticationProviderKey.Local.Name,
            ProviderKey = user.Id.ToString(),
            Version = "v1",
            CreatedAt = TestTime,
            Status = CredentialStatus.Active
        };

        var pipeline = new AuthenticationPipeline(
            registry.Object,
            credentialService,
            new NullTransactionProvider(),
            AllowPrimaryAuthenticationRateLimiter.Instance,
            AllowAuthenticationFactorRateLimiter.Instance,
            new AuthenticationPipelineDependencies(sink, new FakeTimeProvider(TestTime)));
        return (pipeline, registry, credentialService, providerMock, provider, assertion, user, credential);
    }

    private static AuthenticationSessionService CreateSessionService(
        ISecurityEventSink sink,
        out Mock<IAuthenticationSessionRepository> repository,
        out FakeTimeProvider timeProvider)
    {
        repository = new Mock<IAuthenticationSessionRepository>();
        var hasher = new Mock<ISecureTokenHasher>();
        hasher.Setup(h => h.HashToken(It.IsAny<string>())).Returns<string>(token => $"hashed:{token}");
        var users = new Mock<IUserRepository>();
        users.Setup(r => r.GetUserByIdAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Guid userId, CancellationToken _) => new User { Id = userId, DisplayEmail = "user@example.com" });
        timeProvider = new FakeTimeProvider(TestTime);

        return new AuthenticationSessionService(
            repository.Object,
            hasher.Object,
            new FixedSessionTokenGenerator("raw-token"),
            new NullTransactionProvider(),
            new AuthenticationSessionServiceDependencies(
                TimeProvider: timeProvider,
                SecurityEventSink: sink,
                UserRepository: users.Object));
    }

    private static AuthenticationSession CreateSession(DateTimeOffset expiresAt)
    {
        return new AuthenticationSession
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            TokenHash = "hashed:raw-token",
            CreatedAt = TestTime.AddDays(-1),
            ExpiresAt = expiresAt,
            IpAddress = "127.0.0.1",
            UserAgent = "agent"
        };
    }

    private static UserCredential CreateCredential(Guid userId)
    {
        return new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Local,
            ProviderName = AuthenticationProviderKey.Local.Name,
            ProviderKey = userId.ToString(),
            Version = "v1",
            CreatedAt = TestTime,
            Status = CredentialStatus.Active
        };
    }

    private static AuthenticationContext CreateContext()
    {
        return new AuthenticationContext("test@example.com", IpAddress: "127.0.0.1", UserAgent: "agent", CorrelationId: "corr");
    }

    private sealed record TestAssertion(AuthenticationProviderKey ProviderIdentity) : IAuthenticationAssertion;

    private sealed class FixedSessionTokenGenerator(string token) : ISecureTokenGenerator
    {
        public string GenerateToken(int byteLength = ISecureTokenGenerator.DefaultByteLength)
        {
            return token;
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

    private sealed class ThrowingSecurityEventSink : ISecurityEventSink
    {
        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            throw new InvalidOperationException("audit store unavailable");
        }
    }

    private sealed class FailsFirstSecurityEventSink : ISecurityEventSink
    {
        private bool _failed;

        public List<AshlarSecurityEvent> Events { get; } = [];

        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            Events.Add(securityEvent);
            if (_failed)
            {
                return Task.CompletedTask;
            }

            _failed = true;
            throw new InvalidOperationException("first audit failed");
        }
    }
}
