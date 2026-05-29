using Moq;
using Ashlar.Auditing;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Tests.Identity.Features.Authentication;

internal sealed class AuthenticationPipelineTests
{
    private Mock<IAuthenticationProviderRegistry> _providerRegistryMock;
    private Mock<ICredentialService> _credentialServiceMock;
    private Mock<IPrimaryAuthenticationProvider> _providerMock;
    private Mock<IPrimaryAuthenticationRateLimiter> _primaryRateLimiterMock;
    private Mock<IAuthenticationFactorRateLimiter> _factorRateLimiterMock;
    private AuthenticationPipeline _pipeline;

    [SetUp]
    public void SetUp()
    {
        _providerRegistryMock = new Mock<IAuthenticationProviderRegistry>();
        _credentialServiceMock = new Mock<ICredentialService>();
        _providerMock = new Mock<IPrimaryAuthenticationProvider>();
        _primaryRateLimiterMock = CreateAllowingPrimaryRateLimiter();
        _factorRateLimiterMock = CreateAllowingFactorRateLimiter();
        _pipeline = new AuthenticationPipeline(_providerRegistryMock.Object, _credentialServiceMock.Object, new NullTransactionProvider(), _primaryRateLimiterMock.Object, _factorRateLimiterMock.Object);
    }

    [Test]
    public void ConstructorShouldThrowOnNullProviderRegistry()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationPipeline(null!, _credentialServiceMock.Object, new NullTransactionProvider(), _primaryRateLimiterMock.Object, _factorRateLimiterMock.Object));
    }

    [Test]
    public void ConstructorShouldThrowOnNullCredentialService()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationPipeline(_providerRegistryMock.Object, null!, new NullTransactionProvider(), _primaryRateLimiterMock.Object, _factorRateLimiterMock.Object));
    }

    [Test]
    public void ConstructorShouldThrowOnNullTransactionProvider()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationPipeline(_providerRegistryMock.Object, _credentialServiceMock.Object, null!, _primaryRateLimiterMock.Object, _factorRateLimiterMock.Object));
    }

    [Test]
    public void ConstructorShouldThrowOnNullPrimaryRateLimiter()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationPipeline(_providerRegistryMock.Object, _credentialServiceMock.Object, new NullTransactionProvider(), null!, _factorRateLimiterMock.Object));
    }

    [Test]
    public void ConstructorShouldThrowOnNullFactorRateLimiter()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationPipeline(_providerRegistryMock.Object, _credentialServiceMock.Object, new NullTransactionProvider(), _primaryRateLimiterMock.Object, null!));
    }

    [Test]
    public void ConstructorShouldAcceptNonNullOptionalLogger()
    {
        var pipeline = new AuthenticationPipeline(
            _providerRegistryMock.Object,
            _credentialServiceMock.Object,
            new NullTransactionProvider(),
            _primaryRateLimiterMock.Object,
            _factorRateLimiterMock.Object,
            new AuthenticationPipelineDependencies(Logger: Mock.Of<Microsoft.Extensions.Logging.ILogger<AuthenticationPipeline>>()));

        Assert.That(pipeline, Is.Not.Null);
    }

    [Test]
    public async Task LoginAsyncWithUnsupportedProviderShouldReturnFailed()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(new AuthenticationProviderKey(ProviderType.Oidc, ProviderType.Oidc.Value));

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
        }

        _credentialServiceMock.Verify(
            s => s.ResolveAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Test]
    public async Task LoginAsyncWithAllowedPrimaryAttemptShouldCheckRateLimitAndCallProvider()
    {
        var context = new AuthenticationContext("test@example.com", IpAddress: "203.0.113.10");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var primaryRateLimiter = new Mock<IPrimaryAuthenticationRateLimiter>();
        primaryRateLimiter.Setup(l => l.CheckAsync(context, assertion, AuthenticationProviderKey.Local, It.IsAny<CancellationToken>()))
            .ReturnsAsync(RateLimitDecision.Allow());
        _pipeline = new AuthenticationPipeline(
            _providerRegistryMock.Object,
            _credentialServiceMock.Object,
            new NullTransactionProvider(),
            primaryRateLimiter.Object,
            _factorRateLimiterMock.Object);

        _credentialServiceMock.Setup(s => s.ResolveAsync(context, assertion, provider, It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, credential, credential, false));
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Failed));

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
            primaryRateLimiter.Verify(l => l.CheckAsync(context, assertion, AuthenticationProviderKey.Local, It.IsAny<CancellationToken>()), Times.Once);
            _providerMock.Verify(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [Test]
    public async Task LoginAsyncWithPrimaryRateLimiterFailureShouldFailOpenAndCallProvider()
    {
        var context = new AuthenticationContext("test@example.com", IpAddress: "203.0.113.10");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var primaryRateLimiter = new Mock<IPrimaryAuthenticationRateLimiter>();
        primaryRateLimiter.Setup(l => l.CheckAsync(context, assertion, AuthenticationProviderKey.Local, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("limiter unavailable"));
        _pipeline = new AuthenticationPipeline(
            _providerRegistryMock.Object,
            _credentialServiceMock.Object,
            new NullTransactionProvider(),
            primaryRateLimiter.Object,
            _factorRateLimiterMock.Object);

        _credentialServiceMock.Setup(s => s.ResolveAsync(context, assertion, provider, It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, credential, credential, false));
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Failed));

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
            _providerMock.Verify(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [Test]
    public void LoginAsyncWithPrimaryRateLimiterCancellationShouldPropagate()
    {
        var context = new AuthenticationContext("test@example.com", IpAddress: "203.0.113.10");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        ConfigureProviderResolution(assertion);
        var primaryRateLimiter = new Mock<IPrimaryAuthenticationRateLimiter>();
        primaryRateLimiter.Setup(l => l.CheckAsync(context, assertion, AuthenticationProviderKey.Local, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new OperationCanceledException());
        _pipeline = new AuthenticationPipeline(
            _providerRegistryMock.Object,
            _credentialServiceMock.Object,
            new NullTransactionProvider(),
            primaryRateLimiter.Object,
            _factorRateLimiterMock.Object);

        Assert.ThrowsAsync<OperationCanceledException>(() => _pipeline.LoginAsync(context, assertion));
    }

    [Test]
    public async Task LoginAsyncWithBlockedPrimaryAttemptShouldNotResolveCredentialOrAuthenticate()
    {
        var context = new AuthenticationContext("test@example.com", IpAddress: "203.0.113.10");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        ConfigureProviderResolution(assertion);
        var audit = new RecordingSecurityEventSink();
        var primaryRateLimiter = new Mock<IPrimaryAuthenticationRateLimiter>();
        primaryRateLimiter.Setup(l => l.CheckAsync(context, assertion, AuthenticationProviderKey.Local, It.IsAny<CancellationToken>()))
            .ReturnsAsync(BlockedDecision());
        _pipeline = new AuthenticationPipeline(
            _providerRegistryMock.Object,
            _credentialServiceMock.Object,
            new NullTransactionProvider(),
            primaryRateLimiter.Object,
            _factorRateLimiterMock.Object,
            new AuthenticationPipelineDependencies(SecurityEventSink: audit));

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.RateLimited));
            Assert.That(response.User, Is.Null);
            Assert.That(audit.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.AuthenticationRateLimited));
            Assert.That(audit.Events.Single().FailureReason, Is.EqualTo(SecurityEventFailureReasons.RateLimited));
            _credentialServiceMock.Verify(
                s => s.ResolveAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), It.IsAny<CancellationToken>()),
                Times.Never);
            _providerMock.Verify(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential?>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task LoginAsyncWithBlockedUnsupportedProviderShouldReturnRateLimitedBeforeUnsupportedFailure()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(new AuthenticationProviderKey(ProviderType.Oidc, "Contoso"));
        var audit = new RecordingSecurityEventSink();
        var primaryRateLimiter = new Mock<IPrimaryAuthenticationRateLimiter>();
        primaryRateLimiter.Setup(l => l.CheckAsync(context, assertion, assertion.ProviderIdentity, It.IsAny<CancellationToken>()))
            .ReturnsAsync(BlockedDecision());
        _pipeline = new AuthenticationPipeline(
            _providerRegistryMock.Object,
            _credentialServiceMock.Object,
            new NullTransactionProvider(),
            primaryRateLimiter.Object,
            _factorRateLimiterMock.Object,
            new AuthenticationPipelineDependencies(SecurityEventSink: audit));

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.RateLimited));
            Assert.That(audit.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.AuthenticationRateLimited));
            Assert.That(audit.Events.Single().FailureReason, Is.EqualTo(SecurityEventFailureReasons.RateLimited));
        }
    }

    [Test]
    public async Task LoginAsyncWithUnprotectFailureAndNoUserShouldFailBeforeProviderAuthentication()
    {
        var context = new AuthenticationContext("ghost@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var audit = new RecordingSecurityEventSink();
        _pipeline = new AuthenticationPipeline(
            _providerRegistryMock.Object,
            _credentialServiceMock.Object,
            new NullTransactionProvider(),
            _primaryRateLimiterMock.Object,
            _factorRateLimiterMock.Object,
            new AuthenticationPipelineDependencies(SecurityEventSink: audit));

        _credentialServiceMock.Setup(s => s.ResolveAsync(context, assertion, provider, It.IsAny<CancellationToken>()))
            .ReturnsAsync(((IUser?)null, (UserCredential?)null, (UserCredential?)null, true));

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(audit.Events.Single().FailureReason, Is.EqualTo(SecurityEventFailureReasons.UnprotectFailed));
            _providerMock.Verify(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential?>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task VerifyFactorAsyncShouldNotUsePrimaryRateLimiterForAllowedSecondaryFactor()
    {
        var userId = Guid.NewGuid();
        var context = new AuthenticationContext("test@example.com", UserId: userId);
        var assertion = new TestAssertion(new AuthenticationProviderKey(ProviderType.Mfa, "totp"));
        var providerMock = new Mock<ISecondaryAuthenticationFactorProvider>();
        providerMock.SetupGet(p => p.Key).Returns(assertion.ProviderIdentity);
        IAuthenticationProvider? provider = providerMock.Object;
        _providerRegistryMock.Setup(r => r.TryGetProvider(assertion, out provider))
            .Returns(true);
        var user = new User { Id = userId, Email = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var primaryRateLimiter = new Mock<IPrimaryAuthenticationRateLimiter>(MockBehavior.Strict);
        _pipeline = new AuthenticationPipeline(
            _providerRegistryMock.Object,
            _credentialServiceMock.Object,
            new NullTransactionProvider(),
            primaryRateLimiter.Object,
            _factorRateLimiterMock.Object);

        _credentialServiceMock.Setup(s => s.ResolveAsync(context, assertion, provider, It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, credential, credential, false));
        providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Failed));

        var response = await _pipeline.VerifyFactorAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            primaryRateLimiter.VerifyNoOtherCalls();
            _factorRateLimiterMock.Verify(l => l.CheckAsync(context, assertion.ProviderIdentity, It.IsAny<CancellationToken>()), Times.Once);
            providerMock.Verify(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [Test]
    public async Task VerifyFactorAsyncWithFactorRateLimiterFailureShouldFailOpenAndCallProvider()
    {
        var userId = Guid.NewGuid();
        var context = new AuthenticationContext("test@example.com", UserId: userId);
        var assertion = new TestAssertion(new AuthenticationProviderKey(ProviderType.Mfa, "totp"));
        var providerMock = new Mock<ISecondaryAuthenticationFactorProvider>();
        providerMock.SetupGet(p => p.Key).Returns(assertion.ProviderIdentity);
        IAuthenticationProvider? provider = providerMock.Object;
        _providerRegistryMock.Setup(r => r.TryGetProvider(assertion, out provider))
            .Returns(true);
        var user = new User { Id = userId, Email = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var factorRateLimiter = new Mock<IAuthenticationFactorRateLimiter>();
        factorRateLimiter.Setup(l => l.CheckAsync(context, assertion.ProviderIdentity, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("limiter unavailable"));
        _pipeline = new AuthenticationPipeline(
            _providerRegistryMock.Object,
            _credentialServiceMock.Object,
            new NullTransactionProvider(),
            _primaryRateLimiterMock.Object,
            factorRateLimiter.Object);

        _credentialServiceMock.Setup(s => s.ResolveAsync(context, assertion, provider, It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, credential, credential, false));
        providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Failed));

        var response = await _pipeline.VerifyFactorAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
            providerMock.Verify(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [Test]
    public async Task VerifyFactorAsyncWithBlockedGenericFactorAttemptShouldNotResolveCredentialOrAuthenticate()
    {
        var userId = Guid.NewGuid();
        var context = new AuthenticationContext("test@example.com", IpAddress: "203.0.113.22", UserId: userId);
        var assertion = new TestAssertion(new AuthenticationProviderKey(ProviderType.Passkey, "Passkey"));
        var providerMock = new Mock<ISecondaryAuthenticationFactorProvider>();
        providerMock.SetupGet(p => p.Key).Returns(assertion.ProviderIdentity);
        IAuthenticationProvider? provider = providerMock.Object;
        _providerRegistryMock.Setup(r => r.TryGetProvider(assertion, out provider))
            .Returns(true);
        var factorRateLimiter = new Mock<IAuthenticationFactorRateLimiter>();
        factorRateLimiter.Setup(l => l.CheckAsync(context, assertion.ProviderIdentity, It.IsAny<CancellationToken>()))
            .ReturnsAsync(BlockedDecision());
        var audit = new RecordingSecurityEventSink();
        _pipeline = new AuthenticationPipeline(
            _providerRegistryMock.Object,
            _credentialServiceMock.Object,
            new NullTransactionProvider(),
            _primaryRateLimiterMock.Object,
            factorRateLimiter.Object,
            new AuthenticationPipelineDependencies(SecurityEventSink: audit));

        var response = await _pipeline.VerifyFactorAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.RateLimited));
            Assert.That(audit.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.AuthenticationRateLimited));
            Assert.That(audit.Events.Single().UserId, Is.EqualTo(userId));
            _credentialServiceMock.Verify(
                s => s.ResolveAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), It.IsAny<CancellationToken>()),
                Times.Never);
            providerMock.Verify(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential?>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task VerifyFactorAsyncShouldRejectPrimaryProviderWithoutCallingProvider()
    {
        var userId = Guid.NewGuid();
        var context = new AuthenticationContext("test@example.com", UserId: userId);
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        ConfigureProviderResolution(assertion);

        var response = await _pipeline.VerifyFactorAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
            _factorRateLimiterMock.Verify(l => l.CheckAsync(context, assertion.ProviderIdentity, It.IsAny<CancellationToken>()), Times.Once);
            _credentialServiceMock.Verify(
                s => s.ResolveAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), It.IsAny<CancellationToken>()),
                Times.Never);
            _providerMock.Verify(
                p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential?>(), It.IsAny<CancellationToken>()),
                Times.Never);
        }
    }

    [Test]
    public async Task VerifyFactorAsyncShouldRejectSecondaryFactorWithoutUserId()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(new AuthenticationProviderKey(ProviderType.Mfa, "totp"));

        var response = await _pipeline.VerifyFactorAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
            _providerRegistryMock.VerifyNoOtherCalls();
            _credentialServiceMock.Verify(
                s => s.ResolveAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), It.IsAny<CancellationToken>()),
                Times.Never);
        }
    }

    [Test]
    public async Task VerifyFactorAsyncShouldRejectUnsupportedFactorProvider()
    {
        var userId = Guid.NewGuid();
        var context = new AuthenticationContext("test@example.com", UserId: userId);
        var assertion = new TestAssertion(new AuthenticationProviderKey(ProviderType.Mfa, "missing"));

        var response = await _pipeline.VerifyFactorAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
            _factorRateLimiterMock.Verify(l => l.CheckAsync(context, assertion.ProviderIdentity, It.IsAny<CancellationToken>()), Times.Once);
            _credentialServiceMock.Verify(
                s => s.ResolveAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), It.IsAny<CancellationToken>()),
                Times.Never);
        }
    }

    [Test]
    public async Task VerifyFactorAsyncWithBlockedUnsupportedFactorProviderShouldReturnRateLimited()
    {
        var userId = Guid.NewGuid();
        var context = new AuthenticationContext("test@example.com", IpAddress: "203.0.113.44", UserId: userId);
        var assertion = new TestAssertion(new AuthenticationProviderKey(ProviderType.Mfa, "missing"));
        var audit = new RecordingSecurityEventSink();
        var factorRateLimiter = new Mock<IAuthenticationFactorRateLimiter>();
        factorRateLimiter.Setup(l => l.CheckAsync(context, assertion.ProviderIdentity, It.IsAny<CancellationToken>()))
            .ReturnsAsync(BlockedDecision());
        _pipeline = new AuthenticationPipeline(
            _providerRegistryMock.Object,
            _credentialServiceMock.Object,
            new NullTransactionProvider(),
            _primaryRateLimiterMock.Object,
            factorRateLimiter.Object,
            new AuthenticationPipelineDependencies(SecurityEventSink: audit));

        var response = await _pipeline.VerifyFactorAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.RateLimited));
            Assert.That(audit.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.AuthenticationRateLimited));
            Assert.That(audit.Events.Single().UserId, Is.EqualTo(userId));
            _credentialServiceMock.Verify(
                s => s.ResolveAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), It.IsAny<CancellationToken>()),
                Times.Never);
        }
    }

    [Test]
    public async Task LoginAsyncShouldRejectFactorOnlyProviderAfterPrimaryRateLimitCheck()
    {
        var context = new AuthenticationContext("test@example.com", UserId: Guid.NewGuid());
        var assertion = new TestAssertion(new AuthenticationProviderKey(ProviderType.Mfa, "totp"));
        var providerMock = new Mock<ISecondaryAuthenticationFactorProvider>();
        providerMock.SetupGet(p => p.Key).Returns(assertion.ProviderIdentity);
        IAuthenticationProvider? provider = providerMock.Object;
        _providerRegistryMock.Setup(r => r.TryGetProvider(assertion, out provider))
            .Returns(true);

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
            _primaryRateLimiterMock.Verify(l => l.CheckAsync(context, assertion, assertion.ProviderIdentity, It.IsAny<CancellationToken>()), Times.Once);
            _credentialServiceMock.Verify(
                s => s.ResolveAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), It.IsAny<CancellationToken>()),
                Times.Never);
            providerMock.Verify(
                p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential?>(), It.IsAny<CancellationToken>()),
                Times.Never);
        }
    }

    [Test]
    public async Task LoginAsyncWithInvalidCredentialsShouldReturnFailed()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com" };
        var credential = CreateCredential(user.Id);

        _credentialServiceMock.Setup(s => s.ResolveAsync(context, assertion, provider, It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, credential, credential, false));
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Failed));

        var response = await _pipeline.LoginAsync(context, assertion);

        Assert.That(response.Succeeded, Is.False);
        _credentialServiceMock.Verify(
            s => s.UpdateCredentialUsageAsync(It.IsAny<UserCredential>(), It.IsAny<UserCredential?>(), It.IsAny<AuthenticationResult>(), It.IsAny<IAuthenticationProvider>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Test]
    public async Task LoginAsyncWithInactiveUserShouldReturnDisabled()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com", IsActive = false };
        var credential = CreateCredential(user.Id);

        _credentialServiceMock.Setup(s => s.ResolveAsync(context, assertion, provider, It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, credential, credential, false));
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded));

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(response.User, Is.SameAs(user));
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Disabled));
        }
    }

    [Test]
    public async Task LoginAsyncWithMfaRequiredShouldReturnMfaRequiredWithoutCredentialUsageUpdate()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var claims = new Dictionary<string, string> { ["amr"] = "pwd" };
        var result = new AuthenticationResult(AuthenticationResultStatus.MfaRequired, claims);

        _credentialServiceMock.Setup(s => s.ResolveAsync(context, assertion, provider, It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, credential, credential, false));
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(result);

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(response.User, Is.SameAs(user));
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.MfaRequired));
            Assert.That(response.Claims, Is.SameAs(result.Claims));
        }

        _credentialServiceMock.Verify(
            s => s.UpdateCredentialUsageAsync(It.IsAny<UserCredential>(), It.IsAny<UserCredential?>(), It.IsAny<AuthenticationResult>(), It.IsAny<IAuthenticationProvider>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Test]
    public async Task LoginAsyncWithSuccessfulAuthenticationShouldUpdateCredentialAndReturnClaims()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var claims = new Dictionary<string, string> { ["sub"] = user.Id.ToString() };
        var result = new AuthenticationResult(AuthenticationResultStatus.SucceededWithCredentialUpdate, claims);

        _credentialServiceMock.Setup(s => s.ResolveAsync(context, assertion, provider, It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, credential, credential, false));
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(result);
        _credentialServiceMock.Setup(s => s.UpdateCredentialUsageAsync(credential, credential, result, provider, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.True);
            Assert.That(response.User, Is.SameAs(user));
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.SuccessWithCredentialUpdate));
            Assert.That(response.Claims, Is.SameAs(result.Claims));
        }
    }

    [Test]
    public async Task LoginAsyncWithSuccessfulAuthenticationAndNoCredentialShouldReturnSuccessWithoutUsageUpdate()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com" };
        var claims = new Dictionary<string, string> { ["sub"] = user.Id.ToString() };
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, claims);

        _credentialServiceMock.Setup(s => s.ResolveAsync(context, assertion, provider, It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, null, null, false));
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(result);

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.True);
            Assert.That(response.User, Is.SameAs(user));
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Success));
            Assert.That(response.Claims, Is.SameAs(result.Claims));
        }

        _credentialServiceMock.Verify(
            s => s.UpdateCredentialUsageAsync(It.IsAny<UserCredential>(), It.IsAny<UserCredential?>(), It.IsAny<AuthenticationResult>(), It.IsAny<IAuthenticationProvider>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Test]
    public async Task LoginAsyncWithFailedAtomicCredentialConsumptionShouldReturnFailed()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, IsCredentialConsumed: true);

        _credentialServiceMock.Setup(s => s.ResolveAsync(context, assertion, provider, It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, credential, credential, false));
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(result);
        _credentialServiceMock.Setup(s => s.UpdateCredentialUsageAsync(credential, credential, result, provider, It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var response = await _pipeline.LoginAsync(context, assertion);

        Assert.That(response.Succeeded, Is.False);
    }

    [Test]
    public void LoginAsyncShouldPropagateCancellationFromCredentialLifecycle()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, IsCredentialConsumed: true);

        _credentialServiceMock.Setup(s => s.ResolveAsync(context, assertion, provider, It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, credential, credential, false));
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(result);
        _credentialServiceMock.Setup(s => s.UpdateCredentialUsageAsync(credential, credential, result, provider, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new OperationCanceledException());

        Assert.ThrowsAsync<OperationCanceledException>(() => _pipeline.LoginAsync(context, assertion));
    }

    [Test]
    public async Task LoginAsyncWithFailedRequiredCredentialUpdateShouldReturnFailedWithoutUserToAvoidOracle()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, CredentialUpdateRequirement: CredentialUpdateRequirement.Required);

        _credentialServiceMock.Setup(s => s.ResolveAsync(context, assertion, provider, It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, credential, credential, false));
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(result);
        _credentialServiceMock.Setup(s => s.UpdateCredentialUsageAsync(credential, credential, result, provider, It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(response.User, Is.Null);
        }
    }

    [Test]
    public async Task LoginAsyncWithExceptionOnRequiredCredentialUpdateShouldReturnFailedWithoutUserToAvoidOracle()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, CredentialUpdateRequirement: CredentialUpdateRequirement.Required);

        _credentialServiceMock.Setup(s => s.ResolveAsync(context, assertion, provider, It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, credential, credential, false));
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(result);
        _credentialServiceMock.Setup(s => s.UpdateCredentialUsageAsync(credential, credential, result, provider, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("DB error"));

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(response.User, Is.Null);
        }
    }

    [Test]
    public async Task LoginAsyncWithExceptionOnBestEffortCredentialUpdateShouldStillReturnSuccess()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, CredentialUpdateRequirement: CredentialUpdateRequirement.BestEffort);

        _credentialServiceMock.Setup(s => s.ResolveAsync(context, assertion, provider, It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, credential, credential, false));
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(result);
        _credentialServiceMock.Setup(s => s.UpdateCredentialUsageAsync(credential, credential, result, provider, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("DB error"));

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.True);
            Assert.That(response.User, Is.SameAs(user));
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Success));
        }
    }

    [Test]
    public async Task LoginAsyncWithExceptionOnBestEffortCredentialUpdateAndInitializedProviderTypeShouldStillReturnSuccess()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        _providerMock.SetupGet(p => p.Key).Returns(AuthenticationProviderKey.Local);
        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, CredentialUpdateRequirement: CredentialUpdateRequirement.BestEffort);

        _credentialServiceMock.Setup(s => s.ResolveAsync(context, assertion, provider, It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, credential, credential, false));
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(result);
        _credentialServiceMock.Setup(s => s.UpdateCredentialUsageAsync(credential, credential, result, provider, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("DB error"));

        var response = await _pipeline.LoginAsync(context, assertion);

        Assert.That(response.Succeeded, Is.True);
    }

    [Test]
    public async Task LoginAsyncWithNestedTransactionRollbackFromBestEffortCredentialUpdateShouldStillReturnSuccess()
    {
        var transactionProvider = new RollbackOnlyTransactionProvider();
        _pipeline = new AuthenticationPipeline(_providerRegistryMock.Object, _credentialServiceMock.Object, transactionProvider, _primaryRateLimiterMock.Object, _factorRateLimiterMock.Object);
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, CredentialUpdateRequirement: CredentialUpdateRequirement.BestEffort);

        _credentialServiceMock.Setup(s => s.ResolveAsync(context, assertion, provider, It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, credential, credential, false));
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(result);
        _credentialServiceMock.Setup(s => s.UpdateCredentialUsageAsync(credential, credential, result, provider, It.IsAny<CancellationToken>()))
            .Returns(async () =>
            {
                await using var transaction = await transactionProvider.BeginTransactionAsync();
                throw new InvalidOperationException("DB error");
            });

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.True);
            Assert.That(response.User, Is.SameAs(user));
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Success));
        }
    }

    private IAuthenticationProvider ConfigureProviderResolution(IAuthenticationAssertion assertion)
    {
        _providerMock.SetupGet(p => p.Key).Returns(assertion.ProviderIdentity);
        IAuthenticationProvider? provider = _providerMock.Object;
        _providerRegistryMock.Setup(r => r.TryGetProvider(assertion, out provider))
            .Returns(true);
        return provider!;
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
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active
        };
    }

    private static RateLimitDecision BlockedDecision()
    {
        return new RateLimitDecision
        {
            Status = RateLimitStatus.Blocked,
            Remaining = 0,
            WindowResetAt = DateTimeOffset.UtcNow.AddMinutes(1),
            RetryAfter = DateTimeOffset.UtcNow.AddMinutes(1)
        };
    }

    private static Mock<IPrimaryAuthenticationRateLimiter> CreateAllowingPrimaryRateLimiter()
    {
        var primaryRateLimiter = new Mock<IPrimaryAuthenticationRateLimiter>();
        primaryRateLimiter.Setup(l => l.CheckAsync(
                It.IsAny<AuthenticationContext>(),
                It.IsAny<IAuthenticationAssertion>(),
                It.IsAny<AuthenticationProviderKey>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(RateLimitDecision.Allow());
        return primaryRateLimiter;
    }

    private static Mock<IAuthenticationFactorRateLimiter> CreateAllowingFactorRateLimiter()
    {
        var factorRateLimiter = new Mock<IAuthenticationFactorRateLimiter>();
        factorRateLimiter.Setup(l => l.CheckAsync(
                It.IsAny<AuthenticationContext>(),
                It.IsAny<AuthenticationProviderKey>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(RateLimitDecision.Allow());
        return factorRateLimiter;
    }

    private sealed record TestAssertion(AuthenticationProviderKey ProviderIdentity) : IAuthenticationAssertion;

    private sealed class RecordingSecurityEventSink : ISecurityEventSink
    {
        public List<AshlarSecurityEvent> Events { get; } = [];

        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            Events.Add(securityEvent);
            return Task.CompletedTask;
        }
    }

    private sealed class RollbackOnlyTransactionProvider : IAshlarTransactionProvider
    {
        private bool _hasActiveTransaction;
        private bool _mustRollback;
        private readonly List<Func<CancellationToken, Task>> _hooks = [];

        public Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_hasActiveTransaction)
            {
                return Task.FromResult<IAshlarTransaction>(new JointTransaction(this));
            }

            _hasActiveTransaction = true;
            _mustRollback = false;
            return Task.FromResult<IAshlarTransaction>(new RootTransaction(this));
        }

        private sealed class JointTransaction(RollbackOnlyTransactionProvider provider) : IAshlarTransaction
        {
            private bool _committed;
            private bool _disposed;

            public Task CommitAsync(CancellationToken cancellationToken = default)
            {
                cancellationToken.ThrowIfCancellationRequested();
                ObjectDisposedException.ThrowIf(_disposed, this);
                _committed = true;
                return Task.CompletedTask;
            }

            public Task RollbackAsync(CancellationToken cancellationToken = default)
            {
                cancellationToken.ThrowIfCancellationRequested();
                ObjectDisposedException.ThrowIf(_disposed, this);
                provider._mustRollback = true;
                return Task.CompletedTask;
            }

            public void OnCommitted(Func<CancellationToken, Task> action)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                provider._hooks.Add(action);
            }

            public ValueTask DisposeAsync()
            {
                if (_disposed) return ValueTask.CompletedTask;
                _disposed = true;

                if (!_committed)
                {
                    provider._mustRollback = true;
                }

                return ValueTask.CompletedTask;
            }
        }

        private sealed class RootTransaction(RollbackOnlyTransactionProvider provider) : IAshlarTransaction
        {
            private bool _disposed;

            public async Task CommitAsync(CancellationToken cancellationToken = default)
            {
                cancellationToken.ThrowIfCancellationRequested();
                ObjectDisposedException.ThrowIf(_disposed, this);
                if (provider._mustRollback)
                {
                    throw new InvalidOperationException("The transaction cannot be committed because it has been marked for rollback by a nested participant.");
                }

                _disposed = true;
                provider._hasActiveTransaction = false;
                provider._mustRollback = false;

                foreach (var hook in provider._hooks)
                {
                    await hook(cancellationToken);
                }

                provider._hooks.Clear();
            }

            public Task RollbackAsync(CancellationToken cancellationToken = default)
            {
                cancellationToken.ThrowIfCancellationRequested();
                ObjectDisposedException.ThrowIf(_disposed, this);
                _disposed = true;
                provider._hasActiveTransaction = false;
                provider._mustRollback = false;
                provider._hooks.Clear();
                return Task.CompletedTask;
            }

            public void OnCommitted(Func<CancellationToken, Task> action)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                provider._hooks.Add(action);
            }

            public ValueTask DisposeAsync()
            {
                if (_disposed) return ValueTask.CompletedTask;
                _disposed = true;
                provider._hasActiveTransaction = false;
                provider._mustRollback = false;
                return ValueTask.CompletedTask;
            }
        }
    }
}
