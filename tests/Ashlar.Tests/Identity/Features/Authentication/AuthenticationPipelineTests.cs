using Moq;
using Ashlar.Auditing;
using Ashlar.Identity.Models.AccountLockout;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Tests.Identity.Features.Authentication;

#pragma warning disable CS1591
public interface ITestAccountLockoutService
{
    Task<AccountLockoutStatus> GetStatusAsync(IUser user, AuthenticationProviderKey provider, AccountLockoutContext? context = null, CancellationToken cancellationToken = default);
    Task<AccountLockoutFailureResult> RecordFailureAsync(IUser user, AuthenticationProviderKey provider, AccountLockoutContext? context = null, CancellationToken cancellationToken = default);
    Task<bool> ResetAsync(IUser user, AuthenticationProviderKey provider, AccountLockoutContext? context = null, CancellationToken cancellationToken = default);
}
#pragma warning restore CS1591

internal sealed class TestAccountLockoutService(ITestAccountLockoutService inner) : IAccountLockoutService
{
    public Task<AccountLockoutStatus> GetStatusAsync(IUser user, AuthenticationProviderKey provider, AccountLockoutContext? context = null, CancellationToken cancellationToken = default)
        => inner.GetStatusAsync(user, provider, context, cancellationToken);

    public Task<AccountLockoutFailureResult> RecordFailureAsync(IUser user, AuthenticationProviderKey provider, AccountLockoutContext? context = null, CancellationToken cancellationToken = default)
        => inner.RecordFailureAsync(user, provider, context, cancellationToken);

    public Task<bool> ResetAsync(IUser user, AuthenticationProviderKey provider, AccountLockoutContext? context = null, CancellationToken cancellationToken = default)
        => inner.ResetAsync(user, provider, context, cancellationToken);
}

internal sealed class AuthenticationPipelineTests
{
    private Mock<IAuthenticationProviderRegistry> _providerRegistryMock;
    private TestCredentialService _credentialService;
    private Mock<IPrimaryAuthenticationProvider> _providerMock;
    private Mock<IPrimaryAuthenticationRateLimiter> _primaryRateLimiterMock;
    private Mock<IAuthenticationFactorRateLimiter> _factorRateLimiterMock;
    private Mock<ITestAccountLockoutService> _accountLockoutServiceMock;
    private AuthenticationPipeline _pipeline;

    [SetUp]
    public void SetUp()
    {
        _providerRegistryMock = new Mock<IAuthenticationProviderRegistry>();
        _credentialService = new TestCredentialService();
        _providerMock = new Mock<IPrimaryAuthenticationProvider>();
        _primaryRateLimiterMock = CreateAllowingPrimaryRateLimiter();
        _factorRateLimiterMock = CreateAllowingFactorRateLimiter();
        _accountLockoutServiceMock = new Mock<ITestAccountLockoutService>();
        _pipeline = new AuthenticationPipeline(_providerRegistryMock.Object, _credentialService, AshlarDurableTransactionProvider.Create(new NullTransactionProvider()), _primaryRateLimiterMock.Object, _factorRateLimiterMock.Object);
    }

    [Test]
    public void ConstructorShouldThrowOnNullProviderRegistry()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationPipeline(null!, _credentialService, AshlarDurableTransactionProvider.Create(new NullTransactionProvider()), _primaryRateLimiterMock.Object, _factorRateLimiterMock.Object));
    }

    [Test]
    public void ConstructorShouldThrowOnNullCredentialService()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationPipeline(_providerRegistryMock.Object, null!, AshlarDurableTransactionProvider.Create(new NullTransactionProvider()), _primaryRateLimiterMock.Object, _factorRateLimiterMock.Object));
    }

    [Test]
    public void ConstructorShouldThrowOnNullTransactionProvider()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationPipeline(_providerRegistryMock.Object, _credentialService, null!, _primaryRateLimiterMock.Object, _factorRateLimiterMock.Object));
    }

    [Test]
    public void ConstructorShouldThrowOnNullPrimaryRateLimiter()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationPipeline(_providerRegistryMock.Object, _credentialService, AshlarDurableTransactionProvider.Create(new NullTransactionProvider()), null!, _factorRateLimiterMock.Object));
    }

    [Test]
    public void ConstructorShouldThrowOnNullFactorRateLimiter()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationPipeline(_providerRegistryMock.Object, _credentialService, AshlarDurableTransactionProvider.Create(new NullTransactionProvider()), _primaryRateLimiterMock.Object, null!));
    }

    [Test]
    public void ConstructorShouldAcceptNonNullOptionalLogger()
    {
        var pipeline = new AuthenticationPipeline(
            _providerRegistryMock.Object,
            _credentialService,
            AshlarDurableTransactionProvider.Create(new NullTransactionProvider()),
            _primaryRateLimiterMock.Object,
            _factorRateLimiterMock.Object,
            new AuthenticationPipelineDependencies(Logger: Microsoft.Extensions.Logging.Abstractions.NullLogger<AuthenticationPipeline>.Instance));

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

        Assert.That(_credentialService.ContextResolveCalls, Is.Zero);
    }

    [Test]
    public async Task LoginAsyncWithAllowedPrimaryAttemptShouldCheckRateLimitAndCallProvider()
    {
        var context = new AuthenticationContext("test@example.com", IpAddress: "203.0.113.10");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var primaryRateLimiter = new Mock<IPrimaryAuthenticationRateLimiter>();
        primaryRateLimiter.Setup(l => l.CheckAsync(context, assertion, AuthenticationProviderKey.Local, It.IsAny<CancellationToken>()))
            .ReturnsAsync(RateLimitDecision.Allow());
        _pipeline = new AuthenticationPipeline(
            _providerRegistryMock.Object,
            _credentialService,
            AshlarDurableTransactionProvider.Create(new NullTransactionProvider()),
            primaryRateLimiter.Object,
            _factorRateLimiterMock.Object);
        _credentialService.ContextResolveResult = (user, credential, credential, false);
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
    public async Task LoginAsyncWithPrimaryRateLimiterFailureShouldFailClosedAndSkipProvider()
    {
        var context = new AuthenticationContext("test@example.com", IpAddress: "203.0.113.10");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        ConfigureProviderResolution(assertion);
        var logger = new Ashlar.Testing.RecordingLogger<AuthenticationPipeline>();
        var primaryRateLimiter = new Mock<IPrimaryAuthenticationRateLimiter>();
        primaryRateLimiter.Setup(l => l.CheckAsync(context, assertion, AuthenticationProviderKey.Local, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("limiter unavailable"));
        _pipeline = new AuthenticationPipeline(
            _providerRegistryMock.Object,
            _credentialService,
            AshlarDurableTransactionProvider.Create(new NullTransactionProvider()),
            primaryRateLimiter.Object,
            _factorRateLimiterMock.Object,
            new AuthenticationPipelineDependencies(Logger: logger));

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.RateLimited));
            Assert.That(response.User, Is.Null);
            Assert.That(logger.Entries.Single().Level, Is.EqualTo(Microsoft.Extensions.Logging.LogLevel.Error));
            Assert.That(logger.Entries.Single().Message, Does.Contain("FailOpen=False"));
            Assert.That(logger.Entries.Single().Message, Does.Not.Contain("limiter unavailable"));
            Assert.That(_credentialService.ContextResolveCalls, Is.Zero);
            _providerMock.Verify(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential?>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task LoginAsyncWithPrimaryRateLimiterFailureShouldFailOpenWhenConfigured()
    {
        var context = new AuthenticationContext("test@example.com", IpAddress: "203.0.113.10");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var logger = new Ashlar.Testing.RecordingLogger<AuthenticationPipeline>();
        var primaryRateLimiter = new Mock<IPrimaryAuthenticationRateLimiter>();
        primaryRateLimiter.Setup(l => l.CheckAsync(context, assertion, AuthenticationProviderKey.Local, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("limiter unavailable"));
        _pipeline = new AuthenticationPipeline(
            _providerRegistryMock.Object,
            _credentialService,
            AshlarDurableTransactionProvider.Create(new NullTransactionProvider()),
            primaryRateLimiter.Object,
            _factorRateLimiterMock.Object,
            new AuthenticationPipelineDependencies(
                Logger: logger,
                PrimaryRateLimitOptions: new PrimaryAuthenticationRateLimitOptions { FailOpenOnBackendFailure = true }));
        _credentialService.ContextResolveResult = (user, credential, credential, false);
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Failed));

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
            Assert.That(logger.Entries.Single().Message, Does.Contain("FailOpen=True"));
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
            _credentialService,
            AshlarDurableTransactionProvider.Create(new NullTransactionProvider()),
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
            _credentialService,
            AshlarDurableTransactionProvider.Create(new NullTransactionProvider()),
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
            Assert.That(_credentialService.ContextResolveCalls, Is.Zero);
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
            _credentialService,
            AshlarDurableTransactionProvider.Create(new NullTransactionProvider()),
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
            _credentialService,
            AshlarDurableTransactionProvider.Create(new NullTransactionProvider()),
            _primaryRateLimiterMock.Object,
            _factorRateLimiterMock.Object,
            new AuthenticationPipelineDependencies(SecurityEventSink: audit));
        _credentialService.ContextResolveResult = ((IUser?)null, (UserCredential?)null, (UserCredential?)null, true);

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
        var user = new User { Id = userId, DisplayEmail = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var primaryRateLimiter = new Mock<IPrimaryAuthenticationRateLimiter>(MockBehavior.Strict);
        _pipeline = new AuthenticationPipeline(
            _providerRegistryMock.Object,
            _credentialService,
            AshlarDurableTransactionProvider.Create(new NullTransactionProvider()),
            primaryRateLimiter.Object,
            _factorRateLimiterMock.Object);
        _credentialService.ContextResolveResult = (user, credential, credential, false);
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
    public async Task VerifyFactorAsyncWithFactorRateLimiterFailureShouldFailClosedAndSkipProvider()
    {
        var userId = Guid.NewGuid();
        var context = new AuthenticationContext("test@example.com", UserId: userId);
        var assertion = new TestAssertion(new AuthenticationProviderKey(ProviderType.Mfa, "totp"));
        var providerMock = new Mock<ISecondaryAuthenticationFactorProvider>();
        providerMock.SetupGet(p => p.Key).Returns(assertion.ProviderIdentity);
        IAuthenticationProvider? provider = providerMock.Object;
        _providerRegistryMock.Setup(r => r.TryGetProvider(assertion, out provider))
            .Returns(true);
        var logger = new Ashlar.Testing.RecordingLogger<AuthenticationPipeline>();
        var factorRateLimiter = new Mock<IAuthenticationFactorRateLimiter>();
        factorRateLimiter.Setup(l => l.CheckAsync(context, assertion.ProviderIdentity, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("limiter unavailable"));
        _pipeline = new AuthenticationPipeline(
            _providerRegistryMock.Object,
            _credentialService,
            AshlarDurableTransactionProvider.Create(new NullTransactionProvider()),
            _primaryRateLimiterMock.Object,
            factorRateLimiter.Object,
            new AuthenticationPipelineDependencies(Logger: logger));

        var response = await _pipeline.VerifyFactorAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.RateLimited));
            Assert.That(logger.Entries.Single().Level, Is.EqualTo(Microsoft.Extensions.Logging.LogLevel.Error));
            Assert.That(logger.Entries.Single().Message, Does.Contain("Scope=factor"));
            Assert.That(logger.Entries.Single().Message, Does.Contain("FailOpen=False"));
            Assert.That(logger.Entries.Single().Message, Does.Not.Contain("limiter unavailable"));
            Assert.That(_credentialService.ContextResolveCalls, Is.Zero);
            providerMock.Verify(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential?>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task VerifyFactorAsyncWithFactorRateLimiterFailureShouldFailOpenWhenConfigured()
    {
        var userId = Guid.NewGuid();
        var context = new AuthenticationContext("test@example.com", UserId: userId);
        var assertion = new TestAssertion(new AuthenticationProviderKey(ProviderType.Mfa, "totp"));
        var providerMock = new Mock<ISecondaryAuthenticationFactorProvider>();
        providerMock.SetupGet(p => p.Key).Returns(assertion.ProviderIdentity);
        IAuthenticationProvider? provider = providerMock.Object;
        _providerRegistryMock.Setup(r => r.TryGetProvider(assertion, out provider))
            .Returns(true);
        var user = new User { Id = userId, DisplayEmail = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var factorRateLimiter = new Mock<IAuthenticationFactorRateLimiter>();
        factorRateLimiter.Setup(l => l.CheckAsync(context, assertion.ProviderIdentity, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("limiter unavailable"));
        _pipeline = new AuthenticationPipeline(
            _providerRegistryMock.Object,
            _credentialService,
            AshlarDurableTransactionProvider.Create(new NullTransactionProvider()),
            _primaryRateLimiterMock.Object,
            factorRateLimiter.Object,
            new AuthenticationPipelineDependencies(
                FactorRateLimitOptions: new AuthenticationFactorRateLimitOptions { FailOpenOnBackendFailure = true }));
        _credentialService.ContextResolveResult = (user, credential, credential, false);
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
            _credentialService,
            AshlarDurableTransactionProvider.Create(new NullTransactionProvider()),
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
            Assert.That(_credentialService.ContextResolveCalls, Is.Zero);
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
            Assert.That(_credentialService.ContextResolveCalls, Is.Zero);
            _providerMock.Verify(
                p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential?>(), It.IsAny<CancellationToken>()),
                Times.Never);
        }
    }

    [Test]
    public async Task VerifyFactorAsyncShouldRejectUnverifiedUserVerificationAssertionWithoutCallingProvider()
    {
        var userId = Guid.NewGuid();
        var context = new AuthenticationContext("test@example.com", UserId: userId);
        var assertion = new TestUserVerifiedAssertion(new AuthenticationProviderKey(ProviderType.Passkey, "PASSKEY"), UserVerified: false);
        var providerMock = new Mock<ISecondaryAuthenticationFactorProvider>();
        providerMock.SetupGet(p => p.Key).Returns(assertion.ProviderIdentity);
        IAuthenticationProvider? provider = providerMock.Object;
        _providerRegistryMock.Setup(r => r.TryGetProvider(assertion, out provider))
            .Returns(true);

        var response = await _pipeline.VerifyFactorAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
            _factorRateLimiterMock.Verify(l => l.CheckAsync(context, assertion.ProviderIdentity, It.IsAny<CancellationToken>()), Times.Once);
            Assert.That(_credentialService.ContextResolveCalls, Is.Zero);
            providerMock.Verify(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential?>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task LoginAsyncShouldAllowPrimaryUserVerificationAssertionWithoutUserVerification()
    {
        var userId = Guid.NewGuid();
        var context = new AuthenticationContext("test@example.com", UserId: userId);
        var assertion = new TestUserVerifiedAssertion(AuthenticationProviderKey.Local, UserVerified: false);
        ConfigureProviderResolution(assertion);
        var user = new User { Id = userId, DisplayEmail = "test@example.com" };
        var credential = CreateCredential(userId);
        _credentialService.ContextResolveResult = (user, credential, credential, false);
        _credentialService.UsageUpdateResult = CredentialUsageUpdateResult.NotNeeded;
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded));

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.True);
            _providerMock.Verify(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()), Times.Once);
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
            Assert.That(_credentialService.ContextResolveCalls, Is.Zero);
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
            Assert.That(_credentialService.ContextResolveCalls, Is.Zero);
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
            _credentialService,
            AshlarDurableTransactionProvider.Create(new NullTransactionProvider()),
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
            Assert.That(_credentialService.ContextResolveCalls, Is.Zero);
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
            Assert.That(_credentialService.ContextResolveCalls, Is.Zero);
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
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };
        var credential = CreateCredential(user.Id);
        _credentialService.ContextResolveResult = (user, credential, credential, false);
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Failed));

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(_credentialService.UsageUpdateCalls, Is.Zero);
        }
    }

    [Test]
    public async Task LoginAsyncWithLocalPasswordFailureShouldRecordAccountLockoutFailureForResolvedActiveUser()
    {
        var context = new AuthenticationContext("test@example.com", TenantId: Guid.NewGuid());
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com", TenantId = context.TenantId };
        var credential = CreateCredential(user.Id);
        UseAccountLockoutService();
        _accountLockoutServiceMock.Setup(s => s.GetStatusAsync(user, AuthenticationProviderKey.Local, It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(AccountLockoutStatus.None(user.Id, user.TenantId, AuthenticationProviderKey.Local));
        _accountLockoutServiceMock.Setup(s => s.RecordFailureAsync(user, AuthenticationProviderKey.Local, It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AccountLockoutFailureResult(AccountLockoutStatus.None(user.Id, user.TenantId, AuthenticationProviderKey.Local), false, false));
        _credentialService.ContextResolveResult = (user, credential, credential, false);
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Failed));

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            _accountLockoutServiceMock.Verify(s => s.RecordFailureAsync(user, AuthenticationProviderKey.Local, It.Is<AccountLockoutContext>(c => c.Tenant!.TenantId == context.TenantId), It.IsAny<CancellationToken>()), Times.Once);
            _accountLockoutServiceMock.Verify(s => s.ResetAsync(It.IsAny<IUser>(), It.IsAny<AuthenticationProviderKey>(), It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task LoginAsyncWithGlobalLocalPasswordUserAndNoContextTenantShouldUseGlobalLockoutContext()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };
        var credential = CreateCredential(user.Id);
        UseAccountLockoutService();
        _accountLockoutServiceMock.Setup(s => s.GetStatusAsync(user, AuthenticationProviderKey.Local, It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(AccountLockoutStatus.None(user.Id, user.TenantId, AuthenticationProviderKey.Local));
        _accountLockoutServiceMock.Setup(s => s.RecordFailureAsync(user, AuthenticationProviderKey.Local, It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AccountLockoutFailureResult(AccountLockoutStatus.None(user.Id, user.TenantId, AuthenticationProviderKey.Local), false, false));
        _credentialService.ContextResolveResult = (user, credential, credential, false);
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Failed));

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            _accountLockoutServiceMock.Verify(s => s.GetStatusAsync(user, AuthenticationProviderKey.Local, It.Is<AccountLockoutContext>(c => c.Tenant == null), It.IsAny<CancellationToken>()), Times.Once);
            _accountLockoutServiceMock.Verify(s => s.RecordFailureAsync(user, AuthenticationProviderKey.Local, It.Is<AccountLockoutContext>(c => c.Tenant == null), It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [Test]
    public async Task LoginAsyncWithLocalPasswordSuccessShouldResetAccountLockoutAfterSuccessfulAuthentication()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded);
        UseAccountLockoutService();
        _accountLockoutServiceMock.Setup(s => s.GetStatusAsync(user, AuthenticationProviderKey.Local, It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(AccountLockoutStatus.None(user.Id, user.TenantId, AuthenticationProviderKey.Local));
        _accountLockoutServiceMock.Setup(s => s.ResetAsync(user, AuthenticationProviderKey.Local, It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
        _credentialService.ContextResolveResult = (user, credential, credential, false);
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(result);
        _credentialService.UsageUpdateResult = CredentialUsageUpdateResult.NotNeeded;

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.True);
            _accountLockoutServiceMock.Verify(s => s.ResetAsync(user, AuthenticationProviderKey.Local, It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [Test]
    public async Task LoginAsyncWithActiveAutomaticLockoutShouldBlockLocalPasswordBeforeProviderVerification()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var audit = new RecordingSecurityEventSink();
        UseAccountLockoutService(audit);
        _accountLockoutServiceMock.Setup(s => s.GetStatusAsync(user, AuthenticationProviderKey.Local, It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AccountLockoutStatus(user.Id, user.TenantId, AuthenticationProviderKey.Local, 5, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), true));
        _credentialService.ContextResolveResult = (user, credential, credential, false);

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
            Assert.That(response.User, Is.Null);
            Assert.That(audit.Events.Single().FailureReason, Is.EqualTo(SecurityEventFailureReasons.AutomaticAccountLockout));
            _providerMock.Verify(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential?>(), It.IsAny<CancellationToken>()), Times.Never);
            _accountLockoutServiceMock.Verify(s => s.RecordFailureAsync(It.IsAny<IUser>(), It.IsAny<AuthenticationProviderKey>(), It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task LoginAsyncWithThresholdCrossingLocalPasswordFailureShouldReturnGenericFailedResult()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var audit = new RecordingSecurityEventSink();
        UseAccountLockoutService(audit);
        _accountLockoutServiceMock.Setup(s => s.GetStatusAsync(user, AuthenticationProviderKey.Local, It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(AccountLockoutStatus.None(user.Id, user.TenantId, AuthenticationProviderKey.Local));
        _accountLockoutServiceMock.Setup(s => s.RecordFailureAsync(user, AuthenticationProviderKey.Local, It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AccountLockoutFailureResult(new AccountLockoutStatus(user.Id, user.TenantId, AuthenticationProviderKey.Local, 5, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), true), true, true));
        _credentialService.ContextResolveResult = (user, credential, credential, false);
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Failed));

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(response.User, Is.Null);
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
            Assert.That(audit.Events.Single().FailureReason, Is.EqualTo(SecurityEventFailureReasons.AutomaticAccountLockout));
        }
    }

    [Test]
    public async Task LoginAsyncWithUnknownLocalPasswordUserShouldNotRecordAccountLockoutFailure()
    {
        var context = new AuthenticationContext("ghost@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        UseAccountLockoutService();
        _credentialService.ContextResolveResult = ((IUser?)null, (UserCredential?)null, (UserCredential?)null, false);
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Failed));

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            _accountLockoutServiceMock.Verify(s => s.GetStatusAsync(It.IsAny<IUser>(), It.IsAny<AuthenticationProviderKey>(), It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()), Times.Never);
            _accountLockoutServiceMock.Verify(s => s.RecordFailureAsync(It.IsAny<IUser>(), It.IsAny<AuthenticationProviderKey>(), It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [TestCase(UserAccountState.Disabled)]
    [TestCase(UserAccountState.Locked)]
    [TestCase(UserAccountState.Suspended)]
    public async Task LoginAsyncWithUnavailableLocalPasswordUserShouldNotRecordOrResetAccountLockout(UserAccountState accountState)
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com", AccountState = accountState };
        var credential = CreateCredential(user.Id);
        UseAccountLockoutService();
        _credentialService.ContextResolveResult = (user, credential, credential, false);
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded));

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Disabled));
            _accountLockoutServiceMock.Verify(s => s.GetStatusAsync(It.IsAny<IUser>(), It.IsAny<AuthenticationProviderKey>(), It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()), Times.Never);
            _accountLockoutServiceMock.Verify(s => s.RecordFailureAsync(It.IsAny<IUser>(), It.IsAny<AuthenticationProviderKey>(), It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()), Times.Never);
            _accountLockoutServiceMock.Verify(s => s.ResetAsync(It.IsAny<IUser>(), It.IsAny<AuthenticationProviderKey>(), It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task LoginAsyncWithNonLocalProviderShouldNotUseAccountLockout()
    {
        var providerKey = new AuthenticationProviderKey(ProviderType.Oidc, "contoso");
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(providerKey);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };
        var credential = CreateCredential(user.Id);
        UseAccountLockoutService();
        _credentialService.ContextResolveResult = (user, credential, credential, false);
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Failed));

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            _accountLockoutServiceMock.VerifyNoOtherCalls();
        }
    }

    [TestCase(UserAccountState.Disabled)]
    [TestCase(UserAccountState.Locked)]
    [TestCase(UserAccountState.Suspended)]
    public async Task LoginAsyncWithUnavailableUserShouldReturnDisabled(UserAccountState accountState)
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com", AccountState = accountState };
        var credential = CreateCredential(user.Id);
        _credentialService.ContextResolveResult = (user, credential, credential, false);
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
    public async Task LoginAsyncWithUnknownUnavailableStateShouldReturnDisabledWithGenericFailureReason()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com", AccountState = (UserAccountState)999 };
        var credential = CreateCredential(user.Id);
        _credentialService.ContextResolveResult = (user, credential, credential, false);
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded));

        var response = await _pipeline.LoginAsync(context, assertion);

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Disabled));
    }

    [Test]
    public async Task LoginAsyncWithMfaRequiredShouldReturnMfaRequiredWithoutCredentialUsageUpdate()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var claims = new Dictionary<string, string> { ["amr"] = "pwd" };
        var result = new AuthenticationResult(AuthenticationResultStatus.MfaRequired, claims);
        _credentialService.ContextResolveResult = (user, credential, credential, false);
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

        Assert.That(_credentialService.UsageUpdateCalls, Is.Zero);
    }

    [Test]
    public async Task LoginAsyncWithMfaRequiredLocalPasswordSuccessShouldResetAccountLockout()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var result = new AuthenticationResult(AuthenticationResultStatus.MfaRequired);
        UseAccountLockoutService();
        _accountLockoutServiceMock.Setup(s => s.GetStatusAsync(user, AuthenticationProviderKey.Local, It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(AccountLockoutStatus.None(user.Id, user.TenantId, AuthenticationProviderKey.Local));
        _accountLockoutServiceMock.Setup(s => s.ResetAsync(user, AuthenticationProviderKey.Local, It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
        _credentialService.ContextResolveResult = (user, credential, credential, false);
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(result);

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.MfaRequired));
            _accountLockoutServiceMock.Verify(s => s.ResetAsync(user, AuthenticationProviderKey.Local, It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()), Times.Once);
            _accountLockoutServiceMock.Verify(s => s.RecordFailureAsync(It.IsAny<IUser>(), It.IsAny<AuthenticationProviderKey>(), It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task LoginAsyncWithPrimaryRateLimitBlockedShouldNotCheckAccountLockout()
    {
        var context = new AuthenticationContext("test@example.com", IpAddress: "203.0.113.10");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        ConfigureProviderResolution(assertion);
        var primaryRateLimiter = new Mock<IPrimaryAuthenticationRateLimiter>();
        primaryRateLimiter.Setup(l => l.CheckAsync(context, assertion, AuthenticationProviderKey.Local, It.IsAny<CancellationToken>()))
            .ReturnsAsync(BlockedDecision());
        _pipeline = new AuthenticationPipeline(
            _providerRegistryMock.Object,
            _credentialService,
            AshlarDurableTransactionProvider.Create(new NullTransactionProvider()),
            primaryRateLimiter.Object,
            _factorRateLimiterMock.Object,
            new AuthenticationPipelineDependencies(AccountLockoutService: new TestAccountLockoutService(_accountLockoutServiceMock.Object)));

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.RateLimited));
            _accountLockoutServiceMock.VerifyNoOtherCalls();
        }
    }

    [Test]
    public async Task LoginAsyncWithAccountLockoutStatusFailureShouldFailClosedAndSkipPasswordVerification()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var logger = new Ashlar.Testing.RecordingLogger<AuthenticationPipeline>();
        UseAccountLockoutService(logger);
        _accountLockoutServiceMock.Setup(s => s.GetStatusAsync(user, AuthenticationProviderKey.Local, It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("lockout unavailable"));
        _credentialService.ContextResolveResult = (user, credential, credential, false);

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.RateLimited));
            Assert.That(logger.Entries.Single().Level, Is.EqualTo(Microsoft.Extensions.Logging.LogLevel.Error));
            Assert.That(logger.Entries.Single().Message, Does.Contain("Operation=get_status"));
            Assert.That(logger.Entries.Single().Message, Does.Contain("FailOpen=False"));
            Assert.That(logger.Entries.Single().Message, Does.Not.Contain("lockout unavailable"));
            _providerMock.Verify(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential?>(), It.IsAny<CancellationToken>()), Times.Never);
            _accountLockoutServiceMock.Verify(s => s.RecordFailureAsync(user, AuthenticationProviderKey.Local, It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task LoginAsyncWithAccountLockoutStatusFailureShouldFailOpenWhenConfigured()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };
        var credential = CreateCredential(user.Id);
        UseAccountLockoutService(new AccountLockoutOptions { FailOpenOnBackendFailure = true });
        _accountLockoutServiceMock.Setup(s => s.GetStatusAsync(user, AuthenticationProviderKey.Local, It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("lockout unavailable"));
        _credentialService.ContextResolveResult = (user, credential, credential, false);
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Failed));
        _accountLockoutServiceMock.Setup(s => s.RecordFailureAsync(user, AuthenticationProviderKey.Local, It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AccountLockoutFailureResult(AccountLockoutStatus.None(user.Id, user.TenantId, AuthenticationProviderKey.Local), false, false));

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
            _providerMock.Verify(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()), Times.Once);
            _accountLockoutServiceMock.Verify(s => s.RecordFailureAsync(user, AuthenticationProviderKey.Local, It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [Test]
    public async Task LoginAsyncWithAccountLockoutFailureRecordingFailureShouldFailClosed()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var logger = new Ashlar.Testing.RecordingLogger<AuthenticationPipeline>();
        UseAccountLockoutService(logger);
        _accountLockoutServiceMock.Setup(s => s.GetStatusAsync(user, AuthenticationProviderKey.Local, It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(AccountLockoutStatus.None(user.Id, user.TenantId, AuthenticationProviderKey.Local));
        _accountLockoutServiceMock.Setup(s => s.RecordFailureAsync(user, AuthenticationProviderKey.Local, It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("lockout unavailable"));
        _credentialService.ContextResolveResult = (user, credential, credential, false);
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Failed));

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.RateLimited));
            Assert.That(response.User, Is.Null);
            Assert.That(logger.Entries.Single().Level, Is.EqualTo(Microsoft.Extensions.Logging.LogLevel.Error));
            Assert.That(logger.Entries.Single().Message, Does.Contain("Operation=record_failure"));
            Assert.That(logger.Entries.Single().Message, Does.Contain("FailOpen=False"));
            Assert.That(logger.Entries.Single().Message, Does.Not.Contain("lockout unavailable"));
        }
    }

    [Test]
    public async Task LoginAsyncWithAccountLockoutFailureRecordingFailureShouldReturnGenericFailedWhenFailOpenConfigured()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var logger = new Ashlar.Testing.RecordingLogger<AuthenticationPipeline>();
        UseAccountLockoutService(
            securityEventSink: null,
            accountLockoutOptions: new AccountLockoutOptions { FailOpenOnBackendFailure = true },
            logger);
        _accountLockoutServiceMock.Setup(s => s.GetStatusAsync(user, AuthenticationProviderKey.Local, It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(AccountLockoutStatus.None(user.Id, user.TenantId, AuthenticationProviderKey.Local));
        _accountLockoutServiceMock.Setup(s => s.RecordFailureAsync(user, AuthenticationProviderKey.Local, It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("lockout unavailable"));
        _credentialService.ContextResolveResult = (user, credential, credential, false);
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Failed));

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
            Assert.That(response.User, Is.Null);
            Assert.That(logger.Entries.Single().Message, Does.Contain("Operation=record_failure"));
            Assert.That(logger.Entries.Single().Message, Does.Contain("FailOpen=True"));
            Assert.That(logger.Entries.Single().Message, Does.Not.Contain("lockout unavailable"));
        }
    }

    [Test]
    public async Task LoginAsyncWithAccountLockoutResetFailureShouldFailOpenAfterSuccessfulPassword()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded);
        UseAccountLockoutService();
        _accountLockoutServiceMock.Setup(s => s.GetStatusAsync(user, AuthenticationProviderKey.Local, It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(AccountLockoutStatus.None(user.Id, user.TenantId, AuthenticationProviderKey.Local));
        _accountLockoutServiceMock.Setup(s => s.ResetAsync(user, AuthenticationProviderKey.Local, It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("lockout unavailable"));
        _credentialService.ContextResolveResult = (user, credential, credential, false);
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(result);
        _credentialService.UsageUpdateResult = CredentialUsageUpdateResult.NotNeeded;

        var response = await _pipeline.LoginAsync(context, assertion);

        Assert.That(response.Succeeded, Is.True);
    }

    [Test]
    public async Task LoginAsyncWithSuccessfulAuthenticationShouldUpdateCredentialAndReturnClaims()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var claims = new Dictionary<string, string> { ["sub"] = user.Id.ToString() };
        var result = new AuthenticationResult(AuthenticationResultStatus.SucceededWithCredentialUpdate, claims);
        _credentialService.ContextResolveResult = (user, credential, credential, false);
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(result);
        _credentialService.UsageUpdateResult = CredentialUsageUpdateResult.Persisted;

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.True);
            Assert.That(response.User, Is.SameAs(user));
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.SuccessWithCredentialUpdate));
            Assert.That(response.Claims, Is.SameAs(result.Claims));
            Assert.That(response.CredentialUpdatePersisted, Is.True);
        }
    }

    [Test]
    public async Task LoginAsyncWithFailedBestEffortCredentialUpdateShouldStillSucceedWithoutPersistenceSignal()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var result = new AuthenticationResult(AuthenticationResultStatus.SucceededWithCredentialUpdate, CredentialUpdateRequirement: CredentialUpdateRequirement.BestEffort);
        _credentialService.ContextResolveResult = (user, credential, credential, false);
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(result);
        _credentialService.UsageUpdateResult = CredentialUsageUpdateResult.BestEffortFailed;

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.True);
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.SuccessWithCredentialUpdate));
            Assert.That(response.CredentialUpdatePersisted, Is.False);
        }
    }

    [Test]
    public async Task LoginAsyncWithSuccessfulAuthenticationAndNoCredentialShouldReturnSuccessWithoutUsageUpdate()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };
        var claims = new Dictionary<string, string> { ["sub"] = user.Id.ToString() };
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, claims);
        _credentialService.ContextResolveResult = (user, null, null, false);
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(result);

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.True);
            Assert.That(response.User, Is.SameAs(user));
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Success));
            Assert.That(response.Claims, Is.SameAs(result.Claims));
            Assert.That(response.CredentialUpdatePersisted, Is.False);
        }

        Assert.That(_credentialService.UsageUpdateCalls, Is.Zero);
    }

    [Test]
    public async Task LoginAsyncWithFailedAtomicCredentialConsumptionShouldReturnFailed()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, IsCredentialConsumed: true);
        _credentialService.ContextResolveResult = (user, credential, credential, false);
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(result);
        _credentialService.UsageUpdateResult = CredentialUsageUpdateResult.RequiredFailed;

        var response = await _pipeline.LoginAsync(context, assertion);

        Assert.That(response.Succeeded, Is.False);
    }

    [Test]
    public async Task LoginAsyncWithFailedAtomicCredentialConsumptionShouldResetAccountLockoutAfterSuccessfulPassword()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, IsCredentialConsumed: true);
        UseAccountLockoutService();
        _accountLockoutServiceMock.Setup(s => s.GetStatusAsync(user, AuthenticationProviderKey.Local, It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(AccountLockoutStatus.None(user.Id, user.TenantId, AuthenticationProviderKey.Local));
        _credentialService.ContextResolveResult = (user, credential, credential, false);
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(result);
        _credentialService.UsageUpdateResult = CredentialUsageUpdateResult.RequiredFailed;

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            _accountLockoutServiceMock.Verify(s => s.ResetAsync(user, AuthenticationProviderKey.Local, It.IsAny<AccountLockoutContext>(), It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [Test]
    public void LoginAsyncShouldPropagateCancellationFromCredentialLifecycle()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, IsCredentialConsumed: true);
        _credentialService.ContextResolveResult = (user, credential, credential, false);
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(result);
        _credentialService.UsageUpdateException = new OperationCanceledException();

        Assert.ThrowsAsync<OperationCanceledException>(() => _pipeline.LoginAsync(context, assertion));
    }

    [Test]
    public async Task LoginAsyncWithFailedRequiredCredentialUpdateShouldReturnFailedWithoutUserToAvoidOracle()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, CredentialUpdateRequirement: CredentialUpdateRequirement.Required);
        _credentialService.ContextResolveResult = (user, credential, credential, false);
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(result);
        _credentialService.UsageUpdateResult = CredentialUsageUpdateResult.RequiredFailed;

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
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, CredentialUpdateRequirement: CredentialUpdateRequirement.Required);
        _credentialService.ContextResolveResult = (user, credential, credential, false);
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(result);
        _credentialService.UsageUpdateException = new InvalidOperationException("DB error");

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
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, CredentialUpdateRequirement: CredentialUpdateRequirement.BestEffort);
        _credentialService.ContextResolveResult = (user, credential, credential, false);
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(result);
        _credentialService.UsageUpdateException = new InvalidOperationException("DB error");

        var response = await _pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.True);
            Assert.That(response.User, Is.SameAs(user));
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Success));
            Assert.That(response.CredentialUpdatePersisted, Is.False);
        }
    }

    [Test]
    public async Task LoginAsyncWithExceptionOnBestEffortCredentialUpdateAndInitializedProviderTypeShouldStillReturnSuccess()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        _providerMock.SetupGet(p => p.Key).Returns(AuthenticationProviderKey.Local);
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, CredentialUpdateRequirement: CredentialUpdateRequirement.BestEffort);
        _credentialService.ContextResolveResult = (user, credential, credential, false);
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(result);
        _credentialService.UsageUpdateException = new InvalidOperationException("DB error");

        var response = await _pipeline.LoginAsync(context, assertion);

        Assert.That(response.Succeeded, Is.True);
    }

    [Test]
    public async Task LoginAsyncWithNestedTransactionRollbackFromBestEffortCredentialUpdateShouldStillReturnSuccess()
    {
        var transactionProvider = new RollbackOnlyTransactionProvider();
        _pipeline = new AuthenticationPipeline(_providerRegistryMock.Object, _credentialService, AshlarDurableTransactionProvider.Create(transactionProvider), _primaryRateLimiterMock.Object, _factorRateLimiterMock.Object);
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(AuthenticationProviderKey.Local);
        var provider = ConfigureProviderResolution(assertion);
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };
        var credential = CreateCredential(user.Id);
        var result = new AuthenticationResult(AuthenticationResultStatus.Succeeded, CredentialUpdateRequirement: CredentialUpdateRequirement.BestEffort);
        _credentialService.ContextResolveResult = (user, credential, credential, false);
        _providerMock.Setup(p => p.AuthenticateAsync(assertion, credential, It.IsAny<CancellationToken>()))
            .ReturnsAsync(result);
        _credentialService.UsageUpdateHandler = async () =>
            {
                await using var transaction = await transactionProvider.BeginTransactionAsync();
                throw new InvalidOperationException("DB error");
            };

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

    private void UseAccountLockoutService(ISecurityEventSink? securityEventSink = null)
    {
        UseAccountLockoutService(securityEventSink, accountLockoutOptions: null);
    }

    private void UseAccountLockoutService(AccountLockoutOptions accountLockoutOptions)
    {
        UseAccountLockoutService(securityEventSink: null, accountLockoutOptions);
    }

    private void UseAccountLockoutService(Ashlar.Testing.RecordingLogger<AuthenticationPipeline> logger)
    {
        UseAccountLockoutService(securityEventSink: null, accountLockoutOptions: null, logger);
    }

    private void UseAccountLockoutService(ISecurityEventSink? securityEventSink, AccountLockoutOptions? accountLockoutOptions)
    {
        UseAccountLockoutService(securityEventSink, accountLockoutOptions, logger: null);
    }

    private void UseAccountLockoutService(
        ISecurityEventSink? securityEventSink,
        AccountLockoutOptions? accountLockoutOptions,
        Ashlar.Testing.RecordingLogger<AuthenticationPipeline>? logger)
    {
        _pipeline = new AuthenticationPipeline(
            _providerRegistryMock.Object,
            _credentialService,
            AshlarDurableTransactionProvider.Create(new NullTransactionProvider()),
            _primaryRateLimiterMock.Object,
            _factorRateLimiterMock.Object,
            new AuthenticationPipelineDependencies(
                SecurityEventSink: securityEventSink,
                Logger: logger,
                AccountLockoutService: new TestAccountLockoutService(_accountLockoutServiceMock.Object),
                AccountLockoutOptions: accountLockoutOptions));
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
    private sealed record TestUserVerifiedAssertion(AuthenticationProviderKey ProviderIdentity, bool UserVerified) : IUserVerifiedAuthenticationAssertion;

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
