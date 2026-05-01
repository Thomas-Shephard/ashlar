using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Moq;

namespace Ashlar.Tests.Identity;

public class AuthenticationPipelineTests
{
    private Mock<IAuthenticationProviderRegistry> _providerRegistryMock;
    private Mock<ICredentialService> _credentialServiceMock;
    private Mock<IAuthenticationProvider> _providerMock;
    private AuthenticationPipeline _pipeline;

    [SetUp]
    public void SetUp()
    {
        _providerRegistryMock = new Mock<IAuthenticationProviderRegistry>();
        _credentialServiceMock = new Mock<ICredentialService>();
        _providerMock = new Mock<IAuthenticationProvider>();
        _pipeline = new AuthenticationPipeline(_providerRegistryMock.Object, _credentialServiceMock.Object);
    }

    [Test]
    public void ConstructorShouldThrowOnNullProviderRegistry()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationPipeline(null!, _credentialServiceMock.Object));
    }

    [Test]
    public void ConstructorShouldThrowOnNullCredentialService()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationPipeline(_providerRegistryMock.Object, null!));
    }

    [Test]
    public async Task LoginAsyncWithUnsupportedProviderShouldReturnFailed()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(ProviderType.Oidc);

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
    public async Task LoginAsyncWithInvalidCredentialsShouldReturnFailed()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(ProviderType.Local);
        var provider = ConfigureProviderResolution(assertion, context);
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
        var assertion = new TestAssertion(ProviderType.Local);
        var provider = ConfigureProviderResolution(assertion, context);
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
    public async Task LoginAsyncWithSuccessfulAuthenticationShouldUpdateCredentialAndReturnClaims()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(ProviderType.Local);
        var provider = ConfigureProviderResolution(assertion, context);
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
            Assert.That(response.Claims, Is.SameAs(claims));
        }
    }

    [Test]
    public async Task LoginAsyncWithFailedAtomicCredentialConsumptionShouldReturnFailed()
    {
        var context = new AuthenticationContext("test@example.com");
        var assertion = new TestAssertion(ProviderType.Local);
        var provider = ConfigureProviderResolution(assertion, context);
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
        var assertion = new TestAssertion(ProviderType.Local);
        var provider = ConfigureProviderResolution(assertion, context);
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

    private IAuthenticationProvider ConfigureProviderResolution(IAuthenticationAssertion assertion, AuthenticationContext context)
    {
        var provider = _providerMock.Object;
        _providerRegistryMock.Setup(r => r.TryGetProvider(assertion, context, out provider))
            .Returns(true);
        return provider;
    }

    private static UserCredential CreateCredential(Guid userId)
    {
        return new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Local,
            ProviderName = ProviderType.Local.Value,
            ProviderKey = userId.ToString(),
            Version = "v1"
        };
    }

    private sealed record TestAssertion(ProviderType ProviderType) : IAuthenticationAssertion;
}
