using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Moq;

namespace Ashlar.Tests.Identity;

internal sealed class AuthenticationPipelineTests
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
        _pipeline = new AuthenticationPipeline(_providerRegistryMock.Object, _credentialServiceMock.Object, new NullTransactionProvider());
    }

    [Test]
    public void ConstructorShouldThrowOnNullProviderRegistry()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationPipeline(null!, _credentialServiceMock.Object, new NullTransactionProvider()));
    }

    [Test]
    public void ConstructorShouldThrowOnNullCredentialService()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationPipeline(_providerRegistryMock.Object, null!, new NullTransactionProvider()));
    }

    [Test]
    public void ConstructorShouldThrowOnNullTransactionProvider()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationPipeline(_providerRegistryMock.Object, _credentialServiceMock.Object, null!));
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
            Assert.That(response.Claims, Is.SameAs(claims));
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
            Assert.That(response.Claims, Is.SameAs(claims));
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
            Assert.That(response.Claims, Is.SameAs(claims));
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
        _pipeline = new AuthenticationPipeline(_providerRegistryMock.Object, _credentialServiceMock.Object, transactionProvider);
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
        var provider = _providerMock.Object;
        _providerRegistryMock.Setup(r => r.TryGetProvider(assertion, out provider))
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
            ProviderName = AuthenticationProviderKey.Local.Name,
            ProviderKey = userId.ToString(),
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active
        };
    }

    private sealed record TestAssertion(AuthenticationProviderKey ProviderIdentity) : IAuthenticationAssertion;

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
