using Ashlar.Auditing;
using Ashlar.Identity.Providers.External;
using Moq;

namespace Ashlar.Tests.Identity.Features.Services;

internal sealed class IdentityServiceAuditingTests
{
    [Test]
    public async Task ManualConstructionWithAuditSinkShouldEmitEvents()
    {
        var sinkMock = new Mock<ISecurityEventSink>();
        var repositoryMock = new Mock<IUserRepository>();
        var providers = new List<IAuthenticationProvider>
        {
            new OidcAuthenticationProvider("Google")
        };
        var credentialServiceMock = new Mock<ICredentialService>();
        var transactionProvider = new NullTransactionProvider();
        var providerRegistry = new AuthenticationProviderRegistry(providers);
        var pipeline = new AuthenticationPipeline(
            providerRegistry,
            credentialServiceMock.Object,
            transactionProvider,
            AllowPrimaryAuthenticationRateLimiter.Instance,
            AllowAuthenticationFactorRateLimiter.Instance,
            new AuthenticationPipelineDependencies(SecurityEventSink: sinkMock.Object));

        var service = new IdentityService(
            repositoryMock.Object,
            providerRegistry,
            credentialServiceMock.Object,
            pipeline,
            transactionProvider,
            new IdentityServiceDependencies(SecurityEventSink: sinkMock.Object));

        var tenantId = Guid.NewGuid();
        var actorUserId = Guid.NewGuid();
        var context = new AuthenticationContext("test@example.com", TenantId: tenantId, UserId: actorUserId);
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub", new Dictionary<string, string>());

        repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((IUser?)null);

        credentialServiceMock.Setup(s => s.ResolveAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(((IUser?)null, (UserCredential?)null, (UserCredential?)null, false));

        await service.LoginAsync(context, assertion);

        sinkMock.Verify(s => s.RecordAsync(
            It.Is<AshlarSecurityEvent>(e =>
                e.EventType == AshlarSecurityEventTypes.AuthenticationFailed &&
                e.TenantId == tenantId &&
                e.ActorUserId == actorUserId),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public void CreateUserAsyncShouldNotCommitWhenRequiredAuditFails()
    {
        var repositoryMock = new Mock<IUserRepository>();
        var transactionProvider = new RecordingTransactionProvider();
        var service = new IdentityService(
            repositoryMock.Object,
            Mock.Of<IAuthenticationProviderRegistry>(),
            Mock.Of<ICredentialService>(),
            Mock.Of<IAuthenticationPipeline>(),
            transactionProvider,
            new IdentityServiceDependencies(SecurityEventSink: new ThrowingSecurityEventSink()));

        Assert.ThrowsAsync<InvalidOperationException>(() => service.CreateUserAsync(new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" }));

        Assert.That(transactionProvider.Transaction.Committed, Is.False);
    }

    private sealed class ThrowingSecurityEventSink : ISecurityEventSink
    {
        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            throw new InvalidOperationException("audit failed");
        }
    }

    private sealed class RecordingTransactionProvider : IAshlarTransactionProvider
    {
        public RecordingTransaction Transaction { get; } = new();

        public Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IAshlarTransaction>(Transaction);
        }
    }

    private sealed class RecordingTransaction : IAshlarTransaction
    {
        public bool Committed { get; private set; }

        public Task CommitAsync(CancellationToken cancellationToken = default)
        {
            Committed = true;
            return Task.CompletedTask;
        }

        public Task RollbackAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

        public void OnCommitted(Func<CancellationToken, Task> action)
        {
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
