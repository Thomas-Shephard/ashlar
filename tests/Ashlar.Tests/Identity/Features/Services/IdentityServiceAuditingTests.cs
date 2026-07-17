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
        var credentialService = new TestCredentialService();
        var transactionProvider = AshlarDurableTransactionProvider.Create(new NullTransactionProvider());
        var providerRegistry = new AuthenticationProviderRegistry(providers);
        var pipeline = new AuthenticationPipeline(
            providerRegistry,
            credentialService,
            transactionProvider,
            AllowPrimaryAuthenticationRateLimiter.Instance,
            AllowAuthenticationFactorRateLimiter.Instance,
            new AuthenticationPipelineDependencies(SecurityEventSink: sinkMock.Object));

        var service = new IdentityService(
            repositoryMock.Object,
            providerRegistry,
            pipeline);

        var tenantId = Guid.NewGuid();
        var actorUserId = Guid.NewGuid();
        var context = new AuthenticationContext("test@example.com", TenantId: tenantId, UserId: actorUserId);
        var assertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "sub", new Dictionary<string, string>());

        repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((IUser?)null);

        credentialService.ContextResolveResult = ((IUser?)null, (UserCredential?)null, (UserCredential?)null, false);

        await service.LoginAsync(context, assertion);

        sinkMock.Verify(s => s.RecordAsync(
            It.Is<AshlarSecurityEvent>(e =>
                e.EventType == AshlarSecurityEventTypes.AuthenticationFailed &&
                e.TenantId == tenantId &&
                e.ActorUserId == actorUserId),
            It.IsAny<CancellationToken>()), Times.Once);
    }
}
