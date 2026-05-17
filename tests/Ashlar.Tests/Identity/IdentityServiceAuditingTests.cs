using Ashlar.Auditing;
using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.Providers.External;
using Moq;

namespace Ashlar.Tests.Identity;

internal sealed class IdentityServiceAuditingTests
{
    [Test]
    public async Task ManualConstructionWithAuditSinkShouldEmitEvents()
    {
        var sinkMock = new Mock<ISecurityEventSink>();
        var repositoryMock = new Mock<IIdentityRepository>();
        var providers = new List<IAuthenticationProvider>
        {
            new OidcAuthenticationProvider("Google")
        };
        var credentialServiceMock = new Mock<ICredentialService>();

        var service = new IdentityService(
            repositoryMock.Object,
            providers,
            credentialServiceMock.Object,
            new NullTransactionProvider(),
            sinkMock.Object);

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
}
