using Ashlar.Auditing;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Identity.Features.Credentials;

internal sealed class ExternalAccountCredentialLinkerTests
{
    private readonly DateTimeOffset _now = new(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);

    [Test]
    public void ConstructorShouldRejectNullDependencies()
    {
        var users = Mock.Of<IUserRepository>();
        var linking = new RecordingCredentialLinkingInfrastructure();
        var clock = new FakeTimeProvider(_now);

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new ExternalAccountCredentialLinker(null!, linking, clock));
            Assert.Throws<ArgumentNullException>(() => _ = new ExternalAccountCredentialLinker(users, null!, clock));
            Assert.DoesNotThrow(() => _ = new ExternalAccountCredentialLinker(users, linking, null!));
        }
    }

    [Test]
    public void LinkExternalAccountCredentialAsyncShouldRejectNullInputs()
    {
        var service = CreateService(out _, out _);
        var request = CreateRequest();

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentNullException>(() => service.LinkExternalAccountCredentialAsync(null!));
            Assert.ThrowsAsync<ArgumentNullException>(() => service.LinkExternalAccountCredentialAsync(request with { Assertion = null! }));
            Assert.ThrowsAsync<ArgumentNullException>(() => service.LinkExternalAccountCredentialAsync(request with { Provider = null! }));
            Assert.ThrowsAsync<ArgumentNullException>(() => service.LinkExternalAccountCredentialAsync(request with { Tenant = null! }));
        }
    }

    [Test]
    public async Task LinkExternalAccountCredentialAsyncShouldRejectExpiredFreshProofBeforeRepositoryLookup()
    {
        var service = CreateService(out var users, out var linking);
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var expiredProof = new FreshMfaVerificationProof(
            userId,
            tenantId,
            sessionId,
            _now.AddMinutes(-10),
            _now.AddMinutes(-1),
            ExternalAccountCredentialLinker.LinkPurpose);
        var result = await service.LinkExternalAccountCredentialAsync(CreateRequest(userId, tenantId, sessionId, freshProof: expiredProof));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            users.Verify(r => r.GetUserByIdAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()), Times.Never);
            Assert.That(linking.Calls, Is.Zero);
        }
    }

    [Test]
    public async Task LinkExternalAccountCredentialAsyncShouldRejectNonExternalProvidersBeforeRepositoryLookup()
    {
        var service = CreateService(out var users, out var linking);
        var provider = new Mock<IAuthenticationProvider>();
        provider.SetupGet(p => p.Key)
            .Returns(AuthenticationProviderKey.Local);

        var result = await service.LinkExternalAccountCredentialAsync(CreateRequest(provider: provider.Object));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            users.Verify(r => r.GetUserByIdAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()), Times.Never);
            Assert.That(linking.Calls, Is.Zero);
        }
    }

    [Test]
    public async Task LinkExternalAccountCredentialAsyncShouldFailWhenUserIsMissing()
    {
        var service = CreateService(out _, out var linking);
        var result = await service.LinkExternalAccountCredentialAsync(CreateRequest());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(linking.Calls, Is.Zero);
        }
    }

    [Test]
    public async Task LinkExternalAccountCredentialAsyncShouldEnforceTenantOwnership()
    {
        var tenantId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        var users = new Mock<IUserRepository>();
        users.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AshlarUser { Id = userId, DisplayEmail = "user@example.com", TenantId = Guid.NewGuid() });
        var linking = new RecordingCredentialLinkingInfrastructure();
        var service = new ExternalAccountCredentialLinker(users.Object, linking, new FakeTimeProvider(_now));

        var result = await service.LinkExternalAccountCredentialAsync(CreateRequest(userId: userId, tenantId: tenantId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            Assert.That(linking.Calls, Is.Zero);
        }
    }

    [TestCase("oidc")]
    [TestCase("oauth")]
    public async Task LinkExternalAccountCredentialAsyncShouldForwardBoundRequestToCredentialInfrastructure(string providerType)
    {
        var tenantId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var assertion = new Mock<IAuthenticationAssertion>().Object;
        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key)
            .Returns(new AuthenticationProviderKey(providerType, "Google"));
        var provider = providerMock.Object;
        var audit = new AuditContext(ActorUserId: userId, CorrelationId: "corr-1");
        var users = new Mock<IUserRepository>();
        users.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AshlarUser { Id = userId, DisplayEmail = "user@example.com", TenantId = tenantId });
        var linking = new RecordingCredentialLinkingInfrastructure();
        var service = new ExternalAccountCredentialLinker(users.Object, linking, new FakeTimeProvider(_now));

        var result = await service.LinkExternalAccountCredentialAsync(CreateRequest(
            userId,
            tenantId,
            sessionId,
            assertion,
            provider,
            audit,
            "metadata"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(linking.Calls, Is.EqualTo(1));
            Assert.That(linking.UserId, Is.EqualTo(userId));
            Assert.That(linking.Assertion, Is.SameAs(assertion));
            Assert.That(linking.Provider, Is.SameAs(provider));
            Assert.That(linking.CredentialValue, Is.Null);
            Assert.That(linking.CredentialMetadata, Is.EqualTo("metadata"));
            Assert.That(linking.Audit, Is.SameAs(audit));
            Assert.That(linking.TenantId, Is.EqualTo(tenantId));
        }
    }

    private ExternalAccountCredentialLinker CreateService(out Mock<IUserRepository> users, out RecordingCredentialLinkingInfrastructure linking)
    {
        users = new Mock<IUserRepository>();
        linking = new RecordingCredentialLinkingInfrastructure();
        return new ExternalAccountCredentialLinker(users.Object, linking, new FakeTimeProvider(_now));
    }

    private ExternalAccountCredentialLinkRequest CreateRequest(
        Guid? userId = null,
        Guid? tenantId = null,
        Guid? sessionId = null,
        IAuthenticationAssertion? assertion = null,
        IAuthenticationProvider? provider = null,
        AuditContext? audit = null,
        string? metadata = null,
        FreshMfaVerificationProof? freshProof = null)
    {
        var resolvedUserId = userId ?? Guid.NewGuid();
        var resolvedTenantId = tenantId ?? Guid.NewGuid();
        var resolvedSessionId = sessionId ?? Guid.NewGuid();
        var proof = freshProof ?? new FreshMfaVerificationProof(
            resolvedUserId,
            resolvedTenantId,
            resolvedSessionId,
            _now,
            _now.AddMinutes(5),
            ExternalAccountCredentialLinker.LinkPurpose);

        var providerMock = new Mock<IAuthenticationProvider>();
        providerMock.SetupGet(p => p.Key)
            .Returns(new AuthenticationProviderKey(ProviderType.Oidc, "Google"));

        return new ExternalAccountCredentialLinkRequest(
            resolvedUserId,
            assertion ?? Mock.Of<IAuthenticationAssertion>(),
            provider ?? providerMock.Object,
            proof,
            resolvedSessionId,
            new TenantContext(resolvedTenantId),
            audit,
            metadata);
    }

    private sealed class RecordingCredentialLinkingInfrastructure : ICredentialLinkingInfrastructure
    {
        public int Calls { get; private set; }
        public Guid UserId { get; private set; }
        public IAuthenticationAssertion? Assertion { get; private set; }
        public IAuthenticationProvider? Provider { get; private set; }
        public string? CredentialValue { get; private set; }
        public string? CredentialMetadata { get; private set; }
        public AuditContext? Audit { get; private set; }
        public Guid? TenantId { get; private set; }

        public Task<Result> LinkCredentialAsync(
            CredentialLinkInfrastructureRequest request,
            CancellationToken cancellationToken)
        {
            Calls++;
            UserId = request.UserId;
            Assertion = request.Assertion;
            Provider = request.Provider;
            CredentialValue = request.CredentialValue;
            CredentialMetadata = request.CredentialMetadata;
            Audit = request.Audit;
            TenantId = request.TenantId;
            return Task.FromResult(Result.Success());
        }
    }
}
