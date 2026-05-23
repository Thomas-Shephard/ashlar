using System.Security.Claims;
using Ashlar.Identity.Abstractions.Repositories;
using Ashlar.Identity.Abstractions.Tenancy;
using Ashlar.Identity.Models.Credentials;
using Ashlar.Identity.Models.Tenants;
using Ashlar.Identity.Providers.External;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;

namespace Ashlar.OAuth.Tests;

internal sealed class AshlarExternalAccountLinkServiceTests
{
    private static readonly string[] SameSubjectTwice = ["same-sub", "same-sub"];
    private static readonly string[] ChangedEmails = ["old@example.com", "new@example.com"];

    [Test]
    public async Task LinkOidcAccountShouldMapPrincipalAndLinkCredentialForCurrentUser()
    {
        var userId = Guid.NewGuid();
        var credentialService = new Mock<ICredentialService>();
        ExternalIdentityAssertion? observedAssertion = null;
        IAuthenticationProvider? observedProvider = null;
        string? observedCredentialValue = "not-null";
        credentialService
            .Setup(s => s.LinkCredentialAsync(userId, It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, "metadata", It.IsAny<CancellationToken>()))
            .Callback<Guid, IAuthenticationAssertion, IAuthenticationProvider, string?, string?, CancellationToken>((_, assertion, provider, credentialValue, _, _) =>
            {
                observedAssertion = (ExternalIdentityAssertion)assertion;
                observedProvider = provider;
                observedCredentialValue = credentialValue;
            })
            .ReturnsAsync(Result.Success());
        var service = CreateService(credentialService.Object);

        var result = await service.LinkOidcAccountAsync(
            userId,
            "Google",
            CreatePrincipal("stable-sub", "first@example.com", tokenClaims: true),
            credentialMetadata: "metadata");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Linked));
            Assert.That(result.Assertion?.ProviderKey, Is.EqualTo("stable-sub"));
            Assert.That(observedAssertion?.ProviderKey, Is.EqualTo("stable-sub"));
            Assert.That(observedAssertion?.Claims["email"], Is.EqualTo("first@example.com"));
            Assert.That(observedProvider?.Key, Is.EqualTo(new AuthenticationProviderKey(ProviderType.Oidc, "Google")));
            Assert.That(observedCredentialValue, Is.Null);
        }
    }

    [Test]
    public async Task LinkOidcAccountShouldReturnUnsupportedProviderForMissingProvider()
    {
        var service = CreateService();

        var result = await service.LinkOidcAccountAsync(Guid.NewGuid(), "Microsoft", CreatePrincipal("sub"));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.UnsupportedProvider));
    }

    [TestCase("")]
    [TestCase(" ")]
    public async Task LinkOidcAccountShouldReturnUnsupportedProviderForBlankProviderName(string providerName)
    {
        var service = CreateService();

        var result = await service.LinkOidcAccountAsync(Guid.NewGuid(), providerName, CreatePrincipal("sub"));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.UnsupportedProvider));
    }

    [Test]
    public async Task LinkOidcAccountShouldReturnInvalidPrincipalForMissingSubject()
    {
        var service = CreateService();

        var result = await service.LinkOidcAccountAsync(Guid.NewGuid(), "Google", new ClaimsPrincipal(new ClaimsIdentity()));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.InvalidPrincipal));
    }

    [Test]
    public async Task LinkOidcAccountShouldReturnInvalidPrincipalForEmptyCurrentUser()
    {
        var service = CreateService();

        var result = await service.LinkOidcAccountAsync(Guid.Empty, "Google", CreatePrincipal("sub"));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.InvalidPrincipal));
    }

    [Test]
    public async Task LinkOidcAccountShouldReturnAlreadyLinkedForSameUser()
    {
        var credentialService = new Mock<ICredentialService>();
        credentialService
            .Setup(s => s.LinkCredentialAsync(It.IsAny<Guid>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure(AshlarFailureCodes.AlreadyLinkedToSelf));
        var service = CreateService(credentialService.Object);

        var result = await service.LinkOidcAccountAsync(Guid.NewGuid(), "Google", CreatePrincipal("sub"));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.AlreadyLinked));
    }

    [Test]
    public async Task LinkOidcAccountShouldReturnAlreadyLinkedToAnotherUser()
    {
        var credentialService = new Mock<ICredentialService>();
        credentialService
            .Setup(s => s.LinkCredentialAsync(It.IsAny<Guid>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure(AshlarFailureCodes.AlreadyLinkedToOther));
        var service = CreateService(credentialService.Object);

        var result = await service.LinkOidcAccountAsync(Guid.NewGuid(), "Google", CreatePrincipal("sub"));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.AlreadyLinkedToAnotherUser));
    }

    [Test]
    public async Task LinkOidcAccountShouldUseSubjectWhenEmailChanges()
    {
        var userId = Guid.NewGuid();
        var assertions = new List<ExternalIdentityAssertion>();
        var credentialService = new Mock<ICredentialService>();
        credentialService
            .Setup(s => s.LinkCredentialAsync(userId, It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .Callback<Guid, IAuthenticationAssertion, IAuthenticationProvider, string?, string?, CancellationToken>((_, assertion, _, _, _, _) =>
                assertions.Add((ExternalIdentityAssertion)assertion))
            .ReturnsAsync(Result.Failure(AshlarFailureCodes.AlreadyLinkedToSelf));
        var service = CreateService(credentialService.Object);

        await service.LinkOidcAccountAsync(userId, "Google", CreatePrincipal("same-sub", "old@example.com"));
        await service.LinkOidcAccountAsync(userId, "Google", CreatePrincipal("same-sub", "new@example.com"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(assertions.Select(a => a.ProviderKey), Is.EqualTo(SameSubjectTwice));
            Assert.That(assertions.Select(a => a.Claims["email"]), Is.EqualTo(ChangedEmails));
        }
    }

    [Test]
    public async Task LinkOidcAccountShouldNotStoreTokens()
    {
        var credentialService = new Mock<ICredentialService>();
        credentialService
            .Setup(s => s.LinkCredentialAsync(It.IsAny<Guid>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success());
        var service = CreateService(credentialService.Object);

        await service.LinkOidcAccountAsync(Guid.NewGuid(), "Google", CreatePrincipal("sub", tokenClaims: true));

        credentialService.Verify(s => s.LinkCredentialAsync(
            It.IsAny<Guid>(),
            It.IsAny<IAuthenticationAssertion>(),
            It.IsAny<IAuthenticationProvider>(),
            null,
            It.IsAny<string?>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task LinkOidcAccountShouldPreserveTenantIsolation()
    {
        var tenantId = Guid.NewGuid();
        var otherTenantId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        var credentialService = new Mock<ICredentialService>();
        var service = CreateService(credentialService.Object, new StubRepository(new TenantUser(userId, tenantId)));

        var result = await service.LinkOidcAccountAsync(userId, "Google", CreatePrincipal("sub"), new TenantContext(otherTenantId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Failed));
            credentialService.Verify(s => s.LinkCredentialAsync(It.IsAny<Guid>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task CompleteOidcLinkShouldClearExternalCookieBeforeLinking()
    {
        var authService = new TestAuthenticationService(AuthenticateResult.Success(new AuthenticationTicket(
            CreatePrincipal("sub"),
            CreateProperties("Google", "Google"),
            "Ashlar.OAuth.External")));
        var credentialService = new Mock<ICredentialService>();
        credentialService
            .Setup(s => s.LinkCredentialAsync(It.IsAny<Guid>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success());
        var service = CreateService(credentialService.Object);

        var result = await service.CompleteOidcLinkAsync(CreateHttpContext(authService), Guid.NewGuid(), "Google");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Linked));
            Assert.That(authService.SignOutCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task LinkOidcAccountFromAuthenticateResultShouldLinkMatchingTicket()
    {
        var credentialService = new Mock<ICredentialService>();
        credentialService
            .Setup(s => s.LinkCredentialAsync(It.IsAny<Guid>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success());
        var service = CreateService(credentialService.Object);
        var ticket = AuthenticateResult.Success(new AuthenticationTicket(
            CreatePrincipal("sub"),
            CreateProperties("Google", "Google"),
            "Ashlar.OAuth.External"));

        var result = await service.LinkOidcAccountAsync(Guid.NewGuid(), "Google", ticket);

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Linked));
    }

    [Test]
    public async Task CompleteOidcLinkShouldReturnProviderMismatch()
    {
        var authService = new TestAuthenticationService(AuthenticateResult.Success(new AuthenticationTicket(
            CreatePrincipal("sub"),
            CreateProperties("Microsoft", "Microsoft"),
            "Ashlar.OAuth.External")));
        var service = CreateService();

        var result = await service.CompleteOidcLinkAsync(CreateHttpContext(authService), Guid.NewGuid(), "Google");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.ProviderMismatch));
            Assert.That(authService.SignOutCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task CompleteOidcLinkShouldReturnAuthenticationFailedWhenTicketMissing()
    {
        var service = CreateService();

        var result = await service.CompleteOidcLinkAsync(CreateHttpContext(new TestAuthenticationService(AuthenticateResult.NoResult())), Guid.NewGuid(), "Google");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.AuthenticationFailed));
    }

    private static AshlarExternalAccountLinkService CreateService(ICredentialService? credentialService = null, IIdentityRepository? repository = null)
    {
        var options = new AshlarOAuthOptions();
        options.AddOidcProvider("Google", _ => { });

        credentialService ??= Mock.Of<ICredentialService>(s =>
            s.LinkCredentialAsync(
                It.IsAny<Guid>(),
                It.IsAny<IAuthenticationAssertion>(),
                It.IsAny<IAuthenticationProvider>(),
                It.IsAny<string?>(),
                It.IsAny<string?>(),
                It.IsAny<CancellationToken>()) == Task.FromResult(Result.Success()));

        return new AshlarExternalAccountLinkService(
            credentialService,
            repository ?? new StubRepository(),
            new TestOptionsMonitor(options));
    }

    private static ClaimsPrincipal CreatePrincipal(string subject, string email = "person@example.com", bool tokenClaims = false)
    {
        var claims = new List<Claim> { new("sub", subject), new("email", email) };
        if (tokenClaims)
        {
            claims.Add(new Claim("access_token", "access-secret"));
            claims.Add(new Claim("refresh_token", "refresh-secret"));
            claims.Add(new Claim("id_token", "id-secret"));
        }

        return new ClaimsPrincipal(new ClaimsIdentity(claims, "oidc"));
    }

    private static DefaultHttpContext CreateHttpContext(IAuthenticationService authenticationService)
    {
        var services = new ServiceCollection();
        services.AddSingleton(authenticationService);
        return new DefaultHttpContext { RequestServices = services.BuildServiceProvider() };
    }

    private static AuthenticationProperties CreateProperties(string providerName, string schemeName)
    {
        var properties = new AuthenticationProperties();
        properties.Items[AshlarOAuthAuthenticationProperties.ProviderName] = providerName;
        properties.Items[AshlarOAuthAuthenticationProperties.SchemeName] = schemeName;
        return properties;
    }

    private sealed class TestOptionsMonitor(AshlarOAuthOptions options) : IOptionsMonitor<AshlarOAuthOptions>
    {
        public AshlarOAuthOptions CurrentValue => options;
        public AshlarOAuthOptions Get(string? name) => options;
        public IDisposable? OnChange(Action<AshlarOAuthOptions, string?> listener) => null;
    }

    private sealed class TestAuthenticationService(AuthenticateResult result) : IAuthenticationService
    {
        public int SignOutCount { get; private set; }
        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme) => Task.FromResult(result);
        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
        {
            SignOutCount++;
            return Task.CompletedTask;
        }
    }

    private sealed class StubRepository(IUser? user = null) : IIdentityRepository
    {
        public Task<IUser?> GetUserByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default) => Task.FromResult<IUser?>(null);
        public Task<IUser?> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken = default) => Task.FromResult(user?.Id == userId ? user : null);
        public Task<UserCredential?> GetCredentialForUserAsync(Guid userId, ProviderType type, string providerName, string? providerKey = null, CancellationToken cancellationToken = default) => Task.FromResult<UserCredential?>(null);
        public Task<IUser?> GetUserByProviderKeyAsync(ProviderType type, string providerName, string providerKey, CancellationToken cancellationToken = default) => Task.FromResult<IUser?>(null);
        public Task<IReadOnlyList<UserCredential>> ListCredentialsForUserAsync(Guid userId, bool activeOnly = true, CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<UserCredential>>(Array.Empty<UserCredential>());
        public Task CreateUserAsync(IUser user, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task UpdateUserAsync(IUser user, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task CreateCredentialAsync(UserCredential credential, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task CreateOrReplaceCredentialAsync(UserCredential credential, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> UpdateCredentialAsync(UserCredential credential, string expectedVersion, CancellationToken cancellationToken = default) => Task.FromResult(true);
        public Task<bool> ConsumeCredentialAsync(Guid credentialId, string expectedVersion, CancellationToken cancellationToken = default) => Task.FromResult(true);
        public Task<int> RevokeCredentialsAsync(Guid userId, ProviderType type, string providerName, CancellationToken cancellationToken = default) => Task.FromResult(0);
    }

    private sealed record TenantUser(Guid Id, Guid? TenantId) : ITenantUser
    {
        public string Email => "tenant@example.com";
        public string? Name => null;
        public bool IsActive => true;
        public DateTimeOffset? EmailVerifiedAt => null;
    }
}
