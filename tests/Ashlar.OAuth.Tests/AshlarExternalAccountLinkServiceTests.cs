using System.Security.Claims;
using Ashlar.Auditing;
using Ashlar.Identity.Abstractions.Repositories;
using Ashlar.Identity.Abstractions.Tenancy;
using Ashlar.Identity.Models.AccountSecurity;
using Ashlar.Identity.Models.Credentials;
using Ashlar.Identity.Models.Tenants;
using Ashlar.Identity.Providers.External;
using Ashlar.OAuth.Providers.GitHub;
using Ashlar.OAuth.Providers.Google;
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
    public void ConstructorShouldRejectNullDependencies()
    {
        var credentialService = Mock.Of<ICredentialService>();
        var accountSecurityService = Mock.Of<IAccountSecurityService>();
        var repository = new StubRepository();
        var options = new TestOptionsMonitor(new AshlarOAuthOptions());

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => new AshlarExternalAccountLinkService(null!, accountSecurityService, repository, options));
            Assert.Throws<ArgumentNullException>(() => new AshlarExternalAccountLinkService(credentialService, null!, repository, options));
            Assert.Throws<ArgumentNullException>(() => new AshlarExternalAccountLinkService(credentialService, accountSecurityService, null!, options));
            Assert.Throws<ArgumentNullException>(() => new AshlarExternalAccountLinkService(credentialService, accountSecurityService, repository, null!));
        }
    }

    [Test]
    public void ResultConveniencePropertiesShouldReflectStatus()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.Linked).Linked, Is.True);
            Assert.That(new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.AlreadyLinked).Linked, Is.False);
            Assert.That(new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.AlreadyLinked).AlreadyLinked, Is.True);
            Assert.That(new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.Linked).AlreadyLinked, Is.False);
            Assert.That(new AshlarExternalAccountUnlinkResult(AshlarExternalAccountUnlinkStatus.Unlinked).Unlinked, Is.True);
            Assert.That(new AshlarExternalAccountUnlinkResult(AshlarExternalAccountUnlinkStatus.NotLinked).Unlinked, Is.False);
        }
    }

    [Test]
    public async Task LinkExternalAccountShouldMapPrincipalAndLinkCredentialForCurrentUser()
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

        var result = await service.LinkExternalAccountAsync(
            userId,
            "Google",
            AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("stable-sub", "first@example.com", tokenClaims: true)),
            credentialMetadata: "metadata");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Linked));
            Assert.That(result.Assertion?.ProviderKey, Is.EqualTo("stable-sub"));
            Assert.That(observedAssertion?.ProviderKey, Is.EqualTo("stable-sub"));
            Assert.That(observedAssertion?.Claims["email"], Is.EqualTo(["first@example.com"]));
            Assert.That(observedProvider?.Key, Is.EqualTo(new AuthenticationProviderKey(ProviderType.Oidc, "Google")));
            Assert.That(observedCredentialValue, Is.Null);
        }
    }

    [Test]
    public async Task LinkExternalAccountShouldMapGitHubPrincipalAndLinkOAuthCredential()
    {
        var userId = Guid.NewGuid();
        var credentialService = new Mock<ICredentialService>();
        ExternalIdentityAssertion? observedAssertion = null;
        IAuthenticationProvider? observedProvider = null;
        credentialService
            .Setup(s => s.LinkCredentialAsync(userId, It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .Callback<Guid, IAuthenticationAssertion, IAuthenticationProvider, string?, string?, CancellationToken>((_, assertion, provider, _, _, _) =>
            {
                observedAssertion = (ExternalIdentityAssertion)assertion;
                observedProvider = provider;
            })
            .ReturnsAsync(Result.Success());
        var service = CreateService(credentialService.Object, includeGitHub: true);

        var result = await service.LinkExternalAccountAsync(userId, "GitHub", AshlarOAuthTestTickets.CreateExternalTicket("GitHub", "GitHub", ProviderType.OAuth, CreateGitHubPrincipal("12345")));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Linked));
            Assert.That(result.Assertion?.ProviderIdentity, Is.EqualTo(new AuthenticationProviderKey(ProviderType.OAuth, "GitHub")));
            Assert.That(result.Assertion?.ProviderKey, Is.EqualTo("12345"));
            Assert.That(observedAssertion?.ProviderKey, Is.EqualTo("12345"));
            Assert.That(observedProvider?.Key, Is.EqualTo(new AuthenticationProviderKey(ProviderType.OAuth, "GitHub")));
        }
    }

    [Test]
    public async Task LinkExternalAccountShouldUseConfiguredOAuth2ProviderKeyClaim()
    {
        var userId = Guid.NewGuid();
        var credentialService = new Mock<ICredentialService>();
        ExternalIdentityAssertion? observedAssertion = null;
        credentialService
            .Setup(s => s.LinkCredentialAsync(userId, It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .Callback<Guid, IAuthenticationAssertion, IAuthenticationProvider, string?, string?, CancellationToken>((_, assertion, _, _, _, _) =>
                observedAssertion = (ExternalIdentityAssertion)assertion)
            .ReturnsAsync(Result.Success());
        var service = CreateService(
            credentialService.Object,
            configureOptions: options => options.AddOAuth2Provider("CustomOAuth", "uid", _ => { }));
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("uid", "stable-uid"), new Claim("id", "not-used")], "oauth"));

        var result = await service.LinkExternalAccountAsync(userId, "CustomOAuth", AshlarOAuthTestTickets.CreateExternalTicket("CustomOAuth", "CustomOAuth", ProviderType.OAuth, principal));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Linked));
            Assert.That(result.Assertion?.ProviderKey, Is.EqualTo("stable-uid"));
            Assert.That(observedAssertion?.ProviderIdentity, Is.EqualTo(new AuthenticationProviderKey(ProviderType.OAuth, "CustomOAuth")));
            Assert.That(observedAssertion?.ProviderKey, Is.EqualTo("stable-uid"));
        }
    }

    [Test]
    public async Task LinkExternalAccountShouldReturnUnsupportedProviderForMissingProvider()
    {
        var service = CreateService();

        var result = await service.LinkExternalAccountAsync(Guid.NewGuid(), "Microsoft", AshlarOAuthTestTickets.CreateExternalTicket("Microsoft", "Microsoft", ProviderType.Oidc, CreatePrincipal("sub")));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.UnsupportedProvider));
    }

    [TestCase("")]
    [TestCase(" ")]
    public async Task LinkExternalAccountShouldReturnUnsupportedProviderForBlankProviderName(string providerName)
    {
        var service = CreateService();

        var result = await service.LinkExternalAccountAsync(Guid.NewGuid(), providerName, AshlarOAuthTestTickets.CreateExternalTicket(providerName, providerName, ProviderType.Oidc, CreatePrincipal("sub")));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.UnsupportedProvider));
    }

    [Test]
    public async Task LinkExternalAccountShouldReturnInvalidPrincipalForMissingSubject()
    {
        var service = CreateService();

        var result = await service.LinkExternalAccountAsync(Guid.NewGuid(), "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, new ClaimsPrincipal(new ClaimsIdentity())));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.InvalidPrincipal));
    }

    [Test]
    public void LinkExternalAccountShouldRejectNullPrincipal()
    {
        var service = CreateService();

        Assert.ThrowsAsync<ArgumentNullException>(() => service.LinkExternalAccountAsync(Guid.NewGuid(), "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, null!)));
    }

    [Test]
    public void LinkExternalAccountShouldNotExposeRawClaimsPrincipalOverloadPublicly()
    {
        var methods = typeof(AshlarExternalAccountLinkService).GetMethods(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public);

        Assert.That(methods, Has.None.Matches<System.Reflection.MethodInfo>(method =>
            method.Name == nameof(AshlarExternalAccountLinkService.LinkExternalAccountAsync)
            && method.GetParameters().Any(parameter => parameter.ParameterType == typeof(ClaimsPrincipal))));
    }

    [Test]
    public async Task LinkExternalAccountShouldReturnInvalidPrincipalWhenConfiguredProviderNameIsInvalid()
    {
        var service = CreateServiceWithProvider(new AshlarOidcProviderOptions(" ", "Google", _ => { }));
        var ticket = AuthenticateResult.Success(new AuthenticationTicket(
            CreatePrincipal("sub"),
            CreateProperties(" ", "Google"),
            "Ashlar.OAuth.External"));

        var result = await service.LinkExternalAccountAsync(Guid.NewGuid(), "Google", ticket);

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.InvalidPrincipal));
    }

    [Test]
    public async Task LinkExternalAccountShouldReturnInvalidPrincipalForEmptyCurrentUser()
    {
        var service = CreateService();

        var result = await service.LinkExternalAccountAsync(Guid.Empty, "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("sub")));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.InvalidPrincipal));
    }

    [Test]
    public async Task LinkExternalAccountShouldReturnAlreadyLinkedForSameUser()
    {
        var credentialService = new Mock<ICredentialService>();
        credentialService
            .Setup(s => s.LinkCredentialAsync(It.IsAny<Guid>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure(AshlarFailureCodes.AlreadyLinkedToSelf));
        var service = CreateService(credentialService.Object);

        var result = await service.LinkExternalAccountAsync(Guid.NewGuid(), "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("sub")));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.AlreadyLinked));
    }

    [Test]
    public async Task LinkExternalAccountShouldReturnAlreadyLinkedToAnotherUser()
    {
        var credentialService = new Mock<ICredentialService>();
        credentialService
            .Setup(s => s.LinkCredentialAsync(It.IsAny<Guid>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure(AshlarFailureCodes.AlreadyLinkedToOther));
        var service = CreateService(credentialService.Object);

        var result = await service.LinkExternalAccountAsync(Guid.NewGuid(), "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("sub")));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.AlreadyLinkedToAnotherUser));
    }

    [Test]
    public async Task LinkExternalAccountShouldReturnInvalidPrincipalWhenCredentialServiceRejectsProviderKey()
    {
        var credentialService = new Mock<ICredentialService>();
        credentialService
            .Setup(s => s.LinkCredentialAsync(It.IsAny<Guid>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure(AshlarFailureCodes.InvalidProviderKey));
        var service = CreateService(credentialService.Object);

        var result = await service.LinkExternalAccountAsync(Guid.NewGuid(), "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("sub")));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.InvalidPrincipal));
    }

    [Test]
    public async Task LinkExternalAccountShouldReturnFailedForUnknownCredentialFailure()
    {
        var credentialService = new Mock<ICredentialService>();
        credentialService
            .Setup(s => s.LinkCredentialAsync(It.IsAny<Guid>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure(AshlarFailureCodes.UserNotFound));
        var service = CreateService(credentialService.Object);

        var result = await service.LinkExternalAccountAsync(Guid.NewGuid(), "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("sub")));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Failed));
    }

    [Test]
    public async Task LinkExternalAccountShouldReturnFailedForCredentialFailureWithoutDetails()
    {
        var credentialService = new Mock<ICredentialService>();
        credentialService
            .Setup(s => s.LinkCredentialAsync(It.IsAny<Guid>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Result(false));
        var service = CreateService(credentialService.Object);

        var result = await service.LinkExternalAccountAsync(Guid.NewGuid(), "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("sub")));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Failed));
    }

    [Test]
    public async Task LinkExternalAccountShouldUseSubjectWhenEmailChanges()
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

        await service.LinkExternalAccountAsync(userId, "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("same-sub", "old@example.com")));
        await service.LinkExternalAccountAsync(userId, "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("same-sub", "new@example.com")));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(assertions.Select(a => a.ProviderKey), Is.EqualTo(SameSubjectTwice));
            Assert.That(assertions.Select(a => a.Claims["email"].Single()), Is.EqualTo(ChangedEmails));
        }
    }

    [Test]
    public async Task LinkExternalAccountShouldNotStoreTokens()
    {
        var credentialService = new Mock<ICredentialService>();
        credentialService
            .Setup(s => s.LinkCredentialAsync(It.IsAny<Guid>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success());
        var service = CreateService(credentialService.Object);

        await service.LinkExternalAccountAsync(Guid.NewGuid(), "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("sub", tokenClaims: true)));

        credentialService.Verify(s => s.LinkCredentialAsync(
            It.IsAny<Guid>(),
            It.IsAny<IAuthenticationAssertion>(),
            It.IsAny<IAuthenticationProvider>(),
            null,
            It.IsAny<string?>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task LinkExternalAccountShouldPreserveTenantIsolation()
    {
        var tenantId = Guid.NewGuid();
        var otherTenantId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        var credentialService = new Mock<ICredentialService>();
        var service = CreateService(credentialService.Object, repository: new StubRepository(new TenantUser(userId, tenantId)));

        var result = await service.LinkExternalAccountAsync(userId, "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("sub")), new TenantContext(otherTenantId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Failed));
            credentialService.Verify(s => s.LinkCredentialAsync(It.IsAny<Guid>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task LinkExternalAccountShouldAllowMatchingTenant()
    {
        var tenantId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        var credentialService = new Mock<ICredentialService>();
        credentialService
            .Setup(s => s.LinkCredentialAsync(userId, It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success());
        var service = CreateService(credentialService.Object, repository: new StubRepository(new TenantUser(userId, tenantId)));

        var result = await service.LinkExternalAccountAsync(userId, "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("sub")), new TenantContext(tenantId));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Linked));
    }

    [Test]
    public async Task LinkExternalAccountShouldAllowGlobalTenantForTenantUserWithoutTenant()
    {
        var userId = Guid.NewGuid();
        var credentialService = new Mock<ICredentialService>();
        credentialService
            .Setup(s => s.LinkCredentialAsync(userId, It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success());
        var service = CreateService(credentialService.Object, repository: new StubRepository(new TenantUser(userId, null)));

        var result = await service.LinkExternalAccountAsync(userId, "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("sub")), TenantContext.Global);

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Linked));
    }

    [Test]
    public async Task LinkExternalAccountShouldFailTenantScopedTenantUserWithoutTenant()
    {
        var userId = Guid.NewGuid();
        var credentialService = new Mock<ICredentialService>();
        var service = CreateService(credentialService.Object, repository: new StubRepository(new TenantUser(userId, null)));

        var result = await service.LinkExternalAccountAsync(userId, "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("sub")), new TenantContext(Guid.NewGuid()));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Failed));
    }

    [Test]
    public async Task LinkExternalAccountShouldFailTenantScopedMissingUser()
    {
        var credentialService = new Mock<ICredentialService>();
        var service = CreateService(credentialService.Object, repository: new StubRepository());

        var result = await service.LinkExternalAccountAsync(Guid.NewGuid(), "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("sub")), new TenantContext(Guid.NewGuid()));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Failed));
    }

    [Test]
    public async Task LinkExternalAccountShouldAllowGlobalTenantForGlobalUser()
    {
        var userId = Guid.NewGuid();
        var credentialService = new Mock<ICredentialService>();
        credentialService
            .Setup(s => s.LinkCredentialAsync(userId, It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success());
        var service = CreateService(credentialService.Object, repository: new StubRepository(new BasicUser(userId)));

        var result = await service.LinkExternalAccountAsync(userId, "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("sub")), TenantContext.Global);

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Linked));
    }

    [Test]
    public async Task LinkExternalAccountShouldFailTenantScopedGlobalUser()
    {
        var userId = Guid.NewGuid();
        var credentialService = new Mock<ICredentialService>();
        var service = CreateService(credentialService.Object, repository: new StubRepository(new BasicUser(userId)));

        var result = await service.LinkExternalAccountAsync(userId, "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("sub")), new TenantContext(Guid.NewGuid()));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Failed));
    }

    [Test]
    public async Task CompleteExternalLinkShouldReturnUnsupportedProvider()
    {
        var service = CreateService();
        var httpContext = CreateHttpContext(new TestAuthenticationService(AuthenticateResult.NoResult()));

        var result = await service.CompleteExternalLinkAsync(httpContext, Guid.NewGuid(), "Microsoft");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.UnsupportedProvider));
            Assert.That(((TestAuthenticationService)httpContext.RequestServices.GetRequiredService<IAuthenticationService>()).SignOutCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task CompleteExternalLinkShouldClearUnsupportedProviderTicketWhenRequestIsCanceled()
    {
        var service = CreateService();
        var authService = new TestAuthenticationService(AuthenticateResult.NoResult());
        var httpContext = CreateHttpContext(authService);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        var result = await service.CompleteExternalLinkAsync(httpContext, Guid.NewGuid(), "Microsoft", cancellationToken: cts.Token);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.UnsupportedProvider));
            Assert.That(authService.SignOutCount, Is.EqualTo(1));
        }
    }

    [Test]
    public void CompleteExternalLinkShouldRejectNullHttpContext()
    {
        var service = CreateService();

        Assert.ThrowsAsync<ArgumentNullException>(() => service.CompleteExternalLinkAsync(null!, Guid.NewGuid(), "Google"));
    }

    [Test]
    public async Task CompleteExternalLinkShouldClearExternalCookieBeforeLinking()
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

        var result = await service.CompleteExternalLinkAsync(CreateHttpContext(authService), Guid.NewGuid(), "Google");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Linked));
            Assert.That(authService.SignOutCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task CompleteExternalLinkShouldReturnProviderMismatchForOidcTicketWithoutProviderType()
    {
        var authService = new TestAuthenticationService(AuthenticateResult.Success(new AuthenticationTicket(
            CreatePrincipal("sub"),
            CreateProperties("Google", "Google", includeProviderType: false),
            "Ashlar.OAuth.External")));
        var credentialService = new Mock<ICredentialService>();
        var service = CreateService(credentialService.Object);

        var result = await service.CompleteExternalLinkAsync(CreateHttpContext(authService), Guid.NewGuid(), "Google");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.ProviderMismatch));
            Assert.That(authService.SignOutCount, Is.EqualTo(1));
        }

        credentialService.Verify(
            s => s.LinkCredentialAsync(It.IsAny<Guid>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Test]
    public async Task CompleteExternalLinkShouldReturnProviderMismatchForOAuthTicketWithoutProviderType()
    {
        var authService = new TestAuthenticationService(AuthenticateResult.Success(new AuthenticationTicket(
            CreateGitHubPrincipal("12345"),
            CreateProperties("GitHub", "GitHub", ProviderType.OAuth, includeProviderType: false),
            "Ashlar.OAuth.External")));
        var service = CreateService(includeGitHub: true);

        var result = await service.CompleteExternalLinkAsync(CreateHttpContext(authService), Guid.NewGuid(), "GitHub");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.ProviderMismatch));
            Assert.That(authService.SignOutCount, Is.EqualTo(1));
        }
    }

    [Test]
    public void CompleteExternalLinkShouldClearExternalTicketWhenAuthenticateThrows()
    {
        var service = CreateService();
        var authService = new TestAuthenticationService(AuthenticateResult.NoResult(), new InvalidOperationException("auth failed"));

        Assert.ThrowsAsync<InvalidOperationException>(() => service.CompleteExternalLinkAsync(CreateHttpContext(authService), Guid.NewGuid(), "Google"));
        Assert.That(authService.SignOutCount, Is.EqualTo(1));
    }

    [Test]
    public async Task LinkExternalAccountFromAuthenticateResultShouldLinkMatchingTicket()
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

        var result = await service.LinkExternalAccountAsync(Guid.NewGuid(), "Google", ticket);

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Linked));
    }

    [Test]
    public void LinkExternalAccountFromAuthenticateResultShouldRejectNullResult()
    {
        var service = CreateService();

        Assert.ThrowsAsync<ArgumentNullException>(() => service.LinkExternalAccountAsync(Guid.NewGuid(), "Google", (AuthenticateResult)null!));
    }

    [Test]
    public async Task LinkExternalAccountFromAuthenticateResultShouldReturnUnsupportedProvider()
    {
        var service = CreateService();
        var ticket = AuthenticateResult.Success(new AuthenticationTicket(
            CreatePrincipal("sub"),
            CreateProperties("Google", "Google"),
            "Ashlar.OAuth.External"));

        var result = await service.LinkExternalAccountAsync(Guid.NewGuid(), "Microsoft", ticket);

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.UnsupportedProvider));
    }

    [Test]
    public async Task LinkExternalAccountFromAuthenticateResultShouldReturnAuthenticationFailedForFailedTicket()
    {
        var service = CreateService();

        var result = await service.LinkExternalAccountAsync(Guid.NewGuid(), "Google", AuthenticateResult.Fail("failed"));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.AuthenticationFailed));
    }

    [Test]
    public async Task LinkExternalAccountFromAuthenticateResultShouldReturnInvalidPrincipalForEmptyPrincipal()
    {
        var service = CreateService();
        var ticket = AuthenticateResult.Success(new AuthenticationTicket(
            new ClaimsPrincipal(),
            CreateProperties("Google", "Google"),
            "Ashlar.OAuth.External"));

        var result = await service.LinkExternalAccountAsync(Guid.NewGuid(), "Google", ticket);

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.InvalidPrincipal));
    }

    [Test]
    public async Task LinkExternalAccountFromAuthenticateResultShouldReturnProviderMismatch()
    {
        var service = CreateService();
        var ticket = AuthenticateResult.Success(new AuthenticationTicket(
            CreatePrincipal("sub"),
            new AuthenticationProperties(),
            "Ashlar.OAuth.External"));

        var result = await service.LinkExternalAccountAsync(Guid.NewGuid(), "Google", ticket);

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.ProviderMismatch));
    }

    [Test]
    public async Task CompleteExternalLinkShouldReturnProviderMismatch()
    {
        var authService = new TestAuthenticationService(AuthenticateResult.Success(new AuthenticationTicket(
            CreatePrincipal("sub"),
            CreateProperties("Microsoft", "Microsoft"),
            "Ashlar.OAuth.External")));
        var service = CreateService();

        var result = await service.CompleteExternalLinkAsync(CreateHttpContext(authService), Guid.NewGuid(), "Google");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.ProviderMismatch));
            Assert.That(authService.SignOutCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task CompleteExternalLinkShouldReturnAuthenticationFailedWhenTicketMissing()
    {
        var service = CreateService();
        var authService = new TestAuthenticationService(AuthenticateResult.NoResult());

        var result = await service.CompleteExternalLinkAsync(CreateHttpContext(authService), Guid.NewGuid(), "Google");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.AuthenticationFailed));
            Assert.That(authService.SignOutCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task UnlinkExternalAccountShouldRevokeConfiguredProvider()
    {
        var userId = Guid.NewGuid();
        var tenant = new TenantContext(Guid.NewGuid());
        AccountSecurityOperationRequest? observedRequest = null;
        var accountSecurity = CreateAccountSecurityService(
            CreatePosture(userId, CreateCredentialItem(ProviderType.Oidc, "Google"), CreateCredentialItem(ProviderType.Local, "Local")),
            revokeResult: Result.Success(new AccountSecurityOperationResult(userId, CredentialsRevoked: 1)));
        accountSecurity
            .Setup(s => s.RevokeCredentialsAsync(userId, new AuthenticationProviderKey(ProviderType.Oidc, "Google"), It.IsAny<AccountSecurityOperationRequest>(), It.IsAny<CancellationToken>()))
            .Callback<Guid, AuthenticationProviderKey, AccountSecurityOperationRequest, CancellationToken>((_, _, request, _) => observedRequest = request)
            .ReturnsAsync(Result.Success(new AccountSecurityOperationResult(userId, CredentialsRevoked: 1)));
        var request = CreateRequest(tenant);
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new TenantUser(userId, tenant.TenantId)));

        var result = await service.UnlinkExternalAccountAsync(userId, "Google", request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Unlinked));
            Assert.That(result.AccountSecurityOperation?.Value?.CredentialsRevoked, Is.EqualTo(1));
            Assert.That(observedRequest, Is.SameAs(request));
        }
    }

    [Test]
    public async Task UnlinkExternalAccountShouldAllowExplicitAllTenantScope()
    {
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        AccountSecurityPostureRequest? observedPostureRequest = null;
        AccountSecurityOperationRequest? observedRevokeRequest = null;
        var accountSecurity = CreateAccountSecurityService(
            CreatePosture(userId, CreateCredentialItem(ProviderType.Oidc, "Google"), CreateCredentialItem(ProviderType.Local, "Local")),
            revokeResult: Result.Success(new AccountSecurityOperationResult(userId, CredentialsRevoked: 1)));
        accountSecurity
            .Setup(s => s.GetUserSecurityPostureAsync(userId, It.IsAny<AccountSecurityPostureRequest>(), It.IsAny<CancellationToken>()))
            .Callback<Guid, AccountSecurityPostureRequest, CancellationToken>((_, request, _) => observedPostureRequest = request)
            .ReturnsAsync(Result.Success(CreatePosture(userId, CreateCredentialItem(ProviderType.Oidc, "Google"), CreateCredentialItem(ProviderType.Local, "Local"))));
        accountSecurity
            .Setup(s => s.RevokeCredentialsAsync(userId, new AuthenticationProviderKey(ProviderType.Oidc, "Google"), It.IsAny<AccountSecurityOperationRequest>(), It.IsAny<CancellationToken>()))
            .Callback<Guid, AuthenticationProviderKey, AccountSecurityOperationRequest, CancellationToken>((_, _, request, _) => observedRevokeRequest = request)
            .ReturnsAsync(Result.Success(new AccountSecurityOperationResult(userId, CredentialsRevoked: 1)));
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new TenantUser(userId, tenantId)));

        var result = await service.UnlinkExternalAccountAsync(userId, "Google", CreateRequest(includeAllTenants: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Unlinked));
            Assert.That(observedPostureRequest?.Tenant?.TenantId, Is.EqualTo(tenantId));
            Assert.That(observedRevokeRequest?.IncludeAllTenants, Is.True);
            Assert.That(observedRevokeRequest?.Tenant, Is.Null);
        }
    }

    [Test]
    public async Task UnlinkExternalAccountShouldUseGlobalPostureScopeForAllTenantGlobalUser()
    {
        var userId = Guid.NewGuid();
        AccountSecurityPostureRequest? observedPostureRequest = null;
        var accountSecurity = CreateAccountSecurityService(
            CreatePosture(userId, CreateCredentialItem(ProviderType.Oidc, "Google"), CreateCredentialItem(ProviderType.Local, "Local")),
            revokeResult: Result.Success(new AccountSecurityOperationResult(userId, CredentialsRevoked: 1)));
        accountSecurity
            .Setup(s => s.GetUserSecurityPostureAsync(userId, It.IsAny<AccountSecurityPostureRequest>(), It.IsAny<CancellationToken>()))
            .Callback<Guid, AccountSecurityPostureRequest, CancellationToken>((_, request, _) => observedPostureRequest = request)
            .ReturnsAsync(Result.Success(CreatePosture(userId, CreateCredentialItem(ProviderType.Oidc, "Google"), CreateCredentialItem(ProviderType.Local, "Local"))));
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(userId)));

        var result = await service.UnlinkExternalAccountAsync(userId, "Google", CreateRequest(includeAllTenants: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Unlinked));
            Assert.That(observedPostureRequest?.Tenant, Is.EqualTo(TenantContext.Global));
        }
    }

    [TestCase("")]
    [TestCase(" ")]
    [TestCase("Microsoft")]
    public async Task UnlinkExternalAccountShouldReturnUnsupportedProviderForBlankOrMissingProvider(string providerName)
    {
        var accountSecurity = CreateAccountSecurityService();
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(Guid.NewGuid())));

        var result = await service.UnlinkExternalAccountAsync(Guid.NewGuid(), providerName, CreateRequest());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.UnsupportedProvider));
            accountSecurity.Verify(s => s.RevokeCredentialsAsync(It.IsAny<Guid>(), It.IsAny<AuthenticationProviderKey>(), It.IsAny<AccountSecurityOperationRequest>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task UnlinkExternalAccountShouldReturnUserNotFoundForMissingUser()
    {
        var userId = Guid.NewGuid();
        var service = CreateService(accountSecurityService: CreateAccountSecurityService().Object, repository: new StubRepository());

        var result = await service.UnlinkExternalAccountAsync(userId, "Google", CreateRequest());

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.UserNotFound));
    }

    [Test]
    public async Task UnlinkExternalAccountShouldReturnUserNotFoundForEmptyCurrentUser()
    {
        var service = CreateService();

        var result = await service.UnlinkExternalAccountAsync(Guid.Empty, "Google", CreateRequest());

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.UserNotFound));
    }

    [Test]
    public async Task UnlinkExternalAccountShouldReturnTenantMismatch()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService();
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new TenantUser(userId, Guid.NewGuid())));

        var result = await service.UnlinkExternalAccountAsync(userId, "Google", CreateRequest(new TenantContext(Guid.NewGuid())));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.TenantMismatch));
            accountSecurity.Verify(s => s.GetUserSecurityPostureAsync(It.IsAny<Guid>(), It.IsAny<AccountSecurityPostureRequest>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task UnlinkExternalAccountShouldReturnNotLinkedWhenConfiguredProviderIsAbsent()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(CreatePosture(userId, CreateCredentialItem(ProviderType.Oidc, "Microsoft"), CreateCredentialItem(ProviderType.Local, "Local")));
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(userId)));

        var result = await service.UnlinkExternalAccountAsync(userId, "Google", CreateRequest());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.NotLinked));
            accountSecurity.Verify(s => s.RevokeCredentialsAsync(It.IsAny<Guid>(), It.IsAny<AuthenticationProviderKey>(), It.IsAny<AccountSecurityOperationRequest>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task UnlinkExternalAccountShouldOnlyRevokeConfiguredOidcProvider()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(
            CreatePosture(
                userId,
                CreateCredentialItem(ProviderType.Oidc, "Google"),
                CreateCredentialItem(ProviderType.Oidc, "Microsoft"),
                CreateCredentialItem(ProviderType.OAuth, "Google"),
                CreateCredentialItem(ProviderType.Local, "Local"),
                CreateCredentialItem(ProviderType.Passkey, "Passkey", isAdditionalVerification: true),
                CreateCredentialItem(ProviderType.Mfa, "totp", isPrimary: false, isAdditionalVerification: true)),
            revokeResult: Result.Success(new AccountSecurityOperationResult(userId, CredentialsRevoked: 1)));
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(userId)));

        var result = await service.UnlinkExternalAccountAsync(userId, "Google", CreateRequest());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Unlinked));
            accountSecurity.Verify(s => s.RevokeCredentialsAsync(userId, new AuthenticationProviderKey(ProviderType.Oidc, "Google"), It.IsAny<AccountSecurityOperationRequest>(), It.IsAny<CancellationToken>()), Times.Once);
            accountSecurity.Verify(s => s.RevokeCredentialsAsync(userId, It.Is<AuthenticationProviderKey>(p => p.Type != ProviderType.Oidc || p.Name != "Google"), It.IsAny<AccountSecurityOperationRequest>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task UnlinkExternalAccountShouldPreventRemovingLastUsablePrimaryCredential()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(CreatePosture(userId, CreateCredentialItem(ProviderType.Oidc, "Google")));
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(userId)));

        var result = await service.UnlinkExternalAccountAsync(userId, "Google", CreateRequest());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.WouldRemoveLastSignInMethod));
            accountSecurity.Verify(s => s.RevokeCredentialsAsync(It.IsAny<Guid>(), It.IsAny<AuthenticationProviderKey>(), It.IsAny<AccountSecurityOperationRequest>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task UnlinkExternalAccountShouldNotRequireFreshMfaInService()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(
            CreatePosture(userId, CreateCredentialItem(ProviderType.Oidc, "Google"), CreateCredentialItem(ProviderType.Local, "Local")),
            revokeResult: Result.Success(new AccountSecurityOperationResult(userId, CredentialsRevoked: 1)));
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(userId)));

        var result = await service.UnlinkExternalAccountAsync(userId, "Google", CreateRequest());

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Unlinked));
    }

    [Test]
    public async Task UnlinkExternalAccountShouldReturnNotLinkedWhenRevocationFindsNoCredentials()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(
            CreatePosture(userId, CreateCredentialItem(ProviderType.Oidc, "Google"), CreateCredentialItem(ProviderType.Local, "Local")),
            revokeResult: Result.Success(new AccountSecurityOperationResult(userId)));
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(userId)));

        var result = await service.UnlinkExternalAccountAsync(userId, "Google", CreateRequest());

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.NotLinked));
    }

    [Test]
    public async Task UnlinkExternalAccountShouldReturnNotLinkedWhenRevocationSucceedsWithoutValue()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(
            CreatePosture(userId, CreateCredentialItem(ProviderType.Oidc, "Google"), CreateCredentialItem(ProviderType.Local, "Local")),
            revokeResult: new Result<AccountSecurityOperationResult>(true));
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(userId)));

        var result = await service.UnlinkExternalAccountAsync(userId, "Google", CreateRequest());

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.NotLinked));
    }

    [Test]
    public async Task UnlinkExternalAccountShouldMapAccountSecurityFailures()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(
            CreatePosture(userId, CreateCredentialItem(ProviderType.Oidc, "Google"), CreateCredentialItem(ProviderType.Local, "Local")),
            revokeResult: Result.Failure<AccountSecurityOperationResult>(AshlarFailureCodes.UserNotFound));
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(userId)));

        var result = await service.UnlinkExternalAccountAsync(userId, "Google", CreateRequest());

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.UserNotFound));
    }

    [Test]
    public async Task UnlinkExternalAccountShouldReturnFailedWhenPostureLookupFails()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService();
        accountSecurity
            .Setup(s => s.GetUserSecurityPostureAsync(userId, It.IsAny<AccountSecurityPostureRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure<AccountSecurityPosture>(AshlarFailureCodes.ValidationError));
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(userId)));

        var result = await service.UnlinkExternalAccountAsync(userId, "Google", CreateRequest());

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Failed));
    }

    [Test]
    public async Task UnlinkExternalAccountShouldReturnFailedWhenPostureLookupFailsWithoutDetails()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService();
        accountSecurity
            .Setup(s => s.GetUserSecurityPostureAsync(userId, It.IsAny<AccountSecurityPostureRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Result<AccountSecurityPosture>(false));
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(userId)));

        var result = await service.UnlinkExternalAccountAsync(userId, "Google", CreateRequest());

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Failed));
    }

    [Test]
    public async Task UnlinkExternalAccountShouldReturnUserNotFoundWhenPostureLookupCannotFindUser()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService();
        accountSecurity
            .Setup(s => s.GetUserSecurityPostureAsync(userId, It.IsAny<AccountSecurityPostureRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure<AccountSecurityPosture>(AshlarFailureCodes.UserNotFound));
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(userId)));

        var result = await service.UnlinkExternalAccountAsync(userId, "Google", CreateRequest());

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.UserNotFound));
    }

    [Test]
    public async Task UnlinkExternalAccountShouldReturnFailedForUnknownRevocationFailure()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(
            CreatePosture(userId, CreateCredentialItem(ProviderType.Oidc, "Google"), CreateCredentialItem(ProviderType.Local, "Local")),
            revokeResult: Result.Failure<AccountSecurityOperationResult>(AshlarFailureCodes.ValidationError));
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(userId)));

        var result = await service.UnlinkExternalAccountAsync(userId, "Google", CreateRequest());

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Failed));
    }

    [Test]
    public async Task UnlinkExternalAccountShouldReturnFailedForRevocationFailureWithoutDetails()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(
            CreatePosture(userId, CreateCredentialItem(ProviderType.Oidc, "Google"), CreateCredentialItem(ProviderType.Local, "Local")),
            revokeResult: new Result<AccountSecurityOperationResult>(false));
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(userId)));

        var result = await service.UnlinkExternalAccountAsync(userId, "Google", CreateRequest());

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Failed));
    }

    [Test]
    public async Task UnlinkExternalAccountShouldAllowGlobalTenantForGlobalUser()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(
            CreatePosture(userId, CreateCredentialItem(ProviderType.Oidc, "Google"), CreateCredentialItem(ProviderType.Local, "Local")),
            revokeResult: Result.Success(new AccountSecurityOperationResult(userId, CredentialsRevoked: 1)));
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(userId)));

        var result = await service.UnlinkExternalAccountAsync(userId, "Google", CreateRequest(TenantContext.Global));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Unlinked));
    }

    [Test]
    public async Task UnlinkExternalAccountShouldRejectGlobalTenantForTenantScopedUser()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService();
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new TenantUser(userId, Guid.NewGuid())));

        var result = await service.UnlinkExternalAccountAsync(userId, "Google", CreateRequest(TenantContext.Global));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.TenantMismatch));
    }

    [Test]
    public async Task UnlinkExternalAccountShouldAllowGlobalTenantForTenantUserWithoutTenant()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(
            CreatePosture(userId, CreateCredentialItem(ProviderType.Oidc, "Google"), CreateCredentialItem(ProviderType.Local, "Local")),
            revokeResult: Result.Success(new AccountSecurityOperationResult(userId, CredentialsRevoked: 1)));
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new TenantUser(userId, null)));

        var result = await service.UnlinkExternalAccountAsync(userId, "Google", CreateRequest(TenantContext.Global));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Unlinked));
    }

    [Test]
    public async Task UnlinkExternalAccountShouldRejectScopedTenantForTenantUserWithoutTenant()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService();
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new TenantUser(userId, null)));

        var result = await service.UnlinkExternalAccountAsync(userId, "Google", CreateRequest(new TenantContext(Guid.NewGuid())));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.TenantMismatch));
    }

    [Test]
    public async Task UnlinkExternalAccountShouldRejectScopedTenantForGlobalUser()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService();
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(userId)));

        var result = await service.UnlinkExternalAccountAsync(userId, "Google", CreateRequest(new TenantContext(Guid.NewGuid())));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.TenantMismatch));
    }

    [Test]
    public async Task UnlinkExternalAccountShouldRevokeGitHubOAuthCredentials()
    {
        var userId = Guid.NewGuid();
        AuthenticationProviderKey? observedProvider = null;
        var accountSecurity = CreateAccountSecurityService(
            CreatePosture(userId, CreateCredentialItem(ProviderType.OAuth, "GitHub"), CreateCredentialItem(ProviderType.Local, "Local")),
            revokeResult: Result.Success(new AccountSecurityOperationResult(userId, CredentialsRevoked: 1)));
        accountSecurity
            .Setup(s => s.RevokeCredentialsAsync(userId, It.IsAny<AuthenticationProviderKey>(), It.IsAny<AccountSecurityOperationRequest>(), It.IsAny<CancellationToken>()))
            .Callback<Guid, AuthenticationProviderKey, AccountSecurityOperationRequest, CancellationToken>((_, provider, _, _) => observedProvider = provider)
            .ReturnsAsync(Result.Success(new AccountSecurityOperationResult(userId, CredentialsRevoked: 1)));
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(userId)), includeGitHub: true);

        var result = await service.UnlinkExternalAccountAsync(userId, "GitHub", CreateRequest());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Unlinked));
            Assert.That(observedProvider, Is.EqualTo(new AuthenticationProviderKey(ProviderType.OAuth, "GitHub")));
        }
    }

    [Test]
    public void UnlinkExternalAccountShouldRejectNullRequestBeforeOtherValidation()
    {
        var accountSecurity = CreateAccountSecurityService();
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(Guid.NewGuid())));

        Assert.ThrowsAsync<ArgumentNullException>(() => service.UnlinkExternalAccountAsync(Guid.Empty, "Microsoft", null!));
        accountSecurity.Verify(s => s.GetUserSecurityPostureAsync(It.IsAny<Guid>(), It.IsAny<AccountSecurityPostureRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    private static AshlarExternalAccountLinkService CreateService(
        ICredentialService? credentialService = null,
        IAccountSecurityService? accountSecurityService = null,
        IUserRepository? repository = null,
        bool includeGitHub = false,
        Action<AshlarOAuthOptions>? configureOptions = null)
    {
        var options = new AshlarOAuthOptions();
        options.AddGoogle();
        if (includeGitHub)
        {
            options.AddGitHub();
        }

        configureOptions?.Invoke(options);

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
            accountSecurityService ?? CreateAccountSecurityService().Object,
            repository ?? new StubRepository(),
            new TestOptionsMonitor(options));
    }

    private static AshlarExternalAccountLinkService CreateServiceWithProvider(AshlarOidcProviderOptions provider)
    {
        var options = new AshlarOAuthOptions();
        var providers = (Dictionary<string, AshlarOidcProviderOptions>)typeof(AshlarOAuthOptions)
            .GetField("_oidcProviders", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
            .GetValue(options)!;
        providers["Google"] = provider;

        return new AshlarExternalAccountLinkService(
            Mock.Of<ICredentialService>(),
            CreateAccountSecurityService().Object,
            new StubRepository(),
            new TestOptionsMonitor(options));
    }

    private static Mock<IAccountSecurityService> CreateAccountSecurityService(
        AccountSecurityPosture? posture = null,
        Result<AccountSecurityOperationResult>? revokeResult = null)
    {
        var accountSecurity = new Mock<IAccountSecurityService>();
        accountSecurity
            .Setup(s => s.GetUserSecurityPostureAsync(It.IsAny<Guid>(), It.IsAny<AccountSecurityPostureRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Guid userId, AccountSecurityPostureRequest request, CancellationToken _) =>
                Result.Success(posture ?? CreatePosture(userId, CreateCredentialItem(ProviderType.Local, "Local"))));
        accountSecurity
            .Setup(s => s.RevokeCredentialsAsync(It.IsAny<Guid>(), It.IsAny<AuthenticationProviderKey>(), It.IsAny<AccountSecurityOperationRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(revokeResult ?? Result.Success(new AccountSecurityOperationResult(Guid.NewGuid(), CredentialsRevoked: 1)));
        return accountSecurity;
    }

    private static AccountSecurityOperationRequest CreateRequest(TenantContext? tenant = null, bool includeAllTenants = false)
    {
        return new AccountSecurityOperationRequest(new AuditContext(Guid.NewGuid(), "127.0.0.1", "NUnit", "corr"), includeAllTenants ? null : tenant ?? TenantContext.Global, "unlink", includeAllTenants);
    }

    private static AccountSecurityPosture CreatePosture(Guid userId, params CredentialPostureItem[] credentials)
    {
        var primary = credentials.Where(c => c.IsPrimaryCredential && c.IsAvailable).ToArray();
        return new AccountSecurityPosture(
            userId,
            UserAccountState.Active,
            true,
            primary.Length > 0,
            primary,
            credentials.Where(c => c.IsAdditionalVerificationFactor).Select(c => new AdditionalVerificationFactorPosture(c.FactorType ?? c.Provider.Name, c.DisplayName, true, c.IsAvailable, [c.Provider])).ToArray(),
            new AccountSecurityPolicyPosture(false, [], [], false, true, [], [], false),
            credentials,
            0,
            null);
    }

    private static CredentialPostureItem CreateCredentialItem(
        ProviderType type,
        string providerName,
        bool isPrimary = true,
        bool isAdditionalVerification = false,
        bool isAvailable = true)
    {
        var provider = new AuthenticationProviderKey(type, providerName);
        return new CredentialPostureItem(
            Guid.NewGuid(),
            provider,
            providerName,
            isPrimary ? CredentialPosturePurpose.Primary : CredentialPosturePurpose.AdditionalVerification,
            isAdditionalVerification ? providerName : null,
            isPrimary,
            isAdditionalVerification,
            isAvailable,
            true,
            false,
            DateTimeOffset.UtcNow,
            null,
            null,
            isAvailable ? CredentialStatus.Active : CredentialStatus.Revoked);
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

    private static ClaimsPrincipal CreateGitHubPrincipal(string id)
    {
        return new ClaimsPrincipal(new ClaimsIdentity([new Claim("id", id), new Claim("login", "octocat"), new Claim("email", "octo@example.com")], "oauth"));
    }

    private static DefaultHttpContext CreateHttpContext(IAuthenticationService authenticationService)
    {
        var services = new ServiceCollection();
        services.AddSingleton(authenticationService);
        return new DefaultHttpContext { RequestServices = services.BuildServiceProvider() };
    }

    private static AuthenticationProperties CreateProperties(string providerName, string schemeName, ProviderType? providerType = null, bool includeProviderType = true)
    {
        var properties = new AuthenticationProperties();
        properties.Items[AshlarOAuthAuthenticationProperties.ProviderName] = providerName;
        properties.Items[AshlarOAuthAuthenticationProperties.SchemeName] = schemeName;
        if (includeProviderType)
        {
            properties.Items[AshlarOAuthAuthenticationProperties.ProviderType] = (providerType ?? ProviderType.Oidc).Value;
        }

        return properties;
    }

    private sealed class TestOptionsMonitor(AshlarOAuthOptions options) : IOptionsMonitor<AshlarOAuthOptions>
    {
        public AshlarOAuthOptions CurrentValue => options;
        public AshlarOAuthOptions Get(string? name) => options;
        public IDisposable? OnChange(Action<AshlarOAuthOptions, string?> listener) => null;
    }

    private sealed class TestAuthenticationService(AuthenticateResult result, Exception? authenticateException = null) : IAuthenticationService
    {
        public int SignOutCount { get; private set; }
        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme)
        {
            if (authenticateException != null)
            {
                throw authenticateException;
            }

            return Task.FromResult(result);
        }
        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
        {
            SignOutCount++;
            return Task.CompletedTask;
        }
    }

    private sealed class StubRepository(IUser? user = null) : IUserRepository
    {
        public Task<IUser?> GetUserByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default) => Task.FromResult<IUser?>(null);
        public Task<IUser?> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken = default) => Task.FromResult(user?.Id == userId ? user : null);
        public Task<IUser?> GetUserByProviderKeyAsync(ProviderType type, string providerName, string providerKey, CancellationToken cancellationToken = default) => Task.FromResult<IUser?>(null);
        public Task CreateUserAsync(IUser user, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task UpdateUserAsync(IUser user, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed record TenantUser(Guid Id, Guid? TenantId) : ITenantUser
    {
        public string DisplayEmail => "tenant@example.com";
        public string? Name => null;
        public UserAccountState AccountState => UserAccountState.Active;
        public DateTimeOffset? EmailVerifiedAt => null;
    }

    private sealed record BasicUser(Guid Id) : IUser
    {
        public string DisplayEmail => "global@example.com";
        public string? Name => null;
        public UserAccountState AccountState => UserAccountState.Active;
        public DateTimeOffset? EmailVerifiedAt => null;
    }
}
