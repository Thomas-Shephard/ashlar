using System.Security.Claims;
using Ashlar.Auditing;
using Ashlar.Identity.Abstractions.Repositories;
using Ashlar.Identity.Abstractions.Tenancy;
using Ashlar.Identity.Models.AccountSecurity;
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
    public void LinkOidcAccountShouldRejectNullPrincipal()
    {
        var service = CreateService();

        Assert.ThrowsAsync<ArgumentNullException>(() => service.LinkOidcAccountAsync(Guid.NewGuid(), "Google", (ClaimsPrincipal)null!));
    }

    [Test]
    public async Task LinkOidcAccountShouldReturnInvalidPrincipalWhenConfiguredProviderNameIsInvalid()
    {
        var service = CreateServiceWithProvider(new AshlarOidcProviderOptions(" ", "Google", _ => { }));

        var result = await service.LinkOidcAccountAsync(Guid.NewGuid(), "Google", CreatePrincipal("sub"));

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
    public async Task LinkOidcAccountShouldReturnInvalidPrincipalWhenCredentialServiceRejectsProviderKey()
    {
        var credentialService = new Mock<ICredentialService>();
        credentialService
            .Setup(s => s.LinkCredentialAsync(It.IsAny<Guid>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure(AshlarFailureCodes.InvalidProviderKey));
        var service = CreateService(credentialService.Object);

        var result = await service.LinkOidcAccountAsync(Guid.NewGuid(), "Google", CreatePrincipal("sub"));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.InvalidPrincipal));
    }

    [Test]
    public async Task LinkOidcAccountShouldReturnFailedForUnknownCredentialFailure()
    {
        var credentialService = new Mock<ICredentialService>();
        credentialService
            .Setup(s => s.LinkCredentialAsync(It.IsAny<Guid>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure(AshlarFailureCodes.UserNotFound));
        var service = CreateService(credentialService.Object);

        var result = await service.LinkOidcAccountAsync(Guid.NewGuid(), "Google", CreatePrincipal("sub"));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Failed));
    }

    [Test]
    public async Task LinkOidcAccountShouldReturnFailedForCredentialFailureWithoutDetails()
    {
        var credentialService = new Mock<ICredentialService>();
        credentialService
            .Setup(s => s.LinkCredentialAsync(It.IsAny<Guid>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Result(false));
        var service = CreateService(credentialService.Object);

        var result = await service.LinkOidcAccountAsync(Guid.NewGuid(), "Google", CreatePrincipal("sub"));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Failed));
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
        var service = CreateService(credentialService.Object, repository: new StubRepository(new TenantUser(userId, tenantId)));

        var result = await service.LinkOidcAccountAsync(userId, "Google", CreatePrincipal("sub"), new TenantContext(otherTenantId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Failed));
            credentialService.Verify(s => s.LinkCredentialAsync(It.IsAny<Guid>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task LinkOidcAccountShouldAllowMatchingTenant()
    {
        var tenantId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        var credentialService = new Mock<ICredentialService>();
        credentialService
            .Setup(s => s.LinkCredentialAsync(userId, It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success());
        var service = CreateService(credentialService.Object, repository: new StubRepository(new TenantUser(userId, tenantId)));

        var result = await service.LinkOidcAccountAsync(userId, "Google", CreatePrincipal("sub"), new TenantContext(tenantId));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Linked));
    }

    [Test]
    public async Task LinkOidcAccountShouldAllowGlobalTenantForTenantUserWithoutTenant()
    {
        var userId = Guid.NewGuid();
        var credentialService = new Mock<ICredentialService>();
        credentialService
            .Setup(s => s.LinkCredentialAsync(userId, It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success());
        var service = CreateService(credentialService.Object, repository: new StubRepository(new TenantUser(userId, null)));

        var result = await service.LinkOidcAccountAsync(userId, "Google", CreatePrincipal("sub"), TenantContext.Global);

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Linked));
    }

    [Test]
    public async Task LinkOidcAccountShouldFailTenantScopedTenantUserWithoutTenant()
    {
        var userId = Guid.NewGuid();
        var credentialService = new Mock<ICredentialService>();
        var service = CreateService(credentialService.Object, repository: new StubRepository(new TenantUser(userId, null)));

        var result = await service.LinkOidcAccountAsync(userId, "Google", CreatePrincipal("sub"), new TenantContext(Guid.NewGuid()));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Failed));
    }

    [Test]
    public async Task LinkOidcAccountShouldFailTenantScopedMissingUser()
    {
        var credentialService = new Mock<ICredentialService>();
        var service = CreateService(credentialService.Object, repository: new StubRepository());

        var result = await service.LinkOidcAccountAsync(Guid.NewGuid(), "Google", CreatePrincipal("sub"), new TenantContext(Guid.NewGuid()));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Failed));
    }

    [Test]
    public async Task LinkOidcAccountShouldAllowGlobalTenantForGlobalUser()
    {
        var userId = Guid.NewGuid();
        var credentialService = new Mock<ICredentialService>();
        credentialService
            .Setup(s => s.LinkCredentialAsync(userId, It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success());
        var service = CreateService(credentialService.Object, repository: new StubRepository(new BasicUser(userId)));

        var result = await service.LinkOidcAccountAsync(userId, "Google", CreatePrincipal("sub"), TenantContext.Global);

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Linked));
    }

    [Test]
    public async Task LinkOidcAccountShouldFailTenantScopedGlobalUser()
    {
        var userId = Guid.NewGuid();
        var credentialService = new Mock<ICredentialService>();
        var service = CreateService(credentialService.Object, repository: new StubRepository(new BasicUser(userId)));

        var result = await service.LinkOidcAccountAsync(userId, "Google", CreatePrincipal("sub"), new TenantContext(Guid.NewGuid()));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Failed));
    }

    [Test]
    public async Task CompleteOidcLinkShouldReturnUnsupportedProvider()
    {
        var service = CreateService();
        var httpContext = CreateHttpContext(new TestAuthenticationService(AuthenticateResult.NoResult()));

        var result = await service.CompleteOidcLinkAsync(httpContext, Guid.NewGuid(), "Microsoft");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.UnsupportedProvider));
    }

    [Test]
    public void CompleteOidcLinkShouldRejectNullHttpContext()
    {
        var service = CreateService();

        Assert.ThrowsAsync<ArgumentNullException>(() => service.CompleteOidcLinkAsync(null!, Guid.NewGuid(), "Google"));
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
    public void LinkOidcAccountFromAuthenticateResultShouldRejectNullResult()
    {
        var service = CreateService();

        Assert.ThrowsAsync<ArgumentNullException>(() => service.LinkOidcAccountAsync(Guid.NewGuid(), "Google", (AuthenticateResult)null!));
    }

    [Test]
    public async Task LinkOidcAccountFromAuthenticateResultShouldReturnUnsupportedProvider()
    {
        var service = CreateService();
        var ticket = AuthenticateResult.Success(new AuthenticationTicket(
            CreatePrincipal("sub"),
            CreateProperties("Google", "Google"),
            "Ashlar.OAuth.External"));

        var result = await service.LinkOidcAccountAsync(Guid.NewGuid(), "Microsoft", ticket);

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.UnsupportedProvider));
    }

    [Test]
    public async Task LinkOidcAccountFromAuthenticateResultShouldReturnAuthenticationFailedForFailedTicket()
    {
        var service = CreateService();

        var result = await service.LinkOidcAccountAsync(Guid.NewGuid(), "Google", AuthenticateResult.Fail("failed"));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.AuthenticationFailed));
    }

    [Test]
    public async Task LinkOidcAccountFromAuthenticateResultShouldReturnInvalidPrincipalForEmptyPrincipal()
    {
        var service = CreateService();
        var ticket = AuthenticateResult.Success(new AuthenticationTicket(
            new ClaimsPrincipal(),
            CreateProperties("Google", "Google"),
            "Ashlar.OAuth.External"));

        var result = await service.LinkOidcAccountAsync(Guid.NewGuid(), "Google", ticket);

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.InvalidPrincipal));
    }

    [Test]
    public async Task LinkOidcAccountFromAuthenticateResultShouldReturnProviderMismatch()
    {
        var service = CreateService();
        var ticket = AuthenticateResult.Success(new AuthenticationTicket(
            CreatePrincipal("sub"),
            new AuthenticationProperties(),
            "Ashlar.OAuth.External"));

        var result = await service.LinkOidcAccountAsync(Guid.NewGuid(), "Google", ticket);

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.ProviderMismatch));
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

    [Test]
    public async Task UnlinkOidcAccountShouldRevokeConfiguredProvider()
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

        var result = await service.UnlinkOidcAccountAsync(userId, "Google", request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Unlinked));
            Assert.That(result.AccountSecurityOperation?.Value?.CredentialsRevoked, Is.EqualTo(1));
            Assert.That(observedRequest, Is.SameAs(request));
        }
    }

    [TestCase("")]
    [TestCase(" ")]
    [TestCase("Microsoft")]
    public async Task UnlinkOidcAccountShouldReturnUnsupportedProviderForBlankOrMissingProvider(string providerName)
    {
        var accountSecurity = CreateAccountSecurityService();
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(Guid.NewGuid())));

        var result = await service.UnlinkOidcAccountAsync(Guid.NewGuid(), providerName, CreateRequest());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.UnsupportedProvider));
            accountSecurity.Verify(s => s.RevokeCredentialsAsync(It.IsAny<Guid>(), It.IsAny<AuthenticationProviderKey>(), It.IsAny<AccountSecurityOperationRequest>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task UnlinkOidcAccountShouldReturnUserNotFoundForMissingUser()
    {
        var userId = Guid.NewGuid();
        var service = CreateService(accountSecurityService: CreateAccountSecurityService().Object, repository: new StubRepository());

        var result = await service.UnlinkOidcAccountAsync(userId, "Google", CreateRequest());

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.UserNotFound));
    }

    [Test]
    public async Task UnlinkOidcAccountShouldReturnUserNotFoundForEmptyCurrentUser()
    {
        var service = CreateService();

        var result = await service.UnlinkOidcAccountAsync(Guid.Empty, "Google", CreateRequest());

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.UserNotFound));
    }

    [Test]
    public async Task UnlinkOidcAccountShouldReturnTenantMismatch()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService();
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new TenantUser(userId, Guid.NewGuid())));

        var result = await service.UnlinkOidcAccountAsync(userId, "Google", CreateRequest(new TenantContext(Guid.NewGuid())));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.TenantMismatch));
            accountSecurity.Verify(s => s.GetUserSecurityPostureAsync(It.IsAny<Guid>(), It.IsAny<UserSecurityPostureRequest>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task UnlinkOidcAccountShouldReturnNotLinkedWhenConfiguredProviderIsAbsent()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(CreatePosture(userId, CreateCredentialItem(ProviderType.Oidc, "Microsoft"), CreateCredentialItem(ProviderType.Local, "Local")));
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(userId)));

        var result = await service.UnlinkOidcAccountAsync(userId, "Google", CreateRequest());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.NotLinked));
            accountSecurity.Verify(s => s.RevokeCredentialsAsync(It.IsAny<Guid>(), It.IsAny<AuthenticationProviderKey>(), It.IsAny<AccountSecurityOperationRequest>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task UnlinkOidcAccountShouldOnlyRevokeConfiguredOidcProvider()
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

        var result = await service.UnlinkOidcAccountAsync(userId, "Google", CreateRequest());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Unlinked));
            accountSecurity.Verify(s => s.RevokeCredentialsAsync(userId, new AuthenticationProviderKey(ProviderType.Oidc, "Google"), It.IsAny<AccountSecurityOperationRequest>(), It.IsAny<CancellationToken>()), Times.Once);
            accountSecurity.Verify(s => s.RevokeCredentialsAsync(userId, It.Is<AuthenticationProviderKey>(p => p.Type != ProviderType.Oidc || p.Name != "Google"), It.IsAny<AccountSecurityOperationRequest>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task UnlinkOidcAccountShouldPreventRemovingLastUsablePrimaryCredential()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(CreatePosture(userId, CreateCredentialItem(ProviderType.Oidc, "Google")));
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(userId)));

        var result = await service.UnlinkOidcAccountAsync(userId, "Google", CreateRequest());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.WouldRemoveLastSignInMethod));
            accountSecurity.Verify(s => s.RevokeCredentialsAsync(It.IsAny<Guid>(), It.IsAny<AuthenticationProviderKey>(), It.IsAny<AccountSecurityOperationRequest>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task UnlinkOidcAccountShouldNotRequireFreshMfaInService()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(
            CreatePosture(userId, CreateCredentialItem(ProviderType.Oidc, "Google"), CreateCredentialItem(ProviderType.Local, "Local")),
            revokeResult: Result.Success(new AccountSecurityOperationResult(userId, CredentialsRevoked: 1)));
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(userId)));

        var result = await service.UnlinkOidcAccountAsync(userId, "Google", CreateRequest());

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Unlinked));
    }

    [Test]
    public async Task UnlinkOidcAccountShouldReturnNotLinkedWhenRevocationFindsNoCredentials()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(
            CreatePosture(userId, CreateCredentialItem(ProviderType.Oidc, "Google"), CreateCredentialItem(ProviderType.Local, "Local")),
            revokeResult: Result.Success(new AccountSecurityOperationResult(userId)));
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(userId)));

        var result = await service.UnlinkOidcAccountAsync(userId, "Google", CreateRequest());

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.NotLinked));
    }

    [Test]
    public async Task UnlinkOidcAccountShouldReturnNotLinkedWhenRevocationSucceedsWithoutValue()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(
            CreatePosture(userId, CreateCredentialItem(ProviderType.Oidc, "Google"), CreateCredentialItem(ProviderType.Local, "Local")),
            revokeResult: new Result<AccountSecurityOperationResult>(true));
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(userId)));

        var result = await service.UnlinkOidcAccountAsync(userId, "Google", CreateRequest());

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.NotLinked));
    }

    [Test]
    public async Task UnlinkOidcAccountShouldMapAccountSecurityFailures()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(
            CreatePosture(userId, CreateCredentialItem(ProviderType.Oidc, "Google"), CreateCredentialItem(ProviderType.Local, "Local")),
            revokeResult: Result.Failure<AccountSecurityOperationResult>(AshlarFailureCodes.UserNotFound));
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(userId)));

        var result = await service.UnlinkOidcAccountAsync(userId, "Google", CreateRequest());

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.UserNotFound));
    }

    [Test]
    public async Task UnlinkOidcAccountShouldReturnFailedWhenPostureLookupFails()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService();
        accountSecurity
            .Setup(s => s.GetUserSecurityPostureAsync(userId, It.IsAny<UserSecurityPostureRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure<UserSecurityPosture>(AshlarFailureCodes.ValidationError));
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(userId)));

        var result = await service.UnlinkOidcAccountAsync(userId, "Google", CreateRequest());

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Failed));
    }

    [Test]
    public async Task UnlinkOidcAccountShouldReturnFailedWhenPostureLookupFailsWithoutDetails()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService();
        accountSecurity
            .Setup(s => s.GetUserSecurityPostureAsync(userId, It.IsAny<UserSecurityPostureRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Result<UserSecurityPosture>(false));
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(userId)));

        var result = await service.UnlinkOidcAccountAsync(userId, "Google", CreateRequest());

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Failed));
    }

    [Test]
    public async Task UnlinkOidcAccountShouldReturnUserNotFoundWhenPostureLookupCannotFindUser()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService();
        accountSecurity
            .Setup(s => s.GetUserSecurityPostureAsync(userId, It.IsAny<UserSecurityPostureRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure<UserSecurityPosture>(AshlarFailureCodes.UserNotFound));
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(userId)));

        var result = await service.UnlinkOidcAccountAsync(userId, "Google", CreateRequest());

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.UserNotFound));
    }

    [Test]
    public async Task UnlinkOidcAccountShouldReturnFailedForUnknownRevocationFailure()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(
            CreatePosture(userId, CreateCredentialItem(ProviderType.Oidc, "Google"), CreateCredentialItem(ProviderType.Local, "Local")),
            revokeResult: Result.Failure<AccountSecurityOperationResult>(AshlarFailureCodes.ValidationError));
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(userId)));

        var result = await service.UnlinkOidcAccountAsync(userId, "Google", CreateRequest());

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Failed));
    }

    [Test]
    public async Task UnlinkOidcAccountShouldReturnFailedForRevocationFailureWithoutDetails()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(
            CreatePosture(userId, CreateCredentialItem(ProviderType.Oidc, "Google"), CreateCredentialItem(ProviderType.Local, "Local")),
            revokeResult: new Result<AccountSecurityOperationResult>(false));
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(userId)));

        var result = await service.UnlinkOidcAccountAsync(userId, "Google", CreateRequest());

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Failed));
    }

    [Test]
    public async Task UnlinkOidcAccountShouldAllowGlobalTenantForGlobalUser()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(
            CreatePosture(userId, CreateCredentialItem(ProviderType.Oidc, "Google"), CreateCredentialItem(ProviderType.Local, "Local")),
            revokeResult: Result.Success(new AccountSecurityOperationResult(userId, CredentialsRevoked: 1)));
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(userId)));

        var result = await service.UnlinkOidcAccountAsync(userId, "Google", CreateRequest(TenantContext.Global));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Unlinked));
    }

    [Test]
    public async Task UnlinkOidcAccountShouldRejectGlobalTenantForTenantScopedUser()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService();
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new TenantUser(userId, Guid.NewGuid())));

        var result = await service.UnlinkOidcAccountAsync(userId, "Google", CreateRequest(TenantContext.Global));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.TenantMismatch));
    }

    [Test]
    public async Task UnlinkOidcAccountShouldAllowGlobalTenantForTenantUserWithoutTenant()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(
            CreatePosture(userId, CreateCredentialItem(ProviderType.Oidc, "Google"), CreateCredentialItem(ProviderType.Local, "Local")),
            revokeResult: Result.Success(new AccountSecurityOperationResult(userId, CredentialsRevoked: 1)));
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new TenantUser(userId, null)));

        var result = await service.UnlinkOidcAccountAsync(userId, "Google", CreateRequest(TenantContext.Global));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Unlinked));
    }

    [Test]
    public async Task UnlinkOidcAccountShouldRejectScopedTenantForTenantUserWithoutTenant()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService();
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new TenantUser(userId, null)));

        var result = await service.UnlinkOidcAccountAsync(userId, "Google", CreateRequest(new TenantContext(Guid.NewGuid())));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.TenantMismatch));
    }

    [Test]
    public async Task UnlinkOidcAccountShouldRejectScopedTenantForGlobalUser()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService();
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(userId)));

        var result = await service.UnlinkOidcAccountAsync(userId, "Google", CreateRequest(new TenantContext(Guid.NewGuid())));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.TenantMismatch));
    }

    [Test]
    public void UnlinkOidcAccountShouldRejectNullRequestBeforeOtherValidation()
    {
        var accountSecurity = CreateAccountSecurityService();
        var service = CreateService(accountSecurityService: accountSecurity.Object, repository: new StubRepository(new BasicUser(Guid.NewGuid())));

        Assert.ThrowsAsync<ArgumentNullException>(() => service.UnlinkOidcAccountAsync(Guid.Empty, "Microsoft", null!));
        accountSecurity.Verify(s => s.GetUserSecurityPostureAsync(It.IsAny<Guid>(), It.IsAny<UserSecurityPostureRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    private static AshlarExternalAccountLinkService CreateService(ICredentialService? credentialService = null, IAccountSecurityService? accountSecurityService = null, IIdentityRepository? repository = null)
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
        UserSecurityPosture? posture = null,
        Result<AccountSecurityOperationResult>? revokeResult = null)
    {
        var accountSecurity = new Mock<IAccountSecurityService>();
        accountSecurity
            .Setup(s => s.GetUserSecurityPostureAsync(It.IsAny<Guid>(), It.IsAny<UserSecurityPostureRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Guid userId, UserSecurityPostureRequest request, CancellationToken _) =>
                Result.Success(posture ?? CreatePosture(userId, CreateCredentialItem(ProviderType.Local, "Local"))));
        accountSecurity
            .Setup(s => s.RevokeCredentialsAsync(It.IsAny<Guid>(), It.IsAny<AuthenticationProviderKey>(), It.IsAny<AccountSecurityOperationRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(revokeResult ?? Result.Success(new AccountSecurityOperationResult(Guid.NewGuid(), CredentialsRevoked: 1)));
        return accountSecurity;
    }

    private static AccountSecurityOperationRequest CreateRequest(TenantContext? tenant = null)
    {
        return new AccountSecurityOperationRequest(new AuditContext(Guid.NewGuid(), "127.0.0.1", "NUnit", "corr"), tenant, "unlink");
    }

    private static UserSecurityPosture CreatePosture(Guid userId, params CredentialPostureItem[] credentials)
    {
        var primary = credentials.Where(c => c.IsPrimaryCredential && c.IsAvailable).ToArray();
        return new UserSecurityPosture(
            userId,
            true,
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

    private sealed record BasicUser(Guid Id) : IUser
    {
        public string Email => "global@example.com";
        public string? Name => null;
        public bool IsActive => true;
        public DateTimeOffset? EmailVerifiedAt => null;
    }
}
