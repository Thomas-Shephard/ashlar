using System.Security.Claims;
using System.Reflection;
using Ashlar.Auditing;
using Ashlar.OAuth.Providers.GitHub;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;

namespace Ashlar.Tests.OAuth;

internal sealed class AshlarExternalAccountLinkServiceTests
{

    [Test]
    public void ConstructorShouldRejectNullDependencies()
    {
        var credentialService = new ValidatedExternalCredentialLinkServiceMock().Object;
        var accountSecurityAdministration = CreateAccountSecurityService();
        var options = new TestOptionsMonitor(new AshlarOAuthOptions());
        var proofValidator = CreateUnlinkProofValidator(TimeProvider.System);

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => new AshlarExternalAccountLinkService(null!, proofValidator, accountSecurityAdministration, options, TimeProvider.System));
            Assert.Throws<ArgumentNullException>(() => new AshlarExternalAccountLinkService(credentialService, null!, accountSecurityAdministration, options, TimeProvider.System));
            Assert.Throws<ArgumentNullException>(() => new AshlarExternalAccountLinkService(credentialService, proofValidator, null!, options, TimeProvider.System));
            Assert.Throws<ArgumentNullException>(() => new AshlarExternalAccountLinkService(credentialService, proofValidator, accountSecurityAdministration, null!, TimeProvider.System));
            Assert.Throws<ArgumentNullException>(() => new AshlarExternalAccountLinkService(credentialService, proofValidator, accountSecurityAdministration, options, null!));
        }
    }

    [Test]
    public void PublicLinkApiShouldNotExposeRawExternalTicketOverload()
    {
        var exportedTypes = typeof(IIdentityService).Assembly.GetExportedTypes();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(typeof(AshlarExternalTicket).IsPublic, Is.False);
            Assert.That(new HostileProvider(), Is.InstanceOf<IAuthenticationProvider>());
            Assert.That(new HostileAssertion(), Is.InstanceOf<IAuthenticationAssertion>());
            Assert.That(exportedTypes, Has.None.Matches<Type>(type => type.Name == "ICredentialLinkService"));
            Assert.That(exportedTypes, Has.None.Matches<Type>(type => type.Name == "CredentialLinkRequest"));
            Assert.That(exportedTypes, Does.Not.Contain(typeof(IValidatedExternalCredentialLinkService)));
            Assert.That(exportedTypes, Does.Not.Contain(typeof(InternalValidatedExternalCredentialLinkRequest)));
            Assert.That(typeof(IValidatedExternalCredentialLinkService).IsPublic, Is.False);
            Assert.That(typeof(InternalValidatedExternalCredentialLinkRequest).IsPublic, Is.False);
            Assert.That(typeof(InternalValidatedExternalCredentialLinkRequest).GetProperties(),
                Has.None.Matches<PropertyInfo>(property =>
                    typeof(IAuthenticationProvider).IsAssignableFrom(property.PropertyType) ||
                    typeof(IAuthenticationAssertion).IsAssignableFrom(property.PropertyType)));
            Assert.That(typeof(AshlarExternalAccountLinkService).GetConstructors(BindingFlags.Instance | BindingFlags.NonPublic)
                .Single().GetParameters().First().ParameterType, Is.EqualTo(typeof(IValidatedExternalCredentialLinkService)));
            Assert.That(exportedTypes
                .SelectMany(type => type.GetMethods(BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public))
                .Where(method => method.Name.Contains("Link", StringComparison.OrdinalIgnoreCase))
                .SelectMany(method => method.GetParameters()),
                Has.None.Matches<ParameterInfo>(parameter =>
                    typeof(IAuthenticationProvider).IsAssignableFrom(parameter.ParameterType) ||
                    typeof(IAuthenticationAssertion).IsAssignableFrom(parameter.ParameterType)));
        }

        var unsafeOverload = typeof(AshlarExternalAccountLinkService)
            .GetMethods(BindingFlags.Instance | BindingFlags.Public)
            .Any(method => method.GetParameters().Any(parameter =>
                parameter.ParameterType == typeof(AuthenticateResult) ||
                parameter.ParameterType == typeof(ClaimsPrincipal) ||
                parameter.ParameterType.GetProperties().Any(property => property.PropertyType == typeof(AuthenticateResult))));

        Assert.That(unsafeOverload, Is.False);
    }

    private sealed class HostileAssertion : IAuthenticationAssertion
    {
        public AuthenticationProviderKey ProviderIdentity { get; } = new(ProviderType.OAuth, "Hostile");
    }

    private sealed class HostileProvider : IAuthenticationProvider
    {
        public AuthenticationProviderKey Key { get; } = new(ProviderType.OAuth, "Hostile");

        public string GetProviderKey(IAuthenticationAssertion assertion, Guid userId) => "attacker-selected-key";

        public string? PrepareCredentialValue(IAuthenticationAssertion assertion, string? rawValue) => rawValue;

        public Task<AuthenticationResult> AuthenticateAsync(
            IAuthenticationAssertion assertion,
            UserCredential? credential,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(new AuthenticationResult(AuthenticationResultStatus.Succeeded));
    }

    [Test]
    public void UnlinkRequestShouldRequireAuditAndTenant()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => new AshlarExternalAccountUnlinkRequest(null!, TenantContext.Global));
            Assert.Throws<ArgumentNullException>(() => new AshlarExternalAccountUnlinkRequest(new AuditContext(Guid.NewGuid()), null!));
        }
    }

    [Test]
    public async Task UnlinkExternalAccountShouldPreservePrimarySignInMethodThroughMutationExecutor()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(revokeResult:
            Result.Failure<AccountSecurityOperationResult>(AshlarFailureCodes.ValidationError));
        var service = CreateService(accountSecurityService: accountSecurity);

        var result = await service.UnlinkWithFreshProofAsync(userId, "Google", CreateRequest(actorUserId: userId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Failed));
            Assert.That(accountSecurity.Request?.PreservePrimarySignInMethod, Is.True);
        }
    }

    [Test]
    public void PublicCompleteLinkApiShouldRequireProofAndSession()
    {
        var overloads = typeof(AshlarExternalAccountLinkService)
            .GetMethods(BindingFlags.Instance | BindingFlags.Public)
            .Where(method => method.Name == nameof(AshlarExternalAccountLinkService.CompleteExternalLinkAsync))
            .ToArray();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(overloads, Is.Not.Empty);
            foreach (var overload in overloads)
            {
                var parameters = overload.GetParameters();
                Assert.That(parameters.Any(parameter => parameter.ParameterType == typeof(FreshMfaVerificationProof)), Is.True);
                Assert.That(parameters.Any(parameter => parameter.Name == "currentSessionId" && parameter.ParameterType == typeof(Guid?)), Is.True);
            }
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
        var credentialService = new ValidatedExternalCredentialLinkServiceMock();
        InternalValidatedExternalCredentialLinkRequest? observedRequest = null;
        AuditContext? observedAudit = null;
        credentialService
            .Setup(s => s.LinkValidatedExternalCredentialAsync(It.Is<InternalValidatedExternalCredentialLinkRequest>(r => r.UserId == userId), It.IsAny<CancellationToken>()))
            .Callback<InternalValidatedExternalCredentialLinkRequest, CancellationToken>((request, _) =>
            {
                observedRequest = request;
                observedAudit = request.Audit;
            })
            .ReturnsAsync(Result.Success());
        var service = CreateService(credentialService.Object);

        var result = await service.LinkWithFreshProofAsync(
            userId,
            "Google",
            AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("stable-sub", "first@example.com", tokenClaims: true)),
            TenantContext.Global);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Linked));
            Assert.That(observedRequest?.ProviderKey, Does.StartWith("oidc-sha256:"));
            Assert.That(new AuthenticationProviderKey(observedRequest!.ProviderType, observedRequest.ProviderName), Is.EqualTo(new AuthenticationProviderKey(ProviderType.Oidc, "Google")));
            Assert.That(observedAudit?.ActorUserId, Is.EqualTo(userId));
        }
    }

    [Test]
    public async Task CompleteExternalLinkShouldRequireFreshProofBeforeConsumingTicket()
    {
        var authService = new TestAuthenticationService(AuthenticateResult.Success(new AuthenticationTicket(
            CreatePrincipal("sub"),
            CreateProperties("Google", "Google"),
            "Ashlar.OAuth.External")));
        var credentialService = new ValidatedExternalCredentialLinkServiceMock();
        var service = CreateService(credentialService.Object);

        var result = await service.CompleteExternalLinkAsync(
            CreateHttpContext(authService),
            Guid.NewGuid(),
            "Google",
            freshMfaProof: null,
            currentSessionId: Guid.NewGuid(),
            TenantContext.Global);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Failed));
            Assert.That(authService.AuthenticateCount, Is.Zero);
            Assert.That(authService.SignOutCount, Is.Zero);
            credentialService.Verify(s => s.LinkValidatedExternalCredentialAsync(It.IsAny<InternalValidatedExternalCredentialLinkRequest>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task LinkExternalAccountShouldStopWhenAuthoritativeProofValidationFails()
    {
        var credentials = new ValidatedExternalCredentialLinkServiceMock();
        var service = CreateService(credentials.Object, proofValidator: new ActiveSessionFreshProofValidator(
            Mock.Of<IAuthenticationSessionRepository>(), TimeProvider.System));

        var result = await service.LinkWithFreshProofAsync(
            Guid.NewGuid(), "Google",
            AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("sub")),
            TenantContext.Global);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Failed));
            Assert.That(result.CredentialLink?.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
        }
        credentials.Verify(s => s.LinkValidatedExternalCredentialAsync(It.IsAny<InternalValidatedExternalCredentialLinkRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task CompleteExternalLinkShouldRequireFreshProofBeforeClearingUnsupportedProviderTicket()
    {
        var authService = new TestAuthenticationService(AuthenticateResult.NoResult());
        var service = CreateService();

        var result = await service.CompleteExternalLinkAsync(
            CreateHttpContext(authService),
            Guid.NewGuid(),
            "Microsoft",
            freshMfaProof: null,
            currentSessionId: Guid.NewGuid(),
            TenantContext.Global);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Failed));
            Assert.That(authService.AuthenticateCount, Is.Zero);
            Assert.That(authService.SignOutCount, Is.Zero);
        }
    }

    [Test]
    public async Task LinkExternalAccountShouldMapGitHubPrincipalAndLinkOAuthCredential()
    {
        var userId = Guid.NewGuid();
        var credentialService = new ValidatedExternalCredentialLinkServiceMock();
        InternalValidatedExternalCredentialLinkRequest? observedRequest = null;
        credentialService
            .Setup(s => s.LinkValidatedExternalCredentialAsync(It.Is<InternalValidatedExternalCredentialLinkRequest>(r => r.UserId == userId), It.IsAny<CancellationToken>()))
            .Callback<InternalValidatedExternalCredentialLinkRequest, CancellationToken>((request, _) =>
            {
                observedRequest = request;
            })
            .ReturnsAsync(Result.Success());
        var service = CreateService(credentialService.Object, includeGitHub: true);

        var result = await service.LinkWithFreshProofAsync(userId, "GitHub", AshlarOAuthTestTickets.CreateExternalTicket("GitHub", "GitHub", ProviderType.OAuth, CreateGitHubPrincipal("12345")), TenantContext.Global);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Linked));
            Assert.That(observedRequest?.ProviderType, Is.EqualTo(ProviderType.OAuth));
            Assert.That(observedRequest?.ProviderName, Is.EqualTo("GitHub"));
            Assert.That(observedRequest?.ProviderKey, Is.EqualTo("12345"));
            Assert.That(observedRequest?.ProviderKey, Is.EqualTo("12345"));
            Assert.That(new AuthenticationProviderKey(observedRequest!.ProviderType, observedRequest.ProviderName), Is.EqualTo(new AuthenticationProviderKey(ProviderType.OAuth, "GitHub")));
        }
    }

    [Test]
    public async Task LinkExternalAccountShouldUseConfiguredOAuth2ProviderKeyClaim()
    {
        var userId = Guid.NewGuid();
        var credentialService = new ValidatedExternalCredentialLinkServiceMock();
        InternalValidatedExternalCredentialLinkRequest? observedRequest = null;
        credentialService
            .Setup(s => s.LinkValidatedExternalCredentialAsync(It.Is<InternalValidatedExternalCredentialLinkRequest>(r => r.UserId == userId), It.IsAny<CancellationToken>()))
            .Callback<InternalValidatedExternalCredentialLinkRequest, CancellationToken>((request, _) =>
                observedRequest = request)
            .ReturnsAsync(Result.Success());
        var service = CreateService(
            credentialService.Object,
            configureOptions: options => options.AddOAuth2Provider("CustomOAuth", "uid", _ => { }));
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("uid", "stable-uid"), new Claim("id", "not-used")], "oauth"));

        var result = await service.LinkWithFreshProofAsync(userId, "CustomOAuth", AshlarOAuthTestTickets.CreateExternalTicket("CustomOAuth", "CustomOAuth", ProviderType.OAuth, principal), TenantContext.Global);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Linked));
            Assert.That(observedRequest?.ProviderKey, Is.EqualTo("stable-uid"));
            Assert.That(new AuthenticationProviderKey(observedRequest!.ProviderType, observedRequest.ProviderName), Is.EqualTo(new AuthenticationProviderKey(ProviderType.OAuth, "CustomOAuth")));
            Assert.That(observedRequest.ProviderKey, Is.EqualTo("stable-uid"));
        }
    }

    [Test]
    public async Task LinkExternalAccountShouldReturnUnsupportedProviderForMissingProvider()
    {
        var service = CreateService();

        var result = await service.LinkWithFreshProofAsync(Guid.NewGuid(), "Microsoft", AshlarOAuthTestTickets.CreateExternalTicket("Microsoft", "Microsoft", ProviderType.Oidc, CreatePrincipal("sub")), TenantContext.Global);

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.UnsupportedProvider));
    }

    [TestCase("")]
    [TestCase(" ")]
    public async Task LinkExternalAccountShouldReturnUnsupportedProviderForBlankProviderName(string providerName)
    {
        var service = CreateService();

        var result = await service.LinkWithFreshProofAsync(Guid.NewGuid(), providerName, AshlarOAuthTestTickets.CreateExternalTicket(providerName, providerName, ProviderType.Oidc, CreatePrincipal("sub")), TenantContext.Global);

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.UnsupportedProvider));
    }

    [Test]
    public async Task LinkExternalAccountShouldReturnInvalidPrincipalForMissingSubject()
    {
        var service = CreateService();

        var result = await service.LinkWithFreshProofAsync(Guid.NewGuid(), "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, new ClaimsPrincipal(new ClaimsIdentity())), TenantContext.Global);

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.InvalidPrincipal));
    }

    [Test]
    public void LinkExternalAccountShouldRejectNullPrincipal()
    {
        var service = CreateService();

        Assert.ThrowsAsync<ArgumentNullException>(() => service.LinkWithFreshProofAsync(Guid.NewGuid(), "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, null!), TenantContext.Global));
    }

    [Test]
    public static async Task LinkExternalAccountShouldReturnInvalidPrincipalWhenConfiguredProviderNameIsInvalid()
    {
        var service = CreateServiceWithProvider(new AshlarOidcProviderOptions(" ", "Google", _ => { }));
        var ticket = AuthenticateResult.Success(new AuthenticationTicket(
            CreatePrincipal("sub"),
            CreateProperties(" ", "Google"),
            "Ashlar.OAuth.External"));

        var result = await service.LinkWithFreshProofAsync(Guid.NewGuid(), "Google", ticket, TenantContext.Global);

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.InvalidPrincipal));
    }

    [Test]
    public async Task LinkExternalAccountShouldReturnAlreadyLinkedForSameUser()
    {
        var credentialService = new ValidatedExternalCredentialLinkServiceMock();
        credentialService
            .Setup(s => s.LinkValidatedExternalCredentialAsync(It.IsAny<InternalValidatedExternalCredentialLinkRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure(AshlarFailureCodes.AlreadyLinkedToSelf));
        var service = CreateService(credentialService.Object);

        var result = await service.LinkWithFreshProofAsync(Guid.NewGuid(), "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("sub")), TenantContext.Global);

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.AlreadyLinked));
    }

    [Test]
    public async Task LinkExternalAccountShouldReturnAlreadyLinkedToAnotherUser()
    {
        var credentialService = new ValidatedExternalCredentialLinkServiceMock();
        credentialService
            .Setup(s => s.LinkValidatedExternalCredentialAsync(It.IsAny<InternalValidatedExternalCredentialLinkRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure(AshlarFailureCodes.AlreadyLinkedToOther));
        var service = CreateService(credentialService.Object);

        var result = await service.LinkWithFreshProofAsync(Guid.NewGuid(), "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("sub")), TenantContext.Global);

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.AlreadyLinkedToAnotherUser));
    }

    [Test]
    public async Task LinkExternalAccountShouldReturnInvalidPrincipalWhenCredentialServiceRejectsProviderKey()
    {
        var credentialService = new ValidatedExternalCredentialLinkServiceMock();
        credentialService
            .Setup(s => s.LinkValidatedExternalCredentialAsync(It.IsAny<InternalValidatedExternalCredentialLinkRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure(AshlarFailureCodes.InvalidProviderKey));
        var service = CreateService(credentialService.Object);

        var result = await service.LinkWithFreshProofAsync(Guid.NewGuid(), "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("sub")), TenantContext.Global);

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.InvalidPrincipal));
    }

    [Test]
    public async Task LinkExternalAccountShouldReturnFailedForUnknownCredentialFailure()
    {
        var credentialService = new ValidatedExternalCredentialLinkServiceMock();
        credentialService
            .Setup(s => s.LinkValidatedExternalCredentialAsync(It.IsAny<InternalValidatedExternalCredentialLinkRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure(AshlarFailureCodes.UserNotFound));
        var service = CreateService(credentialService.Object);

        var result = await service.LinkWithFreshProofAsync(Guid.NewGuid(), "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("sub")), TenantContext.Global);

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Failed));
    }

    [Test]
    public async Task LinkExternalAccountShouldReturnFailedForCredentialFailureWithoutDetails()
    {
        var credentialService = new ValidatedExternalCredentialLinkServiceMock();
        credentialService
            .Setup(s => s.LinkValidatedExternalCredentialAsync(It.IsAny<InternalValidatedExternalCredentialLinkRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure(AshlarFailureCodes.ValidationError));
        var service = CreateService(credentialService.Object);

        var result = await service.LinkWithFreshProofAsync(Guid.NewGuid(), "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("sub")), TenantContext.Global);

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Failed));
    }

    [Test]
    public async Task LinkExternalAccountShouldUseSubjectWhenEmailChanges()
    {
        var userId = Guid.NewGuid();
        var assertions = new List<InternalValidatedExternalCredentialLinkRequest>();
        var credentialService = new ValidatedExternalCredentialLinkServiceMock();
        credentialService
            .Setup(s => s.LinkValidatedExternalCredentialAsync(It.Is<InternalValidatedExternalCredentialLinkRequest>(r => r.UserId == userId), It.IsAny<CancellationToken>()))
            .Callback<InternalValidatedExternalCredentialLinkRequest, CancellationToken>((request, _) =>
                assertions.Add(request))
            .ReturnsAsync(Result.Failure(AshlarFailureCodes.AlreadyLinkedToSelf));
        var service = CreateService(credentialService.Object);

        await service.LinkWithFreshProofAsync(userId, "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("same-sub", "old@example.com")), TenantContext.Global);
        await service.LinkWithFreshProofAsync(userId, "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("same-sub", "new@example.com")), TenantContext.Global);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(assertions.Select(a => a.ProviderKey).Distinct().Count(), Is.EqualTo(1));
        }
    }

    [Test]
    public async Task LinkExternalAccountShouldNotStoreTokens()
    {
        var credentialService = new ValidatedExternalCredentialLinkServiceMock();
        credentialService
            .Setup(s => s.LinkValidatedExternalCredentialAsync(It.IsAny<InternalValidatedExternalCredentialLinkRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success());
        var service = CreateService(credentialService.Object);

        await service.LinkWithFreshProofAsync(Guid.NewGuid(), "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("sub", tokenClaims: true)), TenantContext.Global);

        credentialService.Verify(s => s.LinkValidatedExternalCredentialAsync(
            It.Is<InternalValidatedExternalCredentialLinkRequest>(request => request.ProviderKey.Length > 0 && request.ProviderName.Length > 0),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task LinkExternalAccountShouldPreserveTenantIsolation()
    {
        var tenantId = Guid.NewGuid();
        var otherTenantId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        var credentialService = new ValidatedExternalCredentialLinkServiceMock();
        credentialService.Setup(s => s.LinkValidatedExternalCredentialAsync(It.IsAny<InternalValidatedExternalCredentialLinkRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure(AshlarFailureCodes.TenantMismatch));
        var service = CreateService(credentialService.Object);

        var result = await service.LinkWithFreshProofAsync(userId, "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("sub")), new TenantContext(otherTenantId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Failed));
            credentialService.Verify(s => s.LinkValidatedExternalCredentialAsync(It.IsAny<InternalValidatedExternalCredentialLinkRequest>(), It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [Test]
    public async Task LinkExternalAccountShouldAllowMatchingTenant()
    {
        var tenantId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        var credentialService = new ValidatedExternalCredentialLinkServiceMock();
        credentialService
            .Setup(s => s.LinkValidatedExternalCredentialAsync(It.Is<InternalValidatedExternalCredentialLinkRequest>(r => r.UserId == userId), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success());
        var service = CreateService(credentialService.Object);

        var result = await service.LinkWithFreshProofAsync(userId, "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("sub")), new TenantContext(tenantId));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Linked));
    }

    [Test]
    public async Task LinkExternalAccountShouldAllowGlobalTenantForTenantUserWithoutTenant()
    {
        var userId = Guid.NewGuid();
        var credentialService = new ValidatedExternalCredentialLinkServiceMock();
        credentialService
            .Setup(s => s.LinkValidatedExternalCredentialAsync(It.Is<InternalValidatedExternalCredentialLinkRequest>(r => r.UserId == userId), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success());
        var service = CreateService(credentialService.Object);

        var result = await service.LinkWithFreshProofAsync(userId, "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("sub")), TenantContext.Global);

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Linked));
    }

    [Test]
    public async Task LinkExternalAccountShouldFailTenantScopedTenantUserWithoutTenant()
    {
        var userId = Guid.NewGuid();
        var credentialService = new ValidatedExternalCredentialLinkServiceMock();
        credentialService.Setup(s => s.LinkValidatedExternalCredentialAsync(It.IsAny<InternalValidatedExternalCredentialLinkRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure(AshlarFailureCodes.TenantMismatch));
        var service = CreateService(credentialService.Object);

        var result = await service.LinkWithFreshProofAsync(userId, "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("sub")), new TenantContext(Guid.NewGuid()));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Failed));
    }

    [Test]
    public async Task LinkExternalAccountShouldFailTenantScopedMissingUser()
    {
        var credentialService = new ValidatedExternalCredentialLinkServiceMock();
        credentialService.Setup(s => s.LinkValidatedExternalCredentialAsync(It.IsAny<InternalValidatedExternalCredentialLinkRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure(AshlarFailureCodes.UserNotFound));
        var service = CreateService(credentialService.Object);

        var result = await service.LinkWithFreshProofAsync(Guid.NewGuid(), "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("sub")), new TenantContext(Guid.NewGuid()));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Failed));
    }

    [Test]
    public async Task LinkExternalAccountShouldAllowGlobalTenantForGlobalUser()
    {
        var userId = Guid.NewGuid();
        var credentialService = new ValidatedExternalCredentialLinkServiceMock();
        credentialService
            .Setup(s => s.LinkValidatedExternalCredentialAsync(It.Is<InternalValidatedExternalCredentialLinkRequest>(r => r.UserId == userId), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success());
        var service = CreateService(credentialService.Object);

        var result = await service.LinkWithFreshProofAsync(userId, "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("sub")), TenantContext.Global);

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Linked));
    }

    [Test]
    public async Task LinkExternalAccountShouldFailTenantScopedGlobalUser()
    {
        var userId = Guid.NewGuid();
        var credentialService = new ValidatedExternalCredentialLinkServiceMock();
        credentialService.Setup(s => s.LinkValidatedExternalCredentialAsync(It.IsAny<InternalValidatedExternalCredentialLinkRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure(AshlarFailureCodes.TenantMismatch));
        var service = CreateService(credentialService.Object);

        var result = await service.LinkWithFreshProofAsync(userId, "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("sub")), new TenantContext(Guid.NewGuid()));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Failed));
    }

    [Test]
    public async Task CompleteExternalLinkShouldReturnUnsupportedProvider()
    {
        var service = CreateService();
        var httpContext = CreateHttpContext(new TestAuthenticationService(AuthenticateResult.NoResult()));

        var result = await service.CompleteWithFreshProofAsync(httpContext, Guid.NewGuid(), "Microsoft", TenantContext.Global);

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

        var result = await service.CompleteWithFreshProofAsync(httpContext, Guid.NewGuid(), "Microsoft", TenantContext.Global, cancellationToken: cts.Token);

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

        Assert.ThrowsAsync<ArgumentNullException>(() => service.CompleteWithFreshProofAsync(null!, Guid.NewGuid(), "Google", TenantContext.Global));
    }

    [Test]
    public async Task CompleteExternalLinkShouldClearExternalCookieBeforeLinking()
    {
        var authService = new TestAuthenticationService(AuthenticateResult.Success(new AuthenticationTicket(
            CreatePrincipal("sub"),
            CreateProperties("Google", "Google"),
            "Ashlar.OAuth.External")));
        var credentialService = new ValidatedExternalCredentialLinkServiceMock();
        credentialService
            .Setup(s => s.LinkValidatedExternalCredentialAsync(It.IsAny<InternalValidatedExternalCredentialLinkRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success());
        var service = CreateService(credentialService.Object);

        var result = await service.CompleteWithFreshProofAsync(CreateHttpContext(authService), Guid.NewGuid(), "Google", TenantContext.Global);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Linked));
            Assert.That(authService.SignOutCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task CompleteExternalLinkShouldRejectOrdinaryExternalSignInTicket()
    {
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var authentication = new TestAuthenticationService(AuthenticateResult.Success(new AuthenticationTicket(
            CreatePrincipal("sub"),
            CreateProperties("Google", "Google"),
            "Ashlar.OAuth.External")));
        var credentials = new ValidatedExternalCredentialLinkServiceMock();
        var service = CreateService(credentials.Object);

        var result = await service.CompleteExternalLinkAsync(
            CreateHttpContext(authentication), userId, "Google",
            ExternalAccountLinkServiceTestExtensions.CreateProof(userId, TenantContext.Global, sessionId),
            sessionId, TenantContext.Global);

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.AuthenticationFailed));
        credentials.Verify(x => x.LinkValidatedExternalCredentialAsync(It.IsAny<InternalValidatedExternalCredentialLinkRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public void CreateExternalLinkChallengePropertiesRejectsEmptyBindings()
    {
        Assert.Throws<ArgumentException>(() => AshlarExternalAccountLinkService.CreateExternalLinkChallengeProperties(Guid.Empty, Guid.NewGuid()));
        Assert.Throws<ArgumentException>(() => AshlarExternalAccountLinkService.CreateExternalLinkChallengeProperties(Guid.NewGuid(), Guid.Empty));
    }

    [TestCase("/")]
    [TestCase("/account/external/link/callback?tab=security#linked")]
    public void CreateExternalLinkChallengePropertiesAcceptsLocalReturnPath(string returnPath)
    {
        var properties = AshlarExternalAccountLinkService.CreateExternalLinkChallengeProperties(
            Guid.NewGuid(), Guid.NewGuid(), returnPath);

        Assert.That(properties.RedirectUri, Is.EqualTo(returnPath));
    }

    [TestCase("https://evil.example")]
    [TestCase("//evil.example")]
    [TestCase("/\\evil.example")]
    [TestCase("/%2f%2fevil.example")]
    [TestCase("/%5cevil.example")]
    [TestCase("/%255cevil.example")]
    [TestCase("/%")]
    [TestCase("/%E0%A4%A")]
    [TestCase("/evil.example\r\nLocation: https://evil.example")]
    [TestCase("/evil.example\0")]
    [TestCase(" /account/external/link/callback")]
    [TestCase("")]
    public void CreateExternalLinkChallengePropertiesRejectsUnsafeReturnPath(string returnPath)
    {
        Assert.Throws<ArgumentException>(() => AshlarExternalAccountLinkService.CreateExternalLinkChallengeProperties(
            Guid.NewGuid(), Guid.NewGuid(), returnPath));
    }

    [Test]
    public async Task CompleteExternalLinkShouldNotLinkWhenClearingSuccessfulTicketThrows()
    {
        var authService = new TestAuthenticationService(
            AuthenticateResult.Success(new AuthenticationTicket(CreatePrincipal("sub"), CreateProperties("Google", "Google"), "Ashlar.OAuth.External")),
            signOutException: new InvalidOperationException("clear failed"));
        var credentialService = new ValidatedExternalCredentialLinkServiceMock();
        var service = CreateService(credentialService.Object);

        var result = await service.CompleteWithFreshProofAsync(CreateHttpContext(authService), Guid.NewGuid(), "Google", TenantContext.Global);

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.AuthenticationFailed));
        credentialService.Verify(s => s.LinkValidatedExternalCredentialAsync(It.IsAny<InternalValidatedExternalCredentialLinkRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task CompleteExternalLinkShouldReturnProviderMismatchForOidcTicketWithoutProviderType()
    {
        var authService = new TestAuthenticationService(AuthenticateResult.Success(new AuthenticationTicket(
            CreatePrincipal("sub"),
            CreateProperties("Google", "Google", includeProviderType: false),
            "Ashlar.OAuth.External")));
        var credentialService = new ValidatedExternalCredentialLinkServiceMock();
        var service = CreateService(credentialService.Object);

        var result = await service.CompleteWithFreshProofAsync(CreateHttpContext(authService), Guid.NewGuid(), "Google", TenantContext.Global);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.ProviderMismatch));
            Assert.That(authService.SignOutCount, Is.EqualTo(1));
        }

        credentialService.Verify(
            s => s.LinkValidatedExternalCredentialAsync(It.IsAny<InternalValidatedExternalCredentialLinkRequest>(), It.IsAny<CancellationToken>()),
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

        var result = await service.CompleteWithFreshProofAsync(CreateHttpContext(authService), Guid.NewGuid(), "GitHub", TenantContext.Global);

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

        Assert.ThrowsAsync<InvalidOperationException>(() => service.CompleteWithFreshProofAsync(CreateHttpContext(authService), Guid.NewGuid(), "Google", TenantContext.Global));
        Assert.That(authService.SignOutCount, Is.EqualTo(1));
    }

    [Test]
    public async Task LinkExternalAccountFromAuthenticateResultShouldLinkMatchingTicket()
    {
        var credentialService = new ValidatedExternalCredentialLinkServiceMock();
        credentialService
            .Setup(s => s.LinkValidatedExternalCredentialAsync(It.IsAny<InternalValidatedExternalCredentialLinkRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success());
        var service = CreateService(credentialService.Object);
        var ticket = AuthenticateResult.Success(new AuthenticationTicket(
            CreatePrincipal("sub"),
            CreateProperties("Google", "Google"),
            "Ashlar.OAuth.External"));

        var result = await service.LinkWithFreshProofAsync(Guid.NewGuid(), "Google", ticket, TenantContext.Global);

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Linked));
    }

    [Test]
    public void LinkExternalAccountFromAuthenticateResultShouldRejectNullResult()
    {
        var service = CreateService();

        Assert.ThrowsAsync<ArgumentNullException>(() => service.LinkWithFreshProofAsync(Guid.NewGuid(), "Google", (AuthenticateResult)null!, TenantContext.Global));
    }

    [Test]
    public async Task LinkExternalAccountFromAuthenticateResultShouldReturnUnsupportedProvider()
    {
        var service = CreateService();
        var ticket = AuthenticateResult.Success(new AuthenticationTicket(
            CreatePrincipal("sub"),
            CreateProperties("Google", "Google"),
            "Ashlar.OAuth.External"));

        var result = await service.LinkWithFreshProofAsync(Guid.NewGuid(), "Microsoft", ticket, TenantContext.Global);

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.UnsupportedProvider));
    }

    [Test]
    public async Task LinkExternalAccountFromAuthenticateResultShouldReturnAuthenticationFailedForFailedTicket()
    {
        var service = CreateService();

        var result = await service.LinkWithFreshProofAsync(Guid.NewGuid(), "Google", AuthenticateResult.Fail("failed"), TenantContext.Global);

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

        var result = await service.LinkWithFreshProofAsync(Guid.NewGuid(), "Google", ticket, TenantContext.Global);

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

        var result = await service.LinkWithFreshProofAsync(Guid.NewGuid(), "Google", ticket, TenantContext.Global);

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

        var result = await service.CompleteWithFreshProofAsync(CreateHttpContext(authService), Guid.NewGuid(), "Google", TenantContext.Global);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.ProviderMismatch));
            Assert.That(authService.SignOutCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task CompleteExternalLinkShouldLinkMatchingTicket()
    {
        var userId = Guid.NewGuid();
        AuditContext? observedAudit = null;
        var credentialService = new ValidatedExternalCredentialLinkServiceMock();
        credentialService
            .Setup(s => s.LinkValidatedExternalCredentialAsync(It.Is<InternalValidatedExternalCredentialLinkRequest>(r => r.UserId == userId), It.IsAny<CancellationToken>()))
            .Callback<InternalValidatedExternalCredentialLinkRequest, CancellationToken>((request, _) => observedAudit = request.Audit)
            .ReturnsAsync(Result.Success());
        var authService = new TestAuthenticationService(AuthenticateResult.Success(new AuthenticationTicket(
            CreatePrincipal("sub"),
            CreateProperties("Google", "Google"),
            "Ashlar.OAuth.External")));
        var service = CreateService(credentialService.Object);
        var httpContext = CreateHttpContext(authService);
        httpContext.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("203.0.113.20");

        var result = await service.CompleteWithFreshProofAsync(httpContext, userId, "Google", TenantContext.Global);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.Linked));
            Assert.That(authService.SignOutCount, Is.EqualTo(1));
            Assert.That(observedAudit?.IpAddress, Is.EqualTo("203.0.113.20"));
        }
    }

    [Test]
    public async Task CompleteExternalLinkShouldMapCredentialLinkFailure()
    {
        var credentialService = new ValidatedExternalCredentialLinkServiceMock();
        credentialService
            .Setup(s => s.LinkValidatedExternalCredentialAsync(It.IsAny<InternalValidatedExternalCredentialLinkRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure(AshlarFailureCodes.AlreadyLinkedToOther));
        var authService = new TestAuthenticationService(AuthenticateResult.Success(new AuthenticationTicket(
            CreatePrincipal("sub"),
            CreateProperties("Google", "Google"),
            "Ashlar.OAuth.External")));
        var service = CreateService(credentialService.Object);

        var result = await service.CompleteWithFreshProofAsync(CreateHttpContext(authService), Guid.NewGuid(), "Google", TenantContext.Global);

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountLinkStatus.AlreadyLinkedToAnotherUser));
    }

    [Test]
    public async Task CompleteExternalLinkShouldReturnAuthenticationFailedWhenTicketMissing()
    {
        var service = CreateService();
        var authService = new TestAuthenticationService(AuthenticateResult.NoResult());

        var result = await service.CompleteWithFreshProofAsync(CreateHttpContext(authService), Guid.NewGuid(), "Google", TenantContext.Global);

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
        var accountSecurity = CreateAccountSecurityService(
            Result.Success(new AccountSecurityOperationResult(userId, CredentialsRevoked: 1)));
        var request = CreateRequest(tenant, userId);
        var service = CreateService(accountSecurityService: accountSecurity);

        var result = await service.UnlinkWithFreshProofAsync(userId, "Google", request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Unlinked));
            Assert.That(result.AccountSecurityOperation?.Value?.CredentialsRevoked, Is.EqualTo(1));
            Assert.That(accountSecurity.Request!.Audit, Is.SameAs(request.Audit));
            Assert.That(accountSecurity.Request.Tenant, Is.EqualTo(request.Tenant));
        }
    }

    [TestCase("")]
    [TestCase(" ")]
    [TestCase("Microsoft")]
    public async Task UnlinkExternalAccountShouldReturnUnsupportedProviderForBlankOrMissingProvider(string providerName)
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService();
        var service = CreateService(accountSecurityService: accountSecurity);

        var result = await service.UnlinkWithFreshProofAsync(userId, providerName, CreateRequest(actorUserId: userId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.UnsupportedProvider));
            Assert.That(accountSecurity.RevokeCredentialsCallCount, Is.Zero);
        }
    }

    [Test]
    public async Task UnlinkExternalAccountShouldRequireProofBeforeRevealingUnsupportedProvider()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService();
        var service = CreateService(accountSecurityService: accountSecurity);

        var result = await service.UnlinkExternalAccountAsync(
            userId, "NotConfigured", null, null, CreateRequest(actorUserId: userId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Failed));
            Assert.That(accountSecurity.RevokeCredentialsCallCount, Is.Zero);
        }
    }

    [Test]
    public async Task UnlinkExternalAccountShouldReturnUserNotFoundForMissingUser()
    {
        var userId = Guid.NewGuid();
        var service = CreateService(accountSecurityService: CreateAccountSecurityService(revokeResult:
            Result.Failure<AccountSecurityOperationResult>(AshlarFailureCodes.UserNotFound)));

        var result = await service.UnlinkWithFreshProofAsync(userId, "Google", CreateRequest(actorUserId: userId));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.UserNotFound));
    }

    [Test]
    public async Task UnlinkExternalAccountShouldReturnUserNotFoundForEmptyCurrentUser()
    {
        var service = CreateService();

        var result = await service.UnlinkWithFreshProofAsync(Guid.Empty, "Google", CreateRequest());

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Failed));
    }

    [Test]
    public async Task UnlinkExternalAccountShouldUseConfiguredClockForFreshProof()
    {
        var now = new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var timeProvider = new FixedTimeProvider(now);
        var userId = Guid.NewGuid();
        var tenant = new TenantContext(Guid.NewGuid());
        var sessionId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(revokeResult:
            Result.Success(new AccountSecurityOperationResult(userId, CredentialsRevoked: 1)));
        var service = CreateService(accountSecurityService: accountSecurity, timeProvider: timeProvider);

        var result = await service.UnlinkExternalAccountAsync(userId, "Google",
            ExternalAccountLinkServiceTestExtensions.CreateProof(userId, tenant, sessionId, "external-account-unlinking", now, registerSession: true), sessionId,
            CreateRequest(tenant, userId));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Unlinked));
    }

    [Test]
    public async Task UnlinkExternalAccountShouldRejectAuditActorMismatch()
    {
        var currentUserId = Guid.NewGuid();
        var events = new Mock<ISecurityEventSink>();
        var service = CreateService(securityEventSink: events.Object);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        var result = await service.UnlinkWithFreshProofAsync(currentUserId, "Google", CreateRequest(), cancellation.Token);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Failed));
            events.Verify(sink => sink.RecordAsync(It.Is<AshlarSecurityEvent>(securityEvent =>
                securityEvent.EventType == AshlarSecurityEventTypes.UserCredentialsRevoked &&
                securityEvent.Outcome == SecurityEventOutcomes.Failure &&
                securityEvent.UserId == currentUserId &&
                securityEvent.ActorUserId == currentUserId &&
                securityEvent.FailureReason == AshlarFailureCodes.ValidationErrorValue), CancellationToken.None), Times.Once);
        }
    }

    [Test]
    public async Task UnlinkExternalAccountShouldReturnTenantMismatch()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(revokeResult:
            Result.Failure<AccountSecurityOperationResult>(AshlarFailureCodes.TenantMismatch));
        var service = CreateService(accountSecurityService: accountSecurity);

        var result = await service.UnlinkWithFreshProofAsync(userId, "Google", CreateRequest(new TenantContext(Guid.NewGuid()), userId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.TenantMismatch));
            Assert.That(accountSecurity.RevokeCredentialsCallCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task UnlinkExternalAccountShouldReturnNotLinkedWhenConfiguredProviderIsAbsent()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(revokeResult:
            Result.Success(new AccountSecurityOperationResult(userId, CredentialsRevoked: 0)));
        var service = CreateService(accountSecurityService: accountSecurity);

        var result = await service.UnlinkWithFreshProofAsync(userId, "Google", CreateRequest(actorUserId: userId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.NotLinked));
            Assert.That(accountSecurity.RevokeCredentialsCallCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task UnlinkExternalAccountShouldOnlyRevokeConfiguredOidcProvider()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(
            Result.Success(new AccountSecurityOperationResult(userId, CredentialsRevoked: 1)));
        var events = new Mock<ISecurityEventSink>();
        var service = CreateService(accountSecurityService: accountSecurity, securityEventSink: events.Object);

        var result = await service.UnlinkWithFreshProofAsync(userId, "Google", CreateRequest(actorUserId: userId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Unlinked));
            Assert.That(accountSecurity.RevokeCredentialsCallCount, Is.EqualTo(1));
            Assert.That(accountSecurity.Provider, Is.EqualTo(new AuthenticationProviderKey(ProviderType.Oidc, "Google")));
        }
    }

    [Test]
    public async Task UnlinkExternalAccountShouldPreventRemovingLastUsablePrimaryCredential()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(revokeResult:
            Result.Failure<AccountSecurityOperationResult>(AshlarFailureCodes.LastPrimarySignInMethod));
        var service = CreateService(accountSecurityService: accountSecurity);

        var result = await service.UnlinkWithFreshProofAsync(userId, "Google", CreateRequest(actorUserId: userId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.WouldRemoveLastSignInMethod));
            Assert.That(accountSecurity.Request?.PreservePrimarySignInMethod, Is.True);
        }
    }

    [Test]
    public async Task UnlinkExternalAccountShouldRequireFreshMfaBeforeMutation()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(
            Result.Success(new AccountSecurityOperationResult(userId, CredentialsRevoked: 1)));
        var events = new Mock<ISecurityEventSink>();
        var service = CreateService(accountSecurityService: accountSecurity, securityEventSink: events.Object);

        var result = await service.UnlinkExternalAccountAsync(userId, "Google", null, null, CreateRequest(actorUserId: userId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Failed));
            Assert.That(accountSecurity.RevokeCredentialsCallCount, Is.Zero);
            events.Verify(s => s.RecordAsync(It.Is<AshlarSecurityEvent>(e =>
                e.EventType == AshlarSecurityEventTypes.UserCredentialsRevoked && e.Outcome == SecurityEventOutcomes.Failure &&
                e.UserId == userId && e.ActorUserId == userId && e.FailureReason == AshlarFailureCodes.StepUpRequiredValue &&
                e.Provider == null), It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [TestCase(true, AshlarExternalAccountUnlinkStatus.Unlinked, 1)]
    [TestCase(false, AshlarExternalAccountUnlinkStatus.Failed, 0)]
    public async Task UnlinkExternalAccountShouldRequireActiveSourceSessionBeforeMutation(
        bool sourceSessionExists, AshlarExternalAccountUnlinkStatus expectedStatus, int expectedMutations)
    {
        var now = DateTimeOffset.UtcNow;
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var session = new AuthenticationSession
        {
            Id = sessionId,
            UserId = userId,
            TokenHash = "hash",
            CreatedAt = now,
            AdditionalVerificationAt = now,
            ExpiresAt = now.AddHours(1)
        };
        var sessions = new Mock<IAuthenticationSessionRepository>();
        sessions.Setup(repository => repository.GetSessionAsync(sessionId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(sourceSessionExists ? session : null);
        var executor = CreateAccountSecurityService(revokeResult:
            Result.Success(new AccountSecurityOperationResult(userId, CredentialsRevoked: 1)));
        var clock = new FixedTimeProvider(now);
        var service = CreateService(accountSecurityService: executor, timeProvider: clock,
            proofValidator: new ActiveSessionFreshProofValidator(sessions.Object, clock));

        var result = await service.UnlinkExternalAccountAsync(userId, "Google",
            ExternalAccountLinkServiceTestExtensions.CreateProof(userId, TenantContext.Global, sessionId, "external-account-unlinking", now),
            sessionId, CreateRequest(actorUserId: userId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(expectedStatus));
            Assert.That(executor.RevokeCredentialsCallCount, Is.EqualTo(expectedMutations));
        }
    }

    [Test]
    public async Task UnlinkExternalAccountShouldRejectDifferentSessionReturnedForSourceSessionLookup()
    {
        var now = DateTimeOffset.UtcNow;
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var sessions = new Mock<IAuthenticationSessionRepository>();
        sessions.Setup(repository => repository.GetSessionAsync(sessionId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationSession
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                TokenHash = "hash",
                CreatedAt = now,
                AdditionalVerificationAt = now,
                ExpiresAt = now.AddHours(1)
            });
        var executor = CreateAccountSecurityService();
        var clock = new FixedTimeProvider(now);
        var service = CreateService(accountSecurityService: executor, timeProvider: clock,
            proofValidator: new ActiveSessionFreshProofValidator(sessions.Object, clock));

        var result = await service.UnlinkExternalAccountAsync(userId, "Google",
            ExternalAccountLinkServiceTestExtensions.CreateProof(userId, TenantContext.Global, sessionId, "external-account-unlinking", now),
            sessionId, CreateRequest(actorUserId: userId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Failed));
            Assert.That(executor.RevokeCredentialsCallCount, Is.Zero);
        }
    }

    [Test]
    public async Task UnlinkExternalAccountShouldRejectAccountSecurityAdministrationProof()
    {
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var executor = CreateAccountSecurityService();
        var service = CreateService(accountSecurityService: executor);

        var result = await service.UnlinkExternalAccountAsync(userId, "Google",
            ExternalAccountLinkServiceTestExtensions.CreateProof(userId, TenantContext.Global, sessionId, "account-security-administration"),
            sessionId, CreateRequest(actorUserId: userId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Failed));
            Assert.That(executor.RevokeCredentialsCallCount, Is.Zero);
        }
    }

    [TestCase("expired")]
    [TestCase("wrong-user")]
    [TestCase("wrong-tenant")]
    [TestCase("wrong-session")]
    [TestCase("wrong-purpose")]
    public async Task UnlinkExternalAccountShouldRejectInvalidFreshMfaProofBeforeMutation(string proofCase)
    {
        var userId = Guid.NewGuid();
        var tenant = TenantContext.Global;
        var sessionId = Guid.NewGuid();
        var proofUserId = proofCase == "wrong-user" ? Guid.NewGuid() : userId;
        var proofTenant = proofCase == "wrong-tenant" ? new TenantContext(Guid.NewGuid()) : tenant;
        var proofSessionId = proofCase == "wrong-session" ? Guid.NewGuid() : sessionId;
        var purpose = proofCase == "wrong-purpose" ? "external-account-linking" : "external-account-unlinking";
        var verifiedAt = proofCase == "expired" ? DateTimeOffset.UtcNow.AddMinutes(-20) : DateTimeOffset.UtcNow;
        var proof = ExternalAccountLinkServiceTestExtensions.CreateProof(proofUserId, proofTenant, proofSessionId, purpose, verifiedAt, TimeSpan.FromMinutes(10));
        var accountSecurity = CreateAccountSecurityService(
            Result.Success(new AccountSecurityOperationResult(userId, CredentialsRevoked: 1)));
        var events = new Mock<ISecurityEventSink>();
        var service = CreateService(accountSecurityService: accountSecurity, securityEventSink: events.Object);

        var result = await service.UnlinkExternalAccountAsync(userId, "Google", proof, sessionId, CreateRequest(tenant, userId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Failed));
            Assert.That(accountSecurity.RevokeCredentialsCallCount, Is.Zero);
            events.Verify(s => s.RecordAsync(It.Is<AshlarSecurityEvent>(e =>
                e.EventType == AshlarSecurityEventTypes.UserCredentialsRevoked && e.Outcome == SecurityEventOutcomes.Failure &&
                e.UserId == userId && e.ActorUserId == userId && e.TenantId == null &&
                e.Provider == null && e.FailureReason != null),
                It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [Test]
    public async Task UnlinkExternalAccountShouldReturnNotLinkedWhenRevocationFindsNoCredentials()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(Result.Success(new AccountSecurityOperationResult(userId)));
        var service = CreateService(accountSecurityService: accountSecurity);

        var result = await service.UnlinkWithFreshProofAsync(userId, "Google", CreateRequest(actorUserId: userId));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.NotLinked));
    }

    [Test]
    public async Task UnlinkExternalAccountShouldFailWhenRevocationFails()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(Result.Failure<AccountSecurityOperationResult>(AshlarFailureCodes.ValidationError));
        var service = CreateService(accountSecurityService: accountSecurity);

        var result = await service.UnlinkWithFreshProofAsync(userId, "Google", CreateRequest(actorUserId: userId));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Failed));
    }

    [Test]
    public async Task UnlinkExternalAccountShouldMapAccountSecurityFailures()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(
            Result.Failure<AccountSecurityOperationResult>(AshlarFailureCodes.UserNotFound));
        var service = CreateService(accountSecurityService: accountSecurity);

        var result = await service.UnlinkWithFreshProofAsync(userId, "Google", CreateRequest(actorUserId: userId));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.UserNotFound));
    }

    [Test]
    public async Task UnlinkExternalAccountShouldReturnFailedForUnknownRevocationFailure()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(
            Result.Failure<AccountSecurityOperationResult>(AshlarFailureCodes.ValidationError));
        var service = CreateService(accountSecurityService: accountSecurity);

        var result = await service.UnlinkWithFreshProofAsync(userId, "Google", CreateRequest(actorUserId: userId));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Failed));
    }

    [Test]
    public async Task UnlinkExternalAccountShouldReturnFailedForRevocationFailureWithoutDetails()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(Result.Failure<AccountSecurityOperationResult>(AshlarFailureCodes.ValidationError));
        var service = CreateService(accountSecurityService: accountSecurity);

        var result = await service.UnlinkWithFreshProofAsync(userId, "Google", CreateRequest(actorUserId: userId));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Failed));
    }

    [Test]
    public async Task UnlinkExternalAccountShouldAllowGlobalTenantForGlobalUser()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(
            Result.Success(new AccountSecurityOperationResult(userId, CredentialsRevoked: 1)));
        var service = CreateService(accountSecurityService: accountSecurity);

        var result = await service.UnlinkWithFreshProofAsync(userId, "Google", CreateRequest(TenantContext.Global, userId));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Unlinked));
    }

    [Test]
    public async Task UnlinkExternalAccountShouldRejectGlobalTenantForTenantScopedUser()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(revokeResult: Result.Failure<AccountSecurityOperationResult>(AshlarFailureCodes.TenantMismatch));
        var service = CreateService(accountSecurityService: accountSecurity);

        var result = await service.UnlinkWithFreshProofAsync(userId, "Google", CreateRequest(TenantContext.Global, userId));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.TenantMismatch));
    }

    [Test]
    public async Task UnlinkExternalAccountShouldAllowGlobalTenantForTenantUserWithoutTenant()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(
            Result.Success(new AccountSecurityOperationResult(userId, CredentialsRevoked: 1)));
        var service = CreateService(accountSecurityService: accountSecurity);

        var result = await service.UnlinkWithFreshProofAsync(userId, "Google", CreateRequest(TenantContext.Global, userId));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Unlinked));
    }

    [Test]
    public async Task UnlinkExternalAccountShouldRejectScopedTenantForTenantUserWithoutTenant()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(revokeResult: Result.Failure<AccountSecurityOperationResult>(AshlarFailureCodes.TenantMismatch));
        var service = CreateService(accountSecurityService: accountSecurity);

        var result = await service.UnlinkWithFreshProofAsync(userId, "Google", CreateRequest(new TenantContext(Guid.NewGuid()), userId));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.TenantMismatch));
    }

    [Test]
    public async Task UnlinkExternalAccountShouldRejectScopedTenantForGlobalUser()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(revokeResult: Result.Failure<AccountSecurityOperationResult>(AshlarFailureCodes.TenantMismatch));
        var service = CreateService(accountSecurityService: accountSecurity);

        var result = await service.UnlinkWithFreshProofAsync(userId, "Google", CreateRequest(new TenantContext(Guid.NewGuid()), userId));

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.TenantMismatch));
    }

    [Test]
    public async Task UnlinkExternalAccountShouldRevokeGitHubOAuthCredentials()
    {
        var userId = Guid.NewGuid();
        var accountSecurity = CreateAccountSecurityService(
            Result.Success(new AccountSecurityOperationResult(userId, CredentialsRevoked: 1)));
        var service = CreateService(accountSecurityService: accountSecurity, includeGitHub: true);

        var result = await service.UnlinkWithFreshProofAsync(userId, "GitHub", CreateRequest(actorUserId: userId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAccountUnlinkStatus.Unlinked));
            Assert.That(accountSecurity.Provider, Is.EqualTo(new AuthenticationProviderKey(ProviderType.OAuth, "GitHub")));
        }
    }

    [Test]
    public void UnlinkExternalAccountShouldRejectNullRequestBeforeOtherValidation()
    {
        var accountSecurity = CreateAccountSecurityService();
        var service = CreateService(accountSecurityService: accountSecurity);

        Assert.ThrowsAsync<ArgumentNullException>(() => service.UnlinkExternalAccountAsync(Guid.Empty, "Microsoft", null, null, null!));
        Assert.That(accountSecurity.RevokeCredentialsCallCount, Is.Zero);
    }

    private static AshlarExternalAccountLinkService CreateService(
        IValidatedExternalCredentialLinkService? credentialService = null,
        IAccountSecurityMutationExecutor? accountSecurityService = null,
        bool includeGitHub = false,
        Action<AshlarOAuthOptions>? configureOptions = null,
        TimeProvider? timeProvider = null,
        ISecurityEventSink? securityEventSink = null,
        ActiveSessionFreshProofValidator? proofValidator = null)
    {
        var options = new AshlarOAuthOptions();
        options.AddOidcProvider("Google", _ => { });
        if (includeGitHub)
        {
            options.AddGitHub();
        }

        configureOptions?.Invoke(options);

        if (credentialService == null)
        {
            var credentials = new ValidatedExternalCredentialLinkServiceMock();
            credentials.Setup(s => s.LinkValidatedExternalCredentialAsync(
                    It.IsAny<InternalValidatedExternalCredentialLinkRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result.Success());
            credentialService = credentials.Object;
        }

        return new AshlarExternalAccountLinkService(
            credentialService,
            proofValidator ?? CreateUnlinkProofValidator(timeProvider ?? TimeProvider.System),
            accountSecurityService ?? CreateAccountSecurityService(),
            new TestOptionsMonitor(options),
            timeProvider ?? TimeProvider.System,
            securityEventSink);
    }

    private static AshlarExternalAccountLinkService CreateServiceWithProvider(AshlarOidcProviderOptions provider)
    {
        var options = new AshlarOAuthOptions();
        var providers = (Dictionary<string, AshlarOidcProviderOptions>)typeof(AshlarOAuthOptions)
            .GetField("_oidcProviders", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
            .GetValue(options)!;
        providers["Google"] = provider;

        return new AshlarExternalAccountLinkService(
            new ValidatedExternalCredentialLinkServiceMock().Object,
            CreateUnlinkProofValidator(TimeProvider.System),
            CreateAccountSecurityService(),
            new TestOptionsMonitor(options),
            TimeProvider.System);
    }

    private static TestAccountSecurityMutationExecutor CreateAccountSecurityService(Result<AccountSecurityOperationResult>? revokeResult = null)
    {
        return new TestAccountSecurityMutationExecutor(
            revokeResult ?? Result.Success(new AccountSecurityOperationResult(Guid.NewGuid(), CredentialsRevoked: 1)));
    }

    private static ActiveSessionFreshProofValidator CreateUnlinkProofValidator(TimeProvider timeProvider)
    {
        var sessions = new Mock<IAuthenticationSessionRepository>();
        sessions.Setup(repository => repository.GetSessionAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Guid sessionId, CancellationToken _) => ExternalAccountLinkServiceTestExtensions.TakeSession(sessionId));
        return new ActiveSessionFreshProofValidator(sessions.Object, timeProvider);
    }


    private static AshlarExternalAccountUnlinkRequest CreateRequest(TenantContext? tenant = null, Guid? actorUserId = null)
    {
        return new AshlarExternalAccountUnlinkRequest(new AuditContext(actorUserId ?? Guid.NewGuid(), "127.0.0.1", "NUnit", "corr"), tenant ?? TenantContext.Global, "unlink");
    }

    private static ClaimsPrincipal CreatePrincipal(string subject, string email = "person@example.com", bool tokenClaims = false)
    {
        var claims = new List<Claim> { new("iss", "https://issuer.example"), new("sub", subject), new("email", email) };
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

    internal sealed class TestAuthenticationService(AuthenticateResult result, Exception? authenticateException = null, Exception? signOutException = null) : IAuthenticationService
    {
        public int AuthenticateCount { get; private set; }
        public int SignOutCount { get; private set; }
        public void BindLinkingTicket(Guid userId, Guid sessionId)
        {
            if (result.Properties == null) return;
            var binding = AshlarExternalAccountLinkService.CreateExternalLinkChallengeProperties(
                userId, sessionId, "/account/external/link/callback?tab=security#linked");
            foreach (var item in binding.Items) result.Properties.Items[item.Key] = item.Value;
            result.Properties.RedirectUri = binding.RedirectUri;
        }
        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme)
        {
            AuthenticateCount++;
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
            if (signOutException != null)
            {
                throw signOutException;
            }

            return Task.CompletedTask;
        }
    }

    private sealed class TestAccountSecurityMutationExecutor(Result<AccountSecurityOperationResult> result) : IAccountSecurityMutationExecutor
    {
        public int RevokeCredentialsCallCount { get; private set; }
        public Guid UserId { get; private set; }
        public AuthenticationProviderKey Provider { get; private set; }
        public AccountSecurityOperationRequest? Request { get; private set; }

        public Task<Result<AccountSecurityOperationResult>> RevokeCredentialsAsync(Guid userId, AuthenticationProviderKey provider,
            AccountSecurityOperationRequest request, CancellationToken cancellationToken = default)
        {
            RevokeCredentialsCallCount++;
            UserId = userId;
            Provider = provider;
            Request = request;
            return Task.FromResult(result);
        }

        public Task<Result<AccountSecurityOperationResult>> SetUserAccountStateAsync(Guid userId, SetUserAccountStateRequest request, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<Result<AccountSecurityOperationResult>> RevokeSessionsAsync(Guid userId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<Result<AccountSecurityOperationResult>> ResetMfaAsync(Guid userId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<Result<AccountSecurityOperationResult>> RevokeRememberedMfaDeviceAsync(Guid userId, Guid deviceId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<Result<AccountSecurityOperationResult>> RevokeRememberedMfaDevicesAsync(Guid userId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }
}

internal static class ExternalAccountLinkServiceTestExtensions
{
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, AuthenticationSession> Sessions = new();

    internal static AuthenticationSession? TakeSession(Guid sessionId) =>
        Sessions.TryRemove(sessionId, out var session) ? session : null;

    public static Task<AshlarExternalAccountLinkResult> LinkWithFreshProofAsync(
        this AshlarExternalAccountLinkService service,
        Guid currentUserId,
        string providerName,
        AuthenticateResult authenticateResult,
        TenantContext tenant,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authenticateResult);
        var sessionId = Guid.NewGuid();
        var authentication = new AshlarExternalAccountLinkServiceTests.TestAuthenticationService(authenticateResult);
        authentication.BindLinkingTicket(currentUserId, sessionId);
        var services = new ServiceCollection();
        services.AddSingleton<IAuthenticationService>(authentication);
        var httpContext = new DefaultHttpContext { RequestServices = services.BuildServiceProvider() };
        return service.CompleteExternalLinkAsync(
            httpContext,
            currentUserId,
            providerName,
            CreateProof(currentUserId, tenant, sessionId),
            sessionId,
            tenant,
            cancellationToken);
    }

    public static Task<AshlarExternalAccountLinkResult> CompleteWithFreshProofAsync(
        this AshlarExternalAccountLinkService service,
        HttpContext httpContext,
        Guid currentUserId,
        string providerName,
        TenantContext tenant,
        CancellationToken cancellationToken = default)
    {
        var sessionId = Guid.NewGuid();
        if (httpContext != null && httpContext.RequestServices.GetService<IAuthenticationService>() is AshlarExternalAccountLinkServiceTests.TestAuthenticationService authenticationService)
        {
            authenticationService.BindLinkingTicket(currentUserId, sessionId);
        }
        return service.CompleteExternalLinkAsync(
            httpContext!,
            currentUserId,
            providerName,
            CreateProof(currentUserId, tenant, sessionId),
            sessionId,
            tenant,
            cancellationToken);
    }

    public static Task<AshlarExternalAccountUnlinkResult> UnlinkWithFreshProofAsync(
        this AshlarExternalAccountLinkService service,
        Guid currentUserId,
        string providerName,
        AshlarExternalAccountUnlinkRequest request,
        CancellationToken cancellationToken = default)
    {
        var sessionId = Guid.NewGuid();
        var tenant = request.Tenant ?? TenantContext.Global;
        return service.UnlinkExternalAccountAsync(
            currentUserId,
            providerName,
            CreateProof(currentUserId, tenant, sessionId, "external-account-unlinking", registerSession: true),
            sessionId,
            request,
            cancellationToken);
    }

    public static FreshMfaVerificationProof CreateProof(
        Guid userId,
        TenantContext? tenant,
        Guid sessionId,
        string purpose = "external-account-linking",
        DateTimeOffset? verifiedAt = null,
        TimeSpan? freshnessWindow = null,
        bool registerSession = true)
    {
        var resolvedVerifiedAt = verifiedAt ?? DateTimeOffset.UtcNow;
        var resolvedFreshnessWindow = freshnessWindow ?? TimeSpan.FromMinutes(10);
        var session = new AuthenticationSession
        {
            Id = sessionId,
            UserId = userId,
            TenantId = (tenant ?? TenantContext.Global).TenantId,
            TokenHash = "hash",
            CreatedAt = resolvedVerifiedAt,
            AdditionalVerificationAt = resolvedVerifiedAt,
            ExpiresAt = resolvedVerifiedAt.AddHours(1)
        };
        if (registerSession)
        {
            Sessions[sessionId] = session;
        }
        var validatedSession = (ValidatedAuthenticationSession)Activator.CreateInstance(
            typeof(ValidatedAuthenticationSession),
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic,
            binder: null,
            args: [session],
            culture: null)!;
        return new StepUpAuthenticationService(new FixedTimeProvider(resolvedVerifiedAt))
            .CreateFreshMfaProof(validatedSession, new StepUpRequirement(resolvedFreshnessWindow), purpose).Value!;
    }

}

internal sealed class FixedTimeProvider(DateTimeOffset utcNow) : TimeProvider
{
    public override DateTimeOffset GetUtcNow() => utcNow;
}
