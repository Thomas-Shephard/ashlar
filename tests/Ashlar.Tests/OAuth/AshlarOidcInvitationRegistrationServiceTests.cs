using Ashlar.Testing;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Ashlar.Auditing;
using Ashlar.OAuth.Providers.Microsoft;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;

namespace Ashlar.Tests.OAuth;

internal sealed class AshlarOidcInvitationRegistrationServiceTests
{
    [Test]
    public async Task RegisterShouldAcceptInvitationAndLinkOidcCredential()
    {
        var userId = Guid.NewGuid();
        var invitations = CreateInvitations(acceptance: AcceptResult(userId));
        InternalValidatedExternalCredentialLinkRequest? observedRequest = null;
        var linker = new ValidatedExternalCredentialLinkServiceMock();
        linker.Setup(s => s.LinkValidatedExternalCredentialAsync(It.IsAny<InternalValidatedExternalCredentialLinkRequest>(), It.IsAny<CancellationToken>()))
            .Callback<InternalValidatedExternalCredentialLinkRequest, CancellationToken>((request, _) => observedRequest = request)
            .ReturnsAsync(Result.Success());
        var service = CreateService(invitations.Object, linkService: linker.Object);

        var result = await service.RegisterOidcInvitationAsync("token", "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("subject", "invitee@example.com", "true")), "Invitee");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.Registered));
            Assert.That(result.Registered, Is.True);
            Assert.That(result.UserId, Is.EqualTo(userId));
            Assert.That(result.Assertion?.ProviderKey, Is.EqualTo(CreateExpectedIssuerSubjectKey("https://issuer.example", "subject")));
            Assert.That(observedRequest?.ProviderKey, Is.EqualTo(result.Assertion?.ProviderKey));
            Assert.That(observedRequest?.UserId, Is.EqualTo(userId));
            Assert.That(result.Assertion?.Claims, Does.Not.ContainKey("access_token"));
            invitations.Verify(s => s.AcceptInvitationAsync(
                It.Is<AcceptInvitationRequest>(r => r.UserName == "Invitee"),
                It.IsAny<AuthenticationContext?>(),
                It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [Test]
    public async Task RegisterShouldPassAuditContextToCredentialLinker()
    {
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var invitations = CreateInvitations(
            preview: Result.Success(new InvitationAcceptancePreview("invitee@example.com", tenantId)),
            acceptance: AcceptResult(userId));
        InternalValidatedExternalCredentialLinkRequest? observedRequest = null;
        var linker = new ValidatedExternalCredentialLinkServiceMock();
        linker.Setup(s => s.LinkValidatedExternalCredentialAsync(It.IsAny<InternalValidatedExternalCredentialLinkRequest>(), It.IsAny<CancellationToken>()))
            .Callback<InternalValidatedExternalCredentialLinkRequest, CancellationToken>((request, _) => observedRequest = request)
            .ReturnsAsync(Result.Success());
        var context = new AuthenticationContext(UserId: userId, TenantId: tenantId, IpAddress: "203.0.113.10", UserAgent: "agent", CorrelationId: "corr");
        var service = CreateService(invitations.Object, linkService: linker.Object);

        var result = await service.RegisterOidcInvitationAsync(
            "token",
            "Google",
            AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("subject", "invitee@example.com", "true")),
            context: context);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.Registered));
            Assert.That(observedRequest?.UserId, Is.EqualTo(userId));
            Assert.That(observedRequest?.TenantId, Is.EqualTo(tenantId));
            Assert.That(observedRequest?.Audit, Is.EqualTo(new AuditContext(userId, "203.0.113.10", "agent", "corr")));
        }
    }

    [Test]
    public async Task RegisterShouldNotInferDisplayNameFromPrincipal()
    {
        var userId = Guid.NewGuid();
        AcceptInvitationRequest? observedRequest = null;
        var invitations = CreateInvitations(acceptance: AcceptResult(userId));
        invitations.Setup(s => s.AcceptInvitationAsync(It.Is<AcceptInvitationRequest>(r => r.Token == "token"), It.IsAny<AuthenticationContext?>(), It.IsAny<CancellationToken>()))
            .Callback<AcceptInvitationRequest, AuthenticationContext?, CancellationToken>((request, _, _) => observedRequest = request)
            .ReturnsAsync(AcceptResult(userId));
        var service = CreateService(invitations.Object);
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("iss", "https://issuer.example"),
            new Claim("sub", "subject"),
            new Claim("name", "Principal Name"),
            new Claim("email", "invitee@example.com"),
            new Claim("email_verified", "true")
        ], "oidc"));

        var result = await service.RegisterOidcInvitationAsync("token", "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, principal));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.Registered));
            Assert.That(observedRequest?.UserName, Is.Null);
        }
    }

    [Test]
    public void ConstructorShouldRejectNullDependencies()
    {
        var invitations = Mock.Of<IInvitationService>();
        var linker = new ValidatedExternalCredentialLinkServiceMock().Object;
        var transactions = DurableTransactionComposition.Create(CreateTransactionProvider().Object);
        var oauth = new TestOptionsMonitor(CreateOptions());
        var emailPolicy = Mock.Of<IOidcInvitationEmailMatchPolicy>();

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => { _ = new AshlarOidcInvitationRegistrationService(null!, linker, transactions, oauth, emailPolicy); });
            Assert.Throws<ArgumentNullException>(() => new AshlarOidcInvitationRegistrationService(invitations, null!, transactions, oauth, emailPolicy));
            Assert.Throws<ArgumentNullException>(() => { _ = new AshlarOidcInvitationRegistrationService(invitations, linker, null!, oauth, emailPolicy); });
            Assert.Throws<ArgumentNullException>(() => { _ = new AshlarOidcInvitationRegistrationService(invitations, linker, transactions, null!, emailPolicy); });
            Assert.Throws<ArgumentNullException>(() => { _ = new AshlarOidcInvitationRegistrationService(invitations, linker, transactions, oauth, null!); });
            Assert.Throws<ArgumentException>(() => new MicrosoftOidcInvitationEmailMatchPolicy(" ", new StandardOidcVerifiedEmailMatchPolicy()));
            Assert.Throws<ArgumentNullException>(() => new MicrosoftOidcInvitationEmailMatchPolicy("Microsoft", null!));
            Assert.Throws<ArgumentException>(() => new MicrosoftOidcInvitationEmailMatchPolicy("Microsoft", new StandardOidcVerifiedEmailMatchPolicy(), [" "]));
        }
    }

    [Test]
    public void RegisteredConveniencePropertyShouldReflectStatus()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(new AshlarOidcInvitationRegistrationResult(AshlarOidcInvitationRegistrationStatus.Registered).Registered, Is.True);
            Assert.That(new AshlarOidcInvitationRegistrationResult(AshlarOidcInvitationRegistrationStatus.LinkFailed).Registered, Is.False);
            Assert.That(OidcInvitationEmailMatchResult.InvalidPrincipal().Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.InvalidPrincipal));
            Assert.That(OidcInvitationEmailMatchResult.Failed().Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.Failed));
        }
    }

    [TestCase("")]
    [TestCase(" ")]
    [TestCase("Microsoft")]
    public async Task RegisterShouldReturnUnsupportedProvider(string providerName)
    {
        var service = CreateService();

        var result = await service.RegisterOidcInvitationAsync("token", providerName, AshlarOAuthTestTickets.CreateExternalTicket(providerName, providerName, ProviderType.Oidc, CreatePrincipal("subject", "invitee@example.com", "true")));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.UnsupportedProvider));
    }

    [Test]
    public async Task RegisterShouldReturnInvalidPrincipalForMissingSubject()
    {
        var service = CreateService();

        var result = await service.RegisterOidcInvitationAsync("token", "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal(null, "invitee@example.com", "true")));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.InvalidPrincipal));
    }

    [Test]
    public async Task RegisterShouldUseIssuerQualifiedProviderKeyWhenProviderRequiresIssuer()
    {
        var userId = Guid.NewGuid();
        var invitations = CreateInvitations(acceptance: AcceptResult(userId));
        InternalValidatedExternalCredentialLinkRequest? observedRequest = null;
        var linker = new ValidatedExternalCredentialLinkServiceMock();
        linker.Setup(s => s.LinkValidatedExternalCredentialAsync(It.IsAny<InternalValidatedExternalCredentialLinkRequest>(), It.IsAny<CancellationToken>()))
            .Callback<InternalValidatedExternalCredentialLinkRequest, CancellationToken>((request, _) => observedRequest = request)
            .ReturnsAsync(Result.Success());
        var service = CreateService(
            invitations.Object,
            linkService: linker.Object,
            provider: new AshlarOidcProviderOptions("Google", "Google", _ => { }));

        var result = await service.RegisterOidcInvitationAsync(
            "token",
            "Google",
            AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("subject", "invitee@example.com", "true", issuer: "https://issuer.example/tenant")));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.Registered));
            Assert.That(result.Assertion?.ProviderKey, Is.EqualTo(CreateExpectedIssuerSubjectKey("https://issuer.example/tenant", "subject")));
            Assert.That(observedRequest?.ProviderKey, Is.EqualTo(CreateExpectedIssuerSubjectKey("https://issuer.example/tenant", "subject")));
        }
    }

    [Test]
    public async Task RegisterShouldReturnInvalidPrincipalWhenIssuerQualifiedProviderKeyMissingIssuer()
    {
        var service = CreateService(provider: new AshlarOidcProviderOptions("Google", "Google", _ => { }));

        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "subject"), new Claim("email", "invitee@example.com"), new Claim("email_verified", "true")], "oidc"));
        var result = await service.RegisterOidcInvitationAsync("token", "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, principal));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.InvalidPrincipal));
    }

    [Test]
    public async Task RegisterShouldReturnInvalidPrincipalWhenConfiguredProviderNameIsInvalid()
    {
        var service = CreateService(provider: new AshlarOidcProviderOptions(" ", "Google", _ => { }));

        var result = await service.RegisterOidcInvitationAsync("token", "Google", CreateTicket(" ", "Google", "subject"));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.InvalidPrincipal));
    }

    [Test]
    public void RegisterShouldValidateRequiredArguments()
    {
        var service = CreateService();

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentNullException>(() => service.RegisterOidcInvitationAsync("token", "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, null!)));
            Assert.ThrowsAsync<ArgumentNullException>(() => service.RegisterOidcInvitationAsync("token", "Google", (AuthenticateResult)null!));
            Assert.ThrowsAsync<ArgumentNullException>(() => service.CompleteOidcInvitationRegistrationAsync(null!, "token", "Google"));
        }
    }

    [Test]
    public void RegisterShouldNotExposeRawClaimsPrincipalOrAuthenticateResultOverloadPublicly()
    {
        var methods = typeof(AshlarOidcInvitationRegistrationService).GetMethods(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public);

        Assert.That(methods, Has.None.Matches<System.Reflection.MethodInfo>(method =>
            method.GetParameters().Any(parameter => parameter.ParameterType == typeof(ClaimsPrincipal) || parameter.ParameterType == typeof(AuthenticateResult))));
    }

    [TestCase(null)]
    [TestCase(" ")]
    public async Task RegisterShouldReturnInvalidInvitationForMissingInvitationToken(string? token)
    {
        var invitations = CreateInvitations(preview: Result.Failure<InvitationAcceptancePreview>(AshlarFailureCodes.InvalidInvitation), token: token);
        var service = CreateService(invitations.Object);

        var result = await service.RegisterOidcInvitationAsync(token!, "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("subject", "invitee@example.com", "true")));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.InvalidInvitation));

        invitations.Verify(s => s.AcceptInvitationAsync(It.IsAny<AcceptInvitationRequest>(), It.IsAny<AuthenticationContext?>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task RegisterShouldReturnInvalidInvitationForOverlongInvitationToken()
    {
        var overlongToken = new string('a', 257);
        var invitations = CreateInvitations(preview: Result.Failure<InvitationAcceptancePreview>(AshlarFailureCodes.InvalidInvitation), token: overlongToken);
        var service = CreateService(invitations.Object);

        var result = await service.RegisterOidcInvitationAsync(overlongToken, "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("subject", "invitee@example.com", "true")));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.InvalidInvitation));
            Assert.That(result.Assertion?.ProviderKey, Is.EqualTo(CreateExpectedIssuerSubjectKey("https://issuer.example", "subject")));
        }

        invitations.Verify(s => s.AcceptInvitationAsync(It.IsAny<AcceptInvitationRequest>(), It.IsAny<AuthenticationContext?>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task RegisterShouldReturnInvalidInvitationWhenPreviewFails()
    {
        var invitations = CreateInvitations(preview: Result.Failure<InvitationAcceptancePreview>(AshlarFailureCodes.InvalidInvitation));
        var service = CreateService(invitations.Object);

        var result = await service.RegisterOidcInvitationAsync("token", "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("subject", "invitee@example.com", "true")));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.InvalidInvitation));
    }

    [Test]
    public async Task RegisterShouldReturnRateLimitedWhenPreviewIsRateLimited()
    {
        var invitations = CreateInvitations(preview: Result.Failure<InvitationAcceptancePreview>(AshlarFailureCodes.RateLimited));
        var service = CreateService(invitations.Object);

        var result = await service.RegisterOidcInvitationAsync("token", "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("subject", "invitee@example.com", "true")));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.RateLimited));
    }

    [Test]
    public async Task RegisterShouldReturnFailedWhenPreviewFailsWithoutCode()
    {
        var invitations = CreateInvitations(preview: new Result<InvitationAcceptancePreview>(false));
        var service = CreateService(invitations.Object);

        var result = await service.RegisterOidcInvitationAsync("token", "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("subject", "invitee@example.com", "true")));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.Failed));
    }

    [Test]
    public async Task RegisterShouldReturnInvalidInvitationWhenPreviewValueIsMissing()
    {
        var invitations = CreateInvitations(preview: Result.Success<InvitationAcceptancePreview>(null!));
        var service = CreateService(invitations.Object);

        var result = await service.RegisterOidcInvitationAsync("token", "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("subject", "invitee@example.com", "true")));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.InvalidInvitation));
    }

    [Test]
    public async Task RegisterShouldReturnInvalidInvitationWhenContextTenantDiffersFromInvitationTenant()
    {
        var invitationTenantId = Guid.NewGuid();
        var requestedTenantId = Guid.NewGuid();
        var invitations = CreateInvitations(preview: Result.Success(new InvitationAcceptancePreview("invitee@example.com", invitationTenantId)));
        var service = CreateService(invitations.Object);

        var result = await service.RegisterOidcInvitationAsync(
            "token",
            "Google",
            AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("subject", "invitee@example.com", "true")),
            context: new AuthenticationContext(TenantId: requestedTenantId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.InvalidInvitation));
            invitations.Verify(s => s.AcceptInvitationAsync(It.IsAny<AcceptInvitationRequest>(), It.IsAny<AuthenticationContext?>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task RegisterShouldReturnInvalidInvitationWhenContextTenantIsSetButInvitationIsGlobal()
    {
        var invitations = CreateInvitations(preview: Result.Success(new InvitationAcceptancePreview("invitee@example.com", null)));
        var service = CreateService(invitations.Object);

        var result = await service.RegisterOidcInvitationAsync(
            "token",
            "Google",
            AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("subject", "invitee@example.com", "true")),
            context: new AuthenticationContext(TenantId: Guid.NewGuid()));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.InvalidInvitation));
    }

    [Test]
    public async Task RegisterShouldAcceptInvitationWhenContextTenantMatchesInvitationTenant()
    {
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var invitations = CreateInvitations(
            preview: Result.Success(new InvitationAcceptancePreview("invitee@example.com", tenantId)),
            acceptance: AcceptResult(userId));
        var service = CreateService(invitations.Object);

        var result = await service.RegisterOidcInvitationAsync(
            "token",
            "Google",
            AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("subject", "invitee@example.com", "true")),
            context: new AuthenticationContext(TenantId: tenantId));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.Registered));
    }

    [Test]
    public async Task RegisterShouldAcceptInvitationWhenContextHasNoTenant()
    {
        var userId = Guid.NewGuid();
        var invitations = CreateInvitations(acceptance: AcceptResult(userId));
        var service = CreateService(invitations.Object);

        var result = await service.RegisterOidcInvitationAsync(
            "token",
            "Google",
            AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("subject", "invitee@example.com", "true")),
            context: new AuthenticationContext());

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.Registered));
    }

    [Test]
    public async Task RegisterShouldReturnEmailMismatch()
    {
        var service = CreateService();

        var result = await service.RegisterOidcInvitationAsync("token", "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("subject", "other@example.com", "true")));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.EmailMismatch));
    }

    [TestCase(null, true)]
    [TestCase(null, false)]
    [TestCase("false", true)]
    [TestCase("0", true)]
    public async Task RegisterShouldReturnEmailNotVerified(string? verified, bool includeEmail)
    {
        var service = CreateService();

        var result = await service.RegisterOidcInvitationAsync("token", "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("subject", includeEmail ? "invitee@example.com" : null, verified)));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.EmailNotVerified));
    }

    [Test]
    public async Task RegisterShouldUseCustomEmailMatchPolicy()
    {
        var userId = Guid.NewGuid();
        var invitations = CreateInvitations(acceptance: AcceptResult(userId));
        var policy = new Mock<IOidcInvitationEmailMatchPolicy>();
        policy.Setup(p => p.Validate(It.IsAny<OidcInvitationEmailMatchContext>())).Returns(OidcInvitationEmailMatchResult.Success());
        var service = CreateService(invitations.Object, emailPolicy: policy.Object);

        var result = await service.RegisterOidcInvitationAsync("token", "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("subject", "other@example.com", null)));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.Registered));
    }

    [TestCase(AshlarOidcInvitationRegistrationStatus.InvalidPrincipal)]
    [TestCase(AshlarOidcInvitationRegistrationStatus.Failed)]
    public async Task RegisterShouldReturnCustomEmailMatchPolicyFailure(AshlarOidcInvitationRegistrationStatus expected)
    {
        var policy = new Mock<IOidcInvitationEmailMatchPolicy>();
        policy.Setup(p => p.Validate(It.IsAny<OidcInvitationEmailMatchContext>())).Returns(new OidcInvitationEmailMatchResult(expected));
        var service = CreateService(emailPolicy: policy.Object);

        var result = await service.RegisterOidcInvitationAsync("token", "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("subject", "invitee@example.com", "true")));

        Assert.That(result.Status, Is.EqualTo(expected));
    }

    [Test]
    public async Task RegisterShouldUseStandardEmailPolicyForGenericProviders()
    {
        var userId = Guid.NewGuid();
        var invitations = CreateInvitations(acceptance: AcceptResult(userId));
        var options = CreateOptions();
        var transactions = DurableTransactionComposition.Create(CreateTransactionProvider().Object);
        var service = new AshlarOidcInvitationRegistrationService(
            invitations.Object,
            new StubCredentialLinkService(Result.Success()),
            transactions,
            new TestOptionsMonitor(options),
            new StandardOidcVerifiedEmailMatchPolicy());

        var result = await service.RegisterOidcInvitationAsync(
            "token",
            "Google",
            AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("subject", "invitee@example.com", "true")));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.Registered));
    }

    [Test]
    public async Task RegisterShouldUseVerifiedEmailForMicrosoftPresetProviders()
    {
        var userId = Guid.NewGuid();
        var invitations = CreateInvitations(acceptance: AcceptResult(userId));
        var options = CreateOptions();
        options.AddMicrosoft("contoso.onmicrosoft.com");
        var transactions = DurableTransactionComposition.Create(CreateTransactionProvider().Object);
        var service = new AshlarOidcInvitationRegistrationService(
            invitations.Object,
            new StubCredentialLinkService(Result.Success()),
            transactions,
            new TestOptionsMonitor(options),
            new MicrosoftOidcInvitationEmailMatchPolicy("Microsoft", new StandardOidcVerifiedEmailMatchPolicy()));

        var result = await service.RegisterOidcInvitationAsync(
            "token",
            "Microsoft",
            AshlarOAuthTestTickets.CreateExternalTicket("Microsoft", "Microsoft", ProviderType.Oidc, CreatePrincipal("subject", "invitee@example.com", "true")));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.Registered));
    }

    [TestCase("preferred_username")]
    [TestCase("upn")]
    [TestCase("unique_name")]
    public async Task RegisterShouldRejectMicrosoftEmailLikeClaimMatchesByDefault(string claimType)
    {
        var options = CreateOptions();
        options.AddMicrosoft("contoso.onmicrosoft.com");
        var transactions = DurableTransactionComposition.Create(CreateTransactionProvider().Object);
        var service = new AshlarOidcInvitationRegistrationService(
            CreateInvitations().Object,
            new StubCredentialLinkService(Result.Success()),
            transactions,
            new TestOptionsMonitor(options),
            new MicrosoftOidcInvitationEmailMatchPolicy("Microsoft", new StandardOidcVerifiedEmailMatchPolicy()));

        var result = await service.RegisterOidcInvitationAsync(
            "token",
            "Microsoft",
            AshlarOAuthTestTickets.CreateExternalTicket("Microsoft", "Microsoft", ProviderType.Oidc, CreatePrincipalWithClaim("subject", claimType, "invitee@example.com")));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.EmailNotVerified));
    }

    [TestCase(null)]
    [TestCase("false")]
    [TestCase("0")]
    public async Task RegisterShouldRejectMicrosoftUnverifiedEmailByDefault(string? verified)
    {
        var options = CreateOptions();
        options.AddMicrosoft("contoso.onmicrosoft.com");
        var transactions = DurableTransactionComposition.Create(CreateTransactionProvider().Object);
        var service = new AshlarOidcInvitationRegistrationService(
            CreateInvitations().Object,
            new StubCredentialLinkService(Result.Success()),
            transactions,
            new TestOptionsMonitor(options),
            new MicrosoftOidcInvitationEmailMatchPolicy("Microsoft", new StandardOidcVerifiedEmailMatchPolicy()));

        var result = await service.RegisterOidcInvitationAsync(
            "token",
            "Microsoft",
            AshlarOAuthTestTickets.CreateExternalTicket("Microsoft", "Microsoft", ProviderType.Oidc, CreatePrincipal("subject", "invitee@example.com", verified)));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.EmailNotVerified));
    }

    [TestCase("preferred_username")]
    [TestCase("upn")]
    [TestCase("unique_name")]
    public async Task RegisterShouldAllowExplicitMicrosoftEmailLikeClaimMatches(string claimType)
    {
        var userId = Guid.NewGuid();
        var invitations = CreateInvitations(acceptance: AcceptResult(userId));
        var options = CreateOptions();
        options.AddMicrosoft(
            "contoso.onmicrosoft.com",
            configureInvitationEmailMatch: match => match.AllowedEmailLikeClaimTypes.Add(claimType));
        var transactions = DurableTransactionComposition.Create(CreateTransactionProvider().Object);
        var service = new AshlarOidcInvitationRegistrationService(
            invitations.Object,
            new StubCredentialLinkService(Result.Success()),
            transactions,
            new TestOptionsMonitor(options),
            new MicrosoftOidcInvitationEmailMatchPolicy("Microsoft", new StandardOidcVerifiedEmailMatchPolicy(), [claimType]));

        var result = await service.RegisterOidcInvitationAsync(
            "token",
            "Microsoft",
            AshlarOAuthTestTickets.CreateExternalTicket("Microsoft", "Microsoft", ProviderType.Oidc, CreatePrincipalWithClaim("subject", claimType, "invitee@example.com")));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.Registered));
    }

    [Test]
    public async Task RegisterShouldOnlyAllowExplicitMicrosoftEmailLikeClaimTypes()
    {
        var options = CreateOptions();
        var transactions = DurableTransactionComposition.Create(CreateTransactionProvider().Object);
        options.AddMicrosoft(
            "contoso.onmicrosoft.com",
            configureInvitationEmailMatch: match => match.AllowedEmailLikeClaimTypes.Add("upn"));
        var service = new AshlarOidcInvitationRegistrationService(
            CreateInvitations().Object,
            new StubCredentialLinkService(Result.Success()),
            transactions,
            new TestOptionsMonitor(options),
            new MicrosoftOidcInvitationEmailMatchPolicy("Microsoft", new StandardOidcVerifiedEmailMatchPolicy(), ["upn"]));

        var result = await service.RegisterOidcInvitationAsync(
            "token",
            "Microsoft",
            AshlarOAuthTestTickets.CreateExternalTicket("Microsoft", "Microsoft", ProviderType.Oidc, CreatePrincipalWithClaim("subject", "preferred_username", "invitee@example.com")));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.EmailNotVerified));
    }

    [Test]
    public async Task RegisterShouldRejectMicrosoftEmailMismatchEvenWhenAllowedEmailLikeClaimMatches()
    {
        var options = CreateOptions();
        options.AddMicrosoft(
            "contoso.onmicrosoft.com",
            configureInvitationEmailMatch: match => match.AllowedEmailLikeClaimTypes.Add("upn"));
        var transactions = DurableTransactionComposition.Create(CreateTransactionProvider().Object);
        var service = new AshlarOidcInvitationRegistrationService(
            CreateInvitations().Object,
            new StubCredentialLinkService(Result.Success()),
            transactions,
            new TestOptionsMonitor(options),
            new MicrosoftOidcInvitationEmailMatchPolicy("Microsoft", new StandardOidcVerifiedEmailMatchPolicy(), ["upn"]));
        var principal = CreatePrincipal("subject", "other@example.com", "true");
        ((ClaimsIdentity)principal.Identity!).AddClaim(new Claim("upn", "invitee@example.com"));

        var result = await service.RegisterOidcInvitationAsync("token", "Microsoft", AshlarOAuthTestTickets.CreateExternalTicket("Microsoft", "Microsoft", ProviderType.Oidc, principal));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.EmailMismatch));
    }

    [Test]
    public async Task RegisterShouldKeepExplicitMicrosoftEmailLikeClaimMatchingTenantScoped()
    {
        var tenantId = Guid.NewGuid();
        var otherTenantId = Guid.NewGuid();
        var invitations = CreateInvitations(preview: Result.Success(new InvitationAcceptancePreview("invitee@example.com", tenantId)));
        var options = CreateOptions();
        options.AddMicrosoft(
            "contoso.onmicrosoft.com",
            configureInvitationEmailMatch: match => match.AllowedEmailLikeClaimTypes.Add("upn"));
        var transactions = DurableTransactionComposition.Create(CreateTransactionProvider().Object);
        var service = new AshlarOidcInvitationRegistrationService(
            invitations.Object,
            new StubCredentialLinkService(Result.Success()),
            transactions,
            new TestOptionsMonitor(options),
            new MicrosoftOidcInvitationEmailMatchPolicy("Microsoft", new StandardOidcVerifiedEmailMatchPolicy(), ["upn"]));

        var result = await service.RegisterOidcInvitationAsync(
            "token",
            "Microsoft",
            AshlarOAuthTestTickets.CreateExternalTicket("Microsoft", "Microsoft", ProviderType.Oidc, CreatePrincipalWithClaim("subject", "upn", "invitee@example.com")),
            context: new AuthenticationContext(TenantId: otherTenantId));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.InvalidInvitation));
    }

    [Test]
    public async Task RegisterShouldUseFallbackEmailPolicyForNonMicrosoftProvidersWhenMicrosoftPolicyIsRegistered()
    {
        var userId = Guid.NewGuid();
        var invitations = CreateInvitations(acceptance: AcceptResult(userId));
        var options = CreateOptions();
        var transactions = DurableTransactionComposition.Create(CreateTransactionProvider().Object);
        var service = new AshlarOidcInvitationRegistrationService(
            invitations.Object,
            new StubCredentialLinkService(Result.Success()),
            transactions,
            new TestOptionsMonitor(options),
            new MicrosoftOidcInvitationEmailMatchPolicy("Microsoft", new StandardOidcVerifiedEmailMatchPolicy(), ["preferred_username"]));

        var result = await service.RegisterOidcInvitationAsync(
            "token",
            "Google",
            AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("subject", "invitee@example.com", "true")));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.Registered));
    }

    [Test]
    public void MicrosoftEmailPolicyShouldUseFallbackForBlankProviderNames()
    {
        var policy = new MicrosoftOidcInvitationEmailMatchPolicy("Microsoft", new StandardOidcVerifiedEmailMatchPolicy());

        var result = policy.Validate(new OidcInvitationEmailMatchContext(
            " ",
            CreatePrincipal("subject", "invitee@example.com", "true"),
            new InvitationAcceptancePreview("invitee@example.com", null)));

        Assert.That(result.Succeeded, Is.True);
    }

    [Test]
    public async Task RegisterShouldReturnEmailMismatchForMicrosoftPresetWhenCandidateEmailDiffers()
    {
        var options = CreateOptions();
        options.AddMicrosoft(
            "contoso.onmicrosoft.com",
            configureInvitationEmailMatch: match => match.AllowedEmailLikeClaimTypes.Add("preferred_username"));
        var transactions = DurableTransactionComposition.Create(CreateTransactionProvider().Object);
        var service = new AshlarOidcInvitationRegistrationService(
            CreateInvitations().Object,
            new StubCredentialLinkService(Result.Success()),
            transactions,
            new TestOptionsMonitor(options),
            new MicrosoftOidcInvitationEmailMatchPolicy("Microsoft", new StandardOidcVerifiedEmailMatchPolicy(), ["preferred_username"]));

        var result = await service.RegisterOidcInvitationAsync(
            "token",
            "Microsoft",
            AshlarOAuthTestTickets.CreateExternalTicket("Microsoft", "Microsoft", ProviderType.Oidc, CreatePrincipalWithClaim("subject", "preferred_username", "other@example.com")));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.EmailMismatch));
    }

    [Test]
    public async Task RegisterShouldReturnEmailNotVerifiedForMicrosoftPresetWhenNoCandidateEmailExists()
    {
        var options = CreateOptions();
        options.AddMicrosoft("contoso.onmicrosoft.com");
        var transactions = DurableTransactionComposition.Create(CreateTransactionProvider().Object);
        var service = new AshlarOidcInvitationRegistrationService(
            CreateInvitations().Object,
            new StubCredentialLinkService(Result.Success()),
            transactions,
            new TestOptionsMonitor(options),
            new MicrosoftOidcInvitationEmailMatchPolicy("Microsoft", new StandardOidcVerifiedEmailMatchPolicy(), ["preferred_username"]));

        var result = await service.RegisterOidcInvitationAsync(
            "token",
            "Microsoft",
            AshlarOAuthTestTickets.CreateExternalTicket("Microsoft", "Microsoft", ProviderType.Oidc, CreatePrincipalWithClaim("subject", "name", "Invitee")));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.EmailNotVerified));
    }

    [TestCase(AshlarFailureCodes.InvalidInvitationValue, AshlarOidcInvitationRegistrationStatus.InvalidInvitation)]
    [TestCase(AshlarFailureCodes.RateLimitedValue, AshlarOidcInvitationRegistrationStatus.RateLimited)]
    public async Task RegisterShouldMapInvitationAcceptanceFailure(string failureCode, AshlarOidcInvitationRegistrationStatus expected)
    {
        var invitations = CreateInvitations(acceptance: Result.Failure<InvitationAcceptanceResult>(new AshlarFailureCode(failureCode)));
        var service = CreateService(invitations.Object);

        var result = await service.RegisterOidcInvitationAsync("token", "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("subject", "invitee@example.com", "true")));

        Assert.That(result.Status, Is.EqualTo(expected));
    }

    [Test]
    public async Task RegisterShouldMapInvitationAcceptanceFailureWithoutCode()
    {
        var invitations = CreateInvitations(acceptance: new Result<InvitationAcceptanceResult>(false));
        var service = CreateService(invitations.Object);

        var result = await service.RegisterOidcInvitationAsync("token", "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("subject", "invitee@example.com", "true")));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.Failed));
    }

    [Test]
    public async Task RegisterShouldCommitInvitationAcceptanceFailureAudit()
    {
        var transaction = new Mock<IAshlarTransaction>();
        var service = CreateService(
            CreateInvitations(acceptance: Result.Failure<InvitationAcceptanceResult>(AshlarFailureCodes.InvalidInvitation)).Object,
            transaction: transaction);

        await service.RegisterOidcInvitationAsync("token", "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("subject", "invitee@example.com", "true")));

        transaction.Verify(t => t.CommitAsync(It.IsAny<CancellationToken>()), Times.Once);
        transaction.Verify(t => t.RollbackAsync(It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task RegisterShouldMapCredentialProviderKeyConflict()
    {
        var userId = Guid.NewGuid();
        var invitations = CreateInvitations(acceptance: AcceptResult(userId));
        var linker = MockLinkFailure(AshlarFailureCodes.AlreadyLinkedToOther);
        var service = CreateService(invitations.Object, linkService: linker.Object);

        var result = await service.RegisterOidcInvitationAsync("token", "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("subject", "invitee@example.com", "true")));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.AlreadyLinkedToAnotherUser));
            Assert.That(result.UserId, Is.EqualTo(userId));
        }
    }

    [Test]
    public async Task RegisterShouldCommitOnlyAfterInvitationAcceptanceAndCredentialLinkSucceed()
    {
        var userId = Guid.NewGuid();
        var invitations = CreateInvitations(acceptance: AcceptResult(userId));
        var transaction = new Mock<IAshlarTransaction>();
        var service = CreateService(invitations.Object, transaction: transaction);

        var result = await service.RegisterOidcInvitationAsync("token", "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("subject", "invitee@example.com", "true")));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.Registered));
            transaction.Verify(t => t.CommitAsync(It.IsAny<CancellationToken>()), Times.Once);
            transaction.Verify(t => t.RollbackAsync(It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task RegisterShouldRollBackInvitationAcceptanceWhenCredentialLinkFails()
    {
        var userId = Guid.NewGuid();
        var invitations = CreateInvitations(acceptance: AcceptResult(userId));
        var transaction = new Mock<IAshlarTransaction>();
        var service = CreateService(invitations.Object, transaction: transaction, linkService: MockLinkFailure(AshlarFailureCodes.AlreadyLinkedToOther).Object);

        var result = await service.RegisterOidcInvitationAsync("token", "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("subject", "invitee@example.com", "true")));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.AlreadyLinkedToAnotherUser));
            transaction.Verify(t => t.RollbackAsync(It.IsAny<CancellationToken>()), Times.Once);
            transaction.Verify(t => t.CommitAsync(It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task RegisterShouldNotStartTransactionWhenEmailPolicyFails()
    {
        var transactions = CreateTransactionProvider();
        var service = CreateService(transactionProvider: transactions);

        var result = await service.RegisterOidcInvitationAsync("token", "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("subject", "other@example.com", "true")));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.EmailMismatch));
            transactions.Verify(t => t.BeginTransactionAsync(It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public void RegisterShouldMapCredentialLinkFailureWithoutCode()
    {
        var mapper = typeof(AshlarOidcInvitationRegistrationService).GetMethod("MapLinkFailure", System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic)!;

        var status = mapper.Invoke(null, [new Result(false)]);

        Assert.That(status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.LinkFailed));
    }

    [Test]
    public async Task RegisterShouldReturnAlreadyLinkedWhenOidcCredentialAlreadyBelongsToAcceptedUser()
    {
        var userId = Guid.NewGuid();
        var invitations = CreateInvitations(acceptance: AcceptResult(userId));
        var linker = MockLinkFailure(AshlarFailureCodes.AlreadyLinkedToSelf);
        var service = CreateService(invitations.Object, linkService: linker.Object);

        var result = await service.RegisterOidcInvitationAsync("token", "Google", AshlarOAuthTestTickets.CreateExternalTicket("Google", "Google", ProviderType.Oidc, CreatePrincipal("subject", "invitee@example.com", "true")));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.AlreadyLinked));
            linker.Verify(s => s.LinkValidatedExternalCredentialAsync(It.IsAny<InternalValidatedExternalCredentialLinkRequest>(), It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [Test]
    public async Task RegisterFromAuthenticateResultShouldValidateTicket()
    {
        var service = CreateService();

        var failed = await service.RegisterOidcInvitationAsync("token", "Google", AuthenticateResult.Fail("failed"));
        var mismatch = await service.RegisterOidcInvitationAsync("token", "Google", CreateTicket("Microsoft", "Microsoft", "subject"));
        var wrongProviderType = await service.RegisterOidcInvitationAsync("token", "Google", CreateTicket("Google", "Google", "subject", ProviderType.OAuth));
        var missingProviderType = await service.RegisterOidcInvitationAsync("token", "Google", CreateTicket("Google", "Google", "subject", includeProviderType: false));
        var missingProvider = await service.RegisterOidcInvitationAsync("token", "Microsoft", CreateTicket("Microsoft", "Microsoft", "subject"));
        var matched = await service.RegisterOidcInvitationAsync("token", "Google", CreateTicket("Google", "Google", "subject"));
        var matchedWithProviderType = await service.RegisterOidcInvitationAsync("token", "Google", CreateTicket("Google", "Google", "subject", ProviderType.Oidc));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(failed.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.AuthenticationFailed));
            Assert.That(mismatch.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.ProviderMismatch));
            Assert.That(wrongProviderType.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.ProviderMismatch));
            Assert.That(missingProviderType.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.ProviderMismatch));
            Assert.That(missingProvider.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.UnsupportedProvider));
            Assert.That(matched.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.InvalidInvitation));
            Assert.That(matchedWithProviderType.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.InvalidInvitation));
        }
    }

    [Test]
    public async Task CompleteShouldClearExternalCookieAndRegister()
    {
        var userId = Guid.NewGuid();
        var invitations = CreateInvitations(acceptance: AcceptResult(userId));
        var auth = new TestAuthenticationService(CreateTicket("Google", "Google", "subject"));
        var service = CreateService(invitations.Object);

        var result = await service.CompleteOidcInvitationRegistrationAsync(CreateHttpContext(auth), "token", "Google");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.Registered));
            Assert.That(auth.SignOutCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task CompleteShouldNotRegisterWhenClearingSuccessfulTicketThrows()
    {
        var invitations = CreateInvitations(acceptance: AcceptResult(Guid.NewGuid()));
        var auth = new TestAuthenticationService(CreateTicket("Google", "Google", "subject"), signOutException: new InvalidOperationException("clear failed"));
        var service = CreateService(invitations.Object);

        var result = await service.CompleteOidcInvitationRegistrationAsync(CreateHttpContext(auth), "token", "Google");

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.AuthenticationFailed));
        invitations.Verify(s => s.AcceptInvitationAsync(It.IsAny<AcceptInvitationRequest>(), It.IsAny<AuthenticationContext?>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task CompleteFromPropertiesShouldUseTicketState()
    {
        var userId = Guid.NewGuid();
        AcceptInvitationRequest? observedRequest = null;
        var invitations = CreateInvitations(acceptance: AcceptResult(userId), token: "ticket-token");
        invitations.Setup(s => s.AcceptInvitationAsync(It.Is<AcceptInvitationRequest>(r => r.Token == "ticket-token"), It.IsAny<AuthenticationContext?>(), It.IsAny<CancellationToken>()))
            .Callback<AcceptInvitationRequest, AuthenticationContext?, CancellationToken>((request, _, _) => observedRequest = request)
            .ReturnsAsync(AcceptResult(userId));
        var ticket = CreateTicket("Google", "Google", "subject");
        ticket.Properties!.Items["invitation_token"] = "ticket-token";
        ticket.Properties.Items["display_name"] = "Ticket Name";
        var auth = new TestAuthenticationService(ticket);
        var service = CreateService(invitations.Object);

        var result = await service.CompleteOidcInvitationRegistrationFromPropertiesAsync(
            CreateHttpContext(auth),
            "Google",
            "invitation_token",
            "display_name");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.Registered));
            Assert.That(observedRequest?.Token, Is.EqualTo("ticket-token"));
            Assert.That(observedRequest?.UserName, Is.EqualTo("Ticket Name"));
            Assert.That(auth.SignOutCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task CompleteFromPropertiesShouldHandleMissingTicketStateAndDisplayNameProperty()
    {
        var auth = new TestAuthenticationService(CreateTicket("Google", "Google", "subject"));
        var service = CreateService();

        var result = await service.CompleteOidcInvitationRegistrationFromPropertiesAsync(
            CreateHttpContext(auth),
            "Google",
            "missing_token");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.InvalidInvitation));
            Assert.That(auth.SignOutCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task CompleteShouldValidateExternalTicket()
    {
        var service = CreateService();
        var unsupportedAuth = new TestAuthenticationService(AuthenticateResult.NoResult());
        var failedAuth = new TestAuthenticationService(AuthenticateResult.Fail("failed"));
        var mismatchAuth = new TestAuthenticationService(CreateTicket("Microsoft", "Microsoft", "subject"));
        var wrongProviderTypeAuth = new TestAuthenticationService(CreateTicket("Google", "Google", "subject", ProviderType.OAuth));

        var unsupported = await service.CompleteOidcInvitationRegistrationAsync(CreateHttpContext(unsupportedAuth), "token", "Microsoft");
        var failed = await service.CompleteOidcInvitationRegistrationAsync(CreateHttpContext(failedAuth), "token", "Google");
        var mismatch = await service.CompleteOidcInvitationRegistrationAsync(CreateHttpContext(mismatchAuth), "token", "Google");
        var wrongProviderType = await service.CompleteOidcInvitationRegistrationAsync(CreateHttpContext(wrongProviderTypeAuth), "token", "Google");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(unsupported.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.UnsupportedProvider));
            Assert.That(failed.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.AuthenticationFailed));
            Assert.That(mismatch.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.ProviderMismatch));
            Assert.That(wrongProviderType.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.ProviderMismatch));
            Assert.That(unsupportedAuth.SignOutCount, Is.EqualTo(1));
            Assert.That(failedAuth.SignOutCount, Is.EqualTo(1));
            Assert.That(mismatchAuth.SignOutCount, Is.EqualTo(1));
            Assert.That(wrongProviderTypeAuth.SignOutCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task CompleteShouldClearUnsupportedProviderTicketWhenRequestIsCanceled()
    {
        var service = CreateService();
        var auth = new TestAuthenticationService(AuthenticateResult.NoResult());
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        var result = await service.CompleteOidcInvitationRegistrationAsync(
            CreateHttpContext(auth),
            "token",
            "Microsoft",
            cancellationToken: cts.Token);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.UnsupportedProvider));
            Assert.That(auth.SignOutCount, Is.EqualTo(1));
        }
    }

    [Test]
    public void CompleteShouldClearExternalCookieWhenAuthenticateThrows()
    {
        var service = CreateService();
        var auth = new TestAuthenticationService(AuthenticateResult.NoResult(), new InvalidOperationException("auth failed"));

        Assert.ThrowsAsync<InvalidOperationException>(() => service.CompleteOidcInvitationRegistrationAsync(CreateHttpContext(auth), "token", "Google"));
        Assert.That(auth.SignOutCount, Is.EqualTo(1));
    }

    private static AshlarOidcInvitationRegistrationService CreateService(
        IInvitationService? invitations = null,
        AshlarOidcProviderOptions? provider = null,
        IOidcInvitationEmailMatchPolicy? emailPolicy = null,
        Mock<IAshlarTransaction>? transaction = null,
        Mock<IAshlarTransactionProvider>? transactionProvider = null,
        IValidatedExternalCredentialLinkService? linkService = null)
    {
        var transactions = DurableTransactionComposition.Create(
            (transactionProvider ?? CreateTransactionProvider(transaction)).Object);
        return new AshlarOidcInvitationRegistrationService(
            invitations ?? CreateInvitations().Object,
            linkService ?? new StubCredentialLinkService(Result.Success()),
            transactions,
            new TestOptionsMonitor(CreateOptions(provider)),
            emailPolicy ?? new StandardOidcVerifiedEmailMatchPolicy());
    }

    private sealed class StubCredentialLinkService(Result result) : IValidatedExternalCredentialLinkService
    {
        public Task<Result> LinkValidatedExternalCredentialAsync(InternalValidatedExternalCredentialLinkRequest request, CancellationToken cancellationToken = default) =>
            Task.FromResult(result);
    }

    private static ValidatedExternalCredentialLinkServiceMock MockLinkFailure(AshlarFailureCode failure)
    {
        var linker = new ValidatedExternalCredentialLinkServiceMock();
        linker.Setup(s => s.LinkValidatedExternalCredentialAsync(It.IsAny<InternalValidatedExternalCredentialLinkRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure(failure));
        return linker;
    }

    private static Mock<IAshlarTransactionProvider> CreateTransactionProvider(Mock<IAshlarTransaction>? transaction = null)
    {
        transaction ??= new Mock<IAshlarTransaction>();
        transaction.Setup(t => t.CommitAsync(It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        transaction.Setup(t => t.RollbackAsync(It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        transaction.Setup(t => t.DisposeAsync()).Returns(ValueTask.CompletedTask);

        var participant = new Mock<IAshlarTransaction>();
        participant.Setup(t => t.CommitAsync(It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        participant.Setup(t => t.RollbackAsync(It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        participant.Setup(t => t.DisposeAsync()).Returns(ValueTask.CompletedTask);
        var calls = 0;
        var provider = new Mock<IAshlarTransactionProvider>();
        provider.Setup(p => p.BeginTransactionAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => calls++ == 0 ? transaction.Object : participant.Object);
        return provider;
    }

    private static Mock<IInvitationService> CreateInvitations(
        Result<InvitationAcceptancePreview>? preview = null,
        Result<InvitationAcceptanceResult>? acceptance = null,
        string? token = "token")
    {
        var invitations = new Mock<IInvitationService>();
        invitations.Setup(s => s.GetInvitationAcceptancePreviewAsync(token!, It.IsAny<AuthenticationContext?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(preview ?? Result.Success(new InvitationAcceptancePreview("invitee@example.com", null)));
        invitations.Setup(s => s.AcceptInvitationAsync(It.Is<AcceptInvitationRequest>(r => r.Token == token), It.IsAny<AuthenticationContext?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(acceptance ?? Result.Failure<InvitationAcceptanceResult>(AshlarFailureCodes.InvalidInvitation));
        return invitations;
    }

    private static Result<InvitationAcceptanceResult> AcceptResult(Guid userId)
    {
        var user = new Mock<Ashlar.Identity.Abstractions.Tenancy.IUser>();
        user.SetupGet(u => u.Id).Returns(userId);
        user.SetupGet(u => u.DisplayEmail).Returns("invitee@example.com");
        var authenticationResult = new Ashlar.Identity.Models.Mfa.MfaAuthenticationResult(Ashlar.Identity.Models.Mfa.MfaAuthenticationStatus.Succeeded, user.Object);
        return Result.Success(new InvitationAcceptanceResult(userId, authenticationResult));
    }

    private static AshlarOAuthOptions CreateOptions(AshlarOidcProviderOptions? provider = null)
    {
        var options = new AshlarOAuthOptions();
        options.AddOidcProvider("Google", _ => { });
        if (provider != null)
        {
            var providers = (Dictionary<string, AshlarOidcProviderOptions>)typeof(AshlarOAuthOptions)
                .GetField("_oidcProviders", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
                .GetValue(options)!;
            providers["Google"] = provider;
        }
        return options;
    }

    private static ClaimsPrincipal CreatePrincipal(string? subject, string? email, string? emailVerified, string? issuer = "https://issuer.example")
    {
        var claims = new List<Claim>();
        if (issuer != null)
        {
            claims.Add(new Claim("iss", issuer));
        }
        if (subject != null)
        {
            claims.Add(new Claim("sub", subject));
        }
        if (email != null)
        {
            claims.Add(new Claim("email", email));
        }
        if (emailVerified != null)
        {
            claims.Add(new Claim("email_verified", emailVerified));
        }
        claims.Add(new Claim("access_token", "token-value"));
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "oidc"));
    }

    private static ClaimsPrincipal CreatePrincipalWithClaim(string subject, string claimType, string claimValue)
    {
        return new ClaimsPrincipal(new ClaimsIdentity([
            new Claim("iss", "https://issuer.example"),
            new Claim("sub", subject),
            new Claim(claimType, claimValue)
        ], "oidc"));
    }

    private static string CreateExpectedIssuerSubjectKey(string issuer, string subject)
    {
        var payload = JsonSerializer.Serialize(new IssuerSubjectProviderKey(issuer, subject));
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(payload));
        return string.Concat("oidc-sha256:", Convert.ToHexString(hash));
    }

    private static AuthenticateResult CreateTicket(string providerName, string schemeName, string subject, ProviderType? providerType = null, bool includeProviderType = true)
    {
        var properties = new AuthenticationProperties();
        properties.Items[AshlarOAuthAuthenticationProperties.ProviderName] = providerName;
        properties.Items[AshlarOAuthAuthenticationProperties.SchemeName] = schemeName;
        if (includeProviderType)
        {
            properties.Items[AshlarOAuthAuthenticationProperties.ProviderType] = (providerType ?? ProviderType.Oidc).Value;
        }

        return AuthenticateResult.Success(new AuthenticationTicket(
            CreatePrincipal(subject, "invitee@example.com", "true"),
            properties,
            "Ashlar.OAuth.External"));
    }

    private static DefaultHttpContext CreateHttpContext(IAuthenticationService authenticationService)
    {
        var services = new ServiceCollection();
        services.AddSingleton(authenticationService);
        return new DefaultHttpContext { RequestServices = services.BuildServiceProvider() };
    }

    private sealed class TestOptionsMonitor(AshlarOAuthOptions options) : IOptionsMonitor<AshlarOAuthOptions>
    {
        public AshlarOAuthOptions CurrentValue => options;
        public AshlarOAuthOptions Get(string? name) => options;
        public IDisposable? OnChange(Action<AshlarOAuthOptions, string?> listener) => null;
    }

    private sealed class NonDurableTransactionProvider : IAshlarTransactionProvider
    {
        public Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default)
        {
            throw new InvalidOperationException("OIDC invitation registration must fail before starting a non-durable transaction.");
        }
    }

    private sealed class TestAuthenticationService(AuthenticateResult result, Exception? authenticateException = null, Exception? signOutException = null) : IAuthenticationService
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
            if (signOutException != null)
            {
                throw signOutException;
            }

            return Task.CompletedTask;
        }
    }

    private sealed record IssuerSubjectProviderKey(string Issuer, string Subject);
}
