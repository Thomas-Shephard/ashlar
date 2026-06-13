using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Ashlar.Identity.Abstractions.Transactions;
using Ashlar.Identity.Models.Invitations;
using Ashlar.Identity.Providers.External;
using Ashlar.OAuth.Providers.Microsoft;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;

namespace Ashlar.OAuth.Tests;

internal sealed class AshlarOidcInvitationRegistrationServiceTests
{
    [Test]
    public async Task RegisterShouldAcceptInvitationAndLinkOidcCredential()
    {
        var userId = Guid.NewGuid();
        var invitations = CreateInvitations(acceptance: Result.Success(userId));
        var credentials = new Mock<ICredentialService>();
        ExternalIdentityAssertion? observedAssertion = null;
        string? observedCredentialValue = "not-null";
        string? observedMetadata = "not-null";
        credentials.Setup(s => s.LinkCredentialAsync(userId, It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .Callback<Guid, IAuthenticationAssertion, IAuthenticationProvider, string?, string?, CancellationToken>((_, assertion, _, credentialValue, metadata, _) =>
            {
                observedAssertion = (ExternalIdentityAssertion)assertion;
                observedCredentialValue = credentialValue;
                observedMetadata = metadata;
            })
            .ReturnsAsync(Result.Success());
        var service = CreateService(invitations.Object, credentials.Object);

        var result = await service.RegisterOidcInvitationAsync("token", "Google", CreatePrincipal("subject", "invitee@example.com", "true"), "Invitee");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.Registered));
            Assert.That(result.Registered, Is.True);
            Assert.That(result.UserId, Is.EqualTo(userId));
            Assert.That(result.Assertion?.ProviderKey, Is.EqualTo("subject"));
            Assert.That(observedAssertion?.ProviderKey, Is.EqualTo("subject"));
            Assert.That(result.Assertion?.Claims, Does.Not.ContainKey("access_token"));
            Assert.That(observedCredentialValue, Is.Null);
            Assert.That(observedMetadata, Is.Null);
            invitations.Verify(s => s.AcceptInvitationAsync(
                It.Is<AcceptInvitationRequest>(r => r.UserName == "Invitee"),
                It.IsAny<AuthenticationContext?>(),
                It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [Test]
    public async Task RegisterShouldNotInferDisplayNameFromPrincipal()
    {
        var userId = Guid.NewGuid();
        AcceptInvitationRequest? observedRequest = null;
        var invitations = CreateInvitations(acceptance: Result.Success(userId));
        invitations.Setup(s => s.AcceptInvitationAsync(It.Is<AcceptInvitationRequest>(r => r.Token == "token"), It.IsAny<AuthenticationContext?>(), It.IsAny<CancellationToken>()))
            .Callback<AcceptInvitationRequest, AuthenticationContext?, CancellationToken>((request, _, _) => observedRequest = request)
            .ReturnsAsync(Result.Success(userId));
        var credentials = new Mock<ICredentialService>();
        credentials.Setup(s => s.LinkCredentialAsync(userId, It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success());
        var service = CreateService(invitations.Object, credentials.Object);
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("sub", "subject"),
            new Claim("name", "Principal Name"),
            new Claim("email", "invitee@example.com"),
            new Claim("email_verified", "true")
        ], "oidc"));

        var result = await service.RegisterOidcInvitationAsync("token", "Google", principal);

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
        var credentials = Mock.Of<ICredentialService>();
        var transactions = Mock.Of<IAshlarTransactionProvider>();
        var oauth = new TestOptionsMonitor(CreateOptions());
        var emailPolicy = Mock.Of<IOidcInvitationEmailMatchPolicy>();

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => new AshlarOidcInvitationRegistrationService(null!, credentials, transactions, oauth, emailPolicy));
            Assert.Throws<ArgumentNullException>(() => new AshlarOidcInvitationRegistrationService(invitations, null!, transactions, oauth, emailPolicy));
            Assert.Throws<ArgumentNullException>(() => new AshlarOidcInvitationRegistrationService(invitations, credentials, null!, oauth, emailPolicy));
            Assert.Throws<ArgumentNullException>(() => new AshlarOidcInvitationRegistrationService(invitations, credentials, transactions, null!, emailPolicy));
            Assert.Throws<ArgumentNullException>(() => new AshlarOidcInvitationRegistrationService(invitations, credentials, transactions, oauth, null!));
            Assert.Throws<ArgumentException>(() => new MicrosoftOidcInvitationEmailMatchPolicy(" ", new StandardOidcVerifiedEmailMatchPolicy()));
            Assert.Throws<ArgumentNullException>(() => new MicrosoftOidcInvitationEmailMatchPolicy("Microsoft", null!));
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

        var result = await service.RegisterOidcInvitationAsync("token", providerName, CreatePrincipal("subject", "invitee@example.com", "true"));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.UnsupportedProvider));
    }

    [Test]
    public async Task RegisterShouldReturnInvalidPrincipalForMissingSubject()
    {
        var service = CreateService();

        var result = await service.RegisterOidcInvitationAsync("token", "Google", CreatePrincipal(null, "invitee@example.com", "true"));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.InvalidPrincipal));
    }

    [Test]
    public async Task RegisterShouldUseIssuerQualifiedProviderKeyWhenProviderRequiresIssuer()
    {
        var userId = Guid.NewGuid();
        var invitations = CreateInvitations(acceptance: Result.Success(userId));
        var credentials = new Mock<ICredentialService>();
        ExternalIdentityAssertion? observedAssertion = null;
        credentials.Setup(s => s.LinkCredentialAsync(userId, It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .Callback<Guid, IAuthenticationAssertion, IAuthenticationProvider, string?, string?, CancellationToken>((_, assertion, _, _, _, _) =>
            {
                observedAssertion = (ExternalIdentityAssertion)assertion;
            })
            .ReturnsAsync(Result.Success());
        var service = CreateService(
            invitations.Object,
            credentials.Object,
            provider: new AshlarOidcProviderOptions("Google", "Google", _ => { }, AshlarOidcProviderKeyMode.IssuerAndSubject));

        var result = await service.RegisterOidcInvitationAsync(
            "token",
            "Google",
            CreatePrincipal("subject", "invitee@example.com", "true", issuer: "https://issuer.example/tenant"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.Registered));
            Assert.That(result.Assertion?.ProviderKey, Is.EqualTo(CreateExpectedIssuerSubjectKey("https://issuer.example/tenant", "subject")));
            Assert.That(observedAssertion?.ProviderKey, Is.EqualTo(CreateExpectedIssuerSubjectKey("https://issuer.example/tenant", "subject")));
        }
    }

    [Test]
    public async Task RegisterShouldReturnInvalidPrincipalWhenIssuerQualifiedProviderKeyMissingIssuer()
    {
        var service = CreateService(provider: new AshlarOidcProviderOptions("Google", "Google", _ => { }, AshlarOidcProviderKeyMode.IssuerAndSubject));

        var result = await service.RegisterOidcInvitationAsync("token", "Google", CreatePrincipal("subject", "invitee@example.com", "true"));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.InvalidPrincipal));
    }

    [Test]
    public async Task RegisterShouldReturnInvalidPrincipalWhenConfiguredProviderNameIsInvalid()
    {
        var service = CreateService(provider: new AshlarOidcProviderOptions(" ", "Google", _ => { }));

        var result = await service.RegisterOidcInvitationAsync("token", "Google", CreatePrincipal("subject", "invitee@example.com", "true"));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.InvalidPrincipal));
    }

    [Test]
    public void RegisterShouldValidateRequiredArguments()
    {
        var service = CreateService();

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentNullException>(() => service.RegisterOidcInvitationAsync("token", "Google", (ClaimsPrincipal)null!));
            Assert.ThrowsAsync<ArgumentNullException>(() => service.RegisterOidcInvitationAsync("token", "Google", (AuthenticateResult)null!));
            Assert.ThrowsAsync<ArgumentNullException>(() => service.CompleteOidcInvitationRegistrationAsync(null!, "token", "Google"));
        }
    }

    [TestCase(null)]
    [TestCase(" ")]
    public async Task RegisterShouldReturnInvalidInvitationForMissingInvitationToken(string? token)
    {
        var invitations = CreateInvitations(preview: Result.Failure<InvitationAcceptancePreview>(AshlarFailureCodes.InvalidInvitation), token: token);
        var service = CreateService(invitations.Object);

        var result = await service.RegisterOidcInvitationAsync(token!, "Google", CreatePrincipal("subject", "invitee@example.com", "true"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.InvalidInvitation));
            Assert.That(result.Assertion?.ProviderKey, Is.EqualTo("subject"));
        }

        invitations.Verify(s => s.AcceptInvitationAsync(It.IsAny<AcceptInvitationRequest>(), It.IsAny<AuthenticationContext?>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task RegisterShouldReturnInvalidInvitationForOverlongInvitationToken()
    {
        var overlongToken = new string('a', 257);
        var invitations = CreateInvitations(preview: Result.Failure<InvitationAcceptancePreview>(AshlarFailureCodes.InvalidInvitation), token: overlongToken);
        var service = CreateService(invitations.Object);

        var result = await service.RegisterOidcInvitationAsync(overlongToken, "Google", CreatePrincipal("subject", "invitee@example.com", "true"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.InvalidInvitation));
            Assert.That(result.Assertion?.ProviderKey, Is.EqualTo("subject"));
        }

        invitations.Verify(s => s.AcceptInvitationAsync(It.IsAny<AcceptInvitationRequest>(), It.IsAny<AuthenticationContext?>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task RegisterShouldReturnInvalidInvitationWhenPreviewFails()
    {
        var invitations = CreateInvitations(preview: Result.Failure<InvitationAcceptancePreview>(AshlarFailureCodes.InvalidInvitation));
        var service = CreateService(invitations.Object);

        var result = await service.RegisterOidcInvitationAsync("token", "Google", CreatePrincipal("subject", "invitee@example.com", "true"));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.InvalidInvitation));
    }

    [Test]
    public async Task RegisterShouldReturnRateLimitedWhenPreviewIsRateLimited()
    {
        var invitations = CreateInvitations(preview: Result.Failure<InvitationAcceptancePreview>(AshlarFailureCodes.RateLimited));
        var service = CreateService(invitations.Object);

        var result = await service.RegisterOidcInvitationAsync("token", "Google", CreatePrincipal("subject", "invitee@example.com", "true"));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.RateLimited));
    }

    [Test]
    public async Task RegisterShouldReturnFailedWhenPreviewFailsWithoutCode()
    {
        var invitations = CreateInvitations(preview: new Result<InvitationAcceptancePreview>(false));
        var service = CreateService(invitations.Object);

        var result = await service.RegisterOidcInvitationAsync("token", "Google", CreatePrincipal("subject", "invitee@example.com", "true"));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.Failed));
    }

    [Test]
    public async Task RegisterShouldReturnInvalidInvitationWhenPreviewValueIsMissing()
    {
        var invitations = CreateInvitations(preview: Result.Success<InvitationAcceptancePreview>(null!));
        var service = CreateService(invitations.Object);

        var result = await service.RegisterOidcInvitationAsync("token", "Google", CreatePrincipal("subject", "invitee@example.com", "true"));

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
            CreatePrincipal("subject", "invitee@example.com", "true"),
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
            CreatePrincipal("subject", "invitee@example.com", "true"),
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
            acceptance: Result.Success(userId));
        var credentials = new Mock<ICredentialService>();
        credentials.Setup(s => s.LinkCredentialAsync(userId, It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success());
        var service = CreateService(invitations.Object, credentials.Object);

        var result = await service.RegisterOidcInvitationAsync(
            "token",
            "Google",
            CreatePrincipal("subject", "invitee@example.com", "true"),
            context: new AuthenticationContext(TenantId: tenantId));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.Registered));
    }

    [Test]
    public async Task RegisterShouldAcceptInvitationWhenContextHasNoTenant()
    {
        var userId = Guid.NewGuid();
        var invitations = CreateInvitations(acceptance: Result.Success(userId));
        var credentials = new Mock<ICredentialService>();
        credentials.Setup(s => s.LinkCredentialAsync(userId, It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success());
        var service = CreateService(invitations.Object, credentials.Object);

        var result = await service.RegisterOidcInvitationAsync(
            "token",
            "Google",
            CreatePrincipal("subject", "invitee@example.com", "true"),
            context: new AuthenticationContext());

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.Registered));
    }

    [Test]
    public async Task RegisterShouldReturnEmailMismatch()
    {
        var service = CreateService();

        var result = await service.RegisterOidcInvitationAsync("token", "Google", CreatePrincipal("subject", "other@example.com", "true"));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.EmailMismatch));
    }

    [TestCase(null, true)]
    [TestCase(null, false)]
    [TestCase("false", true)]
    [TestCase("0", true)]
    public async Task RegisterShouldReturnEmailNotVerified(string? verified, bool includeEmail)
    {
        var service = CreateService();

        var result = await service.RegisterOidcInvitationAsync("token", "Google", CreatePrincipal("subject", includeEmail ? "invitee@example.com" : null, verified));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.EmailNotVerified));
    }

    [Test]
    public async Task RegisterShouldUseCustomEmailMatchPolicy()
    {
        var userId = Guid.NewGuid();
        var invitations = CreateInvitations(acceptance: Result.Success(userId));
        var credentials = new Mock<ICredentialService>();
        credentials.Setup(s => s.LinkCredentialAsync(userId, It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success());
        var policy = new Mock<IOidcInvitationEmailMatchPolicy>();
        policy.Setup(p => p.Validate(It.IsAny<OidcInvitationEmailMatchContext>())).Returns(OidcInvitationEmailMatchResult.Success());
        var service = CreateService(invitations.Object, credentials.Object, emailPolicy: policy.Object);

        var result = await service.RegisterOidcInvitationAsync("token", "Google", CreatePrincipal("subject", "other@example.com", null));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.Registered));
    }

    [TestCase(AshlarOidcInvitationRegistrationStatus.InvalidPrincipal)]
    [TestCase(AshlarOidcInvitationRegistrationStatus.Failed)]
    public async Task RegisterShouldReturnCustomEmailMatchPolicyFailure(AshlarOidcInvitationRegistrationStatus expected)
    {
        var policy = new Mock<IOidcInvitationEmailMatchPolicy>();
        policy.Setup(p => p.Validate(It.IsAny<OidcInvitationEmailMatchContext>())).Returns(new OidcInvitationEmailMatchResult(expected));
        var service = CreateService(emailPolicy: policy.Object);

        var result = await service.RegisterOidcInvitationAsync("token", "Google", CreatePrincipal("subject", "invitee@example.com", "true"));

        Assert.That(result.Status, Is.EqualTo(expected));
    }

    [Test]
    public async Task RegisterShouldUseStandardEmailPolicyForGenericProviders()
    {
        var userId = Guid.NewGuid();
        var invitations = CreateInvitations(acceptance: Result.Success(userId));
        var credentials = new Mock<ICredentialService>();
        credentials.Setup(s => s.LinkCredentialAsync(userId, It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success());
        var options = CreateOptions();
        var service = new AshlarOidcInvitationRegistrationService(
            invitations.Object,
            credentials.Object,
            CreateTransactionProvider().Object,
            new TestOptionsMonitor(options),
            new StandardOidcVerifiedEmailMatchPolicy());

        var result = await service.RegisterOidcInvitationAsync(
            "token",
            "Google",
            CreatePrincipal("subject", "invitee@example.com", "true"));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.Registered));
    }

    [TestCase("email")]
    [TestCase("preferred_username")]
    [TestCase("upn")]
    [TestCase("unique_name")]
    public async Task RegisterShouldUseMicrosoftEmailPolicyForMicrosoftPresetProviders(string claimType)
    {
        var userId = Guid.NewGuid();
        var invitations = CreateInvitations(acceptance: Result.Success(userId));
        var credentials = new Mock<ICredentialService>();
        credentials.Setup(s => s.LinkCredentialAsync(userId, It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success());
        var options = CreateOptions();
        options.AddMicrosoft("contoso.onmicrosoft.com");
        var service = new AshlarOidcInvitationRegistrationService(
            invitations.Object,
            credentials.Object,
            CreateTransactionProvider().Object,
            new TestOptionsMonitor(options),
            new MicrosoftOidcInvitationEmailMatchPolicy("Microsoft", new StandardOidcVerifiedEmailMatchPolicy()));

        var result = await service.RegisterOidcInvitationAsync(
            "token",
            "Microsoft",
            CreatePrincipalWithClaim("subject", claimType, "invitee@example.com"));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.Registered));
    }

    [Test]
    public async Task RegisterShouldUseFallbackEmailPolicyForNonMicrosoftProvidersWhenMicrosoftPolicyIsRegistered()
    {
        var userId = Guid.NewGuid();
        var invitations = CreateInvitations(acceptance: Result.Success(userId));
        var credentials = new Mock<ICredentialService>();
        credentials.Setup(s => s.LinkCredentialAsync(userId, It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success());
        var options = CreateOptions();
        var service = new AshlarOidcInvitationRegistrationService(
            invitations.Object,
            credentials.Object,
            CreateTransactionProvider().Object,
            new TestOptionsMonitor(options),
            new MicrosoftOidcInvitationEmailMatchPolicy("Microsoft", new StandardOidcVerifiedEmailMatchPolicy()));

        var result = await service.RegisterOidcInvitationAsync(
            "token",
            "Google",
            CreatePrincipal("subject", "invitee@example.com", "true"));

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
        options.AddMicrosoft("contoso.onmicrosoft.com");
        var service = new AshlarOidcInvitationRegistrationService(
            CreateInvitations().Object,
            Mock.Of<ICredentialService>(),
            CreateTransactionProvider().Object,
            new TestOptionsMonitor(options),
            new MicrosoftOidcInvitationEmailMatchPolicy("Microsoft", new StandardOidcVerifiedEmailMatchPolicy()));

        var result = await service.RegisterOidcInvitationAsync(
            "token",
            "Microsoft",
            CreatePrincipalWithClaim("subject", "preferred_username", "other@example.com"));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.EmailMismatch));
    }

    [Test]
    public async Task RegisterShouldReturnEmailNotVerifiedForMicrosoftPresetWhenNoCandidateEmailExists()
    {
        var options = CreateOptions();
        options.AddMicrosoft("contoso.onmicrosoft.com");
        var service = new AshlarOidcInvitationRegistrationService(
            CreateInvitations().Object,
            Mock.Of<ICredentialService>(),
            CreateTransactionProvider().Object,
            new TestOptionsMonitor(options),
            new MicrosoftOidcInvitationEmailMatchPolicy("Microsoft", new StandardOidcVerifiedEmailMatchPolicy()));

        var result = await service.RegisterOidcInvitationAsync(
            "token",
            "Microsoft",
            CreatePrincipalWithClaim("subject", "name", "Invitee"));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.EmailNotVerified));
    }

    [TestCase(AshlarFailureCodes.InvalidInvitationValue, AshlarOidcInvitationRegistrationStatus.InvalidInvitation)]
    [TestCase(AshlarFailureCodes.RateLimitedValue, AshlarOidcInvitationRegistrationStatus.RateLimited)]
    public async Task RegisterShouldMapInvitationAcceptanceFailure(string failureCode, AshlarOidcInvitationRegistrationStatus expected)
    {
        var invitations = CreateInvitations(acceptance: Result.Failure<Guid>(new AshlarFailureCode(failureCode)));
        var service = CreateService(invitations.Object);

        var result = await service.RegisterOidcInvitationAsync("token", "Google", CreatePrincipal("subject", "invitee@example.com", "true"));

        Assert.That(result.Status, Is.EqualTo(expected));
    }

    [Test]
    public async Task RegisterShouldMapInvitationAcceptanceFailureWithoutCode()
    {
        var invitations = CreateInvitations(acceptance: new Result<Guid>(false));
        var service = CreateService(invitations.Object);

        var result = await service.RegisterOidcInvitationAsync("token", "Google", CreatePrincipal("subject", "invitee@example.com", "true"));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.Failed));
    }

    [TestCase(AshlarFailureCodes.AlreadyLinkedToSelfValue, AshlarOidcInvitationRegistrationStatus.AlreadyLinked)]
    [TestCase(AshlarFailureCodes.AlreadyLinkedToOtherValue, AshlarOidcInvitationRegistrationStatus.AlreadyLinkedToAnotherUser)]
    [TestCase(AshlarFailureCodes.InvalidProviderKeyValue, AshlarOidcInvitationRegistrationStatus.InvalidPrincipal)]
    [TestCase(AshlarFailureCodes.UserNotFoundValue, AshlarOidcInvitationRegistrationStatus.LinkFailed)]
    public async Task RegisterShouldMapCredentialLinkFailure(string failureCode, AshlarOidcInvitationRegistrationStatus expected)
    {
        var userId = Guid.NewGuid();
        var invitations = CreateInvitations(acceptance: Result.Success(userId));
        var credentials = new Mock<ICredentialService>();
        credentials.Setup(s => s.LinkCredentialAsync(userId, It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure(new AshlarFailureCode(failureCode)));
        var service = CreateService(invitations.Object, credentials.Object);

        var result = await service.RegisterOidcInvitationAsync("token", "Google", CreatePrincipal("subject", "invitee@example.com", "true"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(expected));
            Assert.That(result.UserId, Is.EqualTo(userId));
        }
    }

    [Test]
    public async Task RegisterShouldCommitOnlyAfterInvitationAcceptanceAndCredentialLinkSucceed()
    {
        var userId = Guid.NewGuid();
        var invitations = CreateInvitations(acceptance: Result.Success(userId));
        var credentials = new Mock<ICredentialService>();
        credentials.Setup(s => s.LinkCredentialAsync(userId, It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success());
        var transaction = new Mock<IAshlarTransaction>();
        var service = CreateService(invitations.Object, credentials.Object, transaction: transaction);

        var result = await service.RegisterOidcInvitationAsync("token", "Google", CreatePrincipal("subject", "invitee@example.com", "true"));

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
        var invitations = CreateInvitations(acceptance: Result.Success(userId));
        var credentials = new Mock<ICredentialService>();
        credentials.Setup(s => s.LinkCredentialAsync(userId, It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure(AshlarFailureCodes.UserNotFound));
        var transaction = new Mock<IAshlarTransaction>();
        var service = CreateService(invitations.Object, credentials.Object, transaction: transaction);

        var result = await service.RegisterOidcInvitationAsync("token", "Google", CreatePrincipal("subject", "invitee@example.com", "true"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.LinkFailed));
            transaction.Verify(t => t.RollbackAsync(It.IsAny<CancellationToken>()), Times.Once);
            transaction.Verify(t => t.CommitAsync(It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task RegisterShouldNotStartTransactionWhenEmailPolicyFails()
    {
        var transactions = new Mock<IAshlarTransactionProvider>();
        var service = CreateService(transactionProvider: transactions);

        var result = await service.RegisterOidcInvitationAsync("token", "Google", CreatePrincipal("subject", "other@example.com", "true"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.EmailMismatch));
            transactions.Verify(t => t.BeginTransactionAsync(It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task RegisterShouldMapCredentialLinkFailureWithoutCode()
    {
        var userId = Guid.NewGuid();
        var invitations = CreateInvitations(acceptance: Result.Success(userId));
        var credentials = new Mock<ICredentialService>();
        credentials.Setup(s => s.LinkCredentialAsync(userId, It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Result(false));
        var service = CreateService(invitations.Object, credentials.Object);

        var result = await service.RegisterOidcInvitationAsync("token", "Google", CreatePrincipal("subject", "invitee@example.com", "true"));

        Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.LinkFailed));
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
        var invitations = CreateInvitations(acceptance: Result.Success(userId));
        var credentials = new Mock<ICredentialService>();
        credentials.Setup(s => s.LinkCredentialAsync(userId, It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success());
        var auth = new TestAuthenticationService(CreateTicket("Google", "Google", "subject"));
        var service = CreateService(invitations.Object, credentials.Object);

        var result = await service.CompleteOidcInvitationRegistrationAsync(CreateHttpContext(auth), "token", "Google");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.Registered));
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
        ICredentialService? credentials = null,
        AshlarOidcProviderOptions? provider = null,
        IOidcInvitationEmailMatchPolicy? emailPolicy = null,
        Mock<IAshlarTransaction>? transaction = null,
        Mock<IAshlarTransactionProvider>? transactionProvider = null)
    {
        return new AshlarOidcInvitationRegistrationService(
            invitations ?? CreateInvitations().Object,
            credentials ?? Mock.Of<ICredentialService>(),
            transactionProvider?.Object ?? CreateTransactionProvider(transaction).Object,
            new TestOptionsMonitor(CreateOptions(provider)),
            emailPolicy ?? new StandardOidcVerifiedEmailMatchPolicy());
    }

    private static Mock<IAshlarTransactionProvider> CreateTransactionProvider(Mock<IAshlarTransaction>? transaction = null)
    {
        transaction ??= new Mock<IAshlarTransaction>();
        transaction.Setup(t => t.CommitAsync(It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        transaction.Setup(t => t.RollbackAsync(It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        transaction.Setup(t => t.DisposeAsync()).Returns(ValueTask.CompletedTask);

        var provider = new Mock<IAshlarTransactionProvider>();
        provider.Setup(p => p.BeginTransactionAsync(It.IsAny<CancellationToken>())).ReturnsAsync(transaction.Object);
        return provider;
    }

    private static Mock<IInvitationService> CreateInvitations(
        Result<InvitationAcceptancePreview>? preview = null,
        Result<Guid>? acceptance = null,
        string? token = "token")
    {
        var invitations = new Mock<IInvitationService>();
        invitations.Setup(s => s.GetInvitationAcceptancePreviewAsync(token!, It.IsAny<AuthenticationContext?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(preview ?? Result.Success(new InvitationAcceptancePreview("invitee@example.com", null)));
        invitations.Setup(s => s.AcceptInvitationAsync(It.Is<AcceptInvitationRequest>(r => r.Token == token), It.IsAny<AuthenticationContext?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(acceptance ?? Result.Failure<Guid>(AshlarFailureCodes.InvalidInvitation));
        return invitations;
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

    private static ClaimsPrincipal CreatePrincipal(string? subject, string? email, string? emailVerified, string? issuer = null)
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

    private sealed record IssuerSubjectProviderKey(string Issuer, string Subject);
}
