using System.Diagnostics.CodeAnalysis;
using Ashlar.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;

namespace Ashlar.Tests.Identity.Features.Authentication;

[TestFixture]
internal sealed class AuthenticationOrchestratorTests
{
    private Mock<IAuthenticationPipeline> _pipelineMock;
    private Mock<IAuthenticationFactorPipeline> _factorPipelineMock;
    private Mock<IAuthenticationHandshakeService> _handshakeServiceMock;
    private Mock<IMfaPolicyEvaluator> _policyEvaluatorMock;
    private IAuthenticationProviderRegistry _providerRegistry;
    private AuthenticationOrchestrator _orchestrator;
    private AuthenticationContext _context;
    private Mock<IAuthenticationAssertion> _assertionMock;
    private Mock<IUser> _userMock;

    [SetUp]
    public void SetUp()
    {
        _pipelineMock = new Mock<IAuthenticationPipeline>();
        _factorPipelineMock = new Mock<IAuthenticationFactorPipeline>();
        _handshakeServiceMock = new Mock<IAuthenticationHandshakeService>();
        _policyEvaluatorMock = new Mock<IMfaPolicyEvaluator>();
        _providerRegistry = CreateProviderRegistry();
        _orchestrator = new AuthenticationOrchestrator(
            _pipelineMock.Object,
            _factorPipelineMock.Object,
            _handshakeServiceMock.Object,
            _policyEvaluatorMock.Object,
            _providerRegistry);

        _context = new AuthenticationContext(IpAddress: "127.0.0.1", UserAgent: "TestAgent");
        _assertionMock = new Mock<IAuthenticationAssertion>();
        _assertionMock.Setup(a => a.ProviderIdentity).Returns(new AuthenticationProviderKey("totp", "totp"));
        _userMock = new Mock<IUser>();
        _userMock.Setup(u => u.Id).Returns(Guid.NewGuid());
        _userMock.Setup(u => u.AccountState).Returns(UserAccountState.Active);
        _handshakeServiceMock
            .Setup(h => h.BeginFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((VerifyAuthenticationHandshakeRequest request, CancellationToken _) => Result.Success(new AuthenticationHandshake(
                Guid.NewGuid(),
                _userMock.Object.Id,
                "hash",
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow.AddMinutes(5),
                false,
                false,
                new HashSet<string> { request.FactorType },
                new HashSet<string>())));
    }

    [Test]
    public async Task AuthenticateAsyncSucceedsWhenNoMfaRequired()
    {
        var options = new MfaOrchestrationOptions();
        var claims = new Dictionary<string, string> { ["test"] = "value" };
        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success, claims));

        _policyEvaluatorMock.Setup(e => e.EvaluateAsync(_userMock.Object, _context, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaPolicyEvaluation(false));

        var result = await _orchestrator.AuthenticateAsync(_context, _assertionMock.Object, options);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Succeeded));
            Assert.That(result.User, Is.EqualTo(_userMock.Object));
            Assert.That(result.Claims?["test"], Is.EqualTo(["value"]));
        }
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void ConstructorThrowsWhenDependenciesAreNull()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationOrchestrator(null!, _factorPipelineMock.Object, _handshakeServiceMock.Object, _policyEvaluatorMock.Object, _providerRegistry));
            Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationOrchestrator(_pipelineMock.Object, null!, _handshakeServiceMock.Object, _policyEvaluatorMock.Object, _providerRegistry));
            Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationOrchestrator(_pipelineMock.Object, _factorPipelineMock.Object, null!, _policyEvaluatorMock.Object, _providerRegistry));
            Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationOrchestrator(_pipelineMock.Object, _factorPipelineMock.Object, _handshakeServiceMock.Object, null!, _providerRegistry));
            Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationOrchestrator(_pipelineMock.Object, _factorPipelineMock.Object, _handshakeServiceMock.Object, _policyEvaluatorMock.Object, null!));
        }
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void AuthenticateAsyncThrowsWhenArgumentsAreNull()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentNullException>(() => _orchestrator.AuthenticateAsync(null!, _assertionMock.Object));
            Assert.ThrowsAsync<ArgumentNullException>(() => _orchestrator.AuthenticateAsync(_context, null!));
        }
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void VerifyFactorAsyncThrowsWhenArgumentsAreNullOrWhiteSpace()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentNullException>(() => _orchestrator.VerifyFactorAsync(null!, "totp", _context, _assertionMock.Object));
            Assert.ThrowsAsync<ArgumentException>(() => _orchestrator.VerifyFactorAsync("", "totp", _context, _assertionMock.Object));
            Assert.ThrowsAsync<ArgumentNullException>(() => _orchestrator.VerifyFactorAsync("token", null!, _context, _assertionMock.Object));
            Assert.ThrowsAsync<ArgumentException>(() => _orchestrator.VerifyFactorAsync("token", "", _context, _assertionMock.Object));
            Assert.ThrowsAsync<ArgumentNullException>(() => _orchestrator.VerifyFactorAsync("token", "totp", null!, _assertionMock.Object));
        }
    }

    [Test]
    public async Task AuthenticateAsyncReturnsMfaRequiredWhenPolicyRequiresMfa()
    {
        var claims = new Dictionary<string, string> { ["test"] = "value" };
        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success, claims));

        var requiredFactors = new[] { "totp" };
        _policyEvaluatorMock.Setup(e => e.EvaluateAsync(_userMock.Object, _context, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaPolicyEvaluation(true, new MfaRequirement(requiredFactors)));

        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, requiredFactors.ToHashSet(), new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.CreateHandshakeAsync(It.IsAny<CreateAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(new AuthenticationHandshakeCreated(handshake, "token")));

        var result = await _orchestrator.AuthenticateAsync(_context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.MfaRequired));
            Assert.That(result.User, Is.EqualTo(_userMock.Object));
            Assert.That(result.HandshakeToken, Is.EqualTo("token"));
            Assert.That(result.RequiredFactors, Is.EquivalentTo(requiredFactors));
        }

        _handshakeServiceMock.Verify(h => h.CreateHandshakeAsync(
            It.Is<CreateAuthenticationHandshakeRequest>(r =>
                r.UserId == _userMock.Object.Id &&
                r.RequiredFactors.SequenceEqual(requiredFactors) &&
                r.Metadata != null && r.Metadata["claim:test"] == "[\"value\"]"),
            It.IsAny<CancellationToken>()));
    }

    [Test]
    public async Task AuthenticateAsyncSkipsPolicyRequiredMfaWhenRememberedDeviceTokenIsValid()
    {
        var tenantId = Guid.NewGuid();
        var context = _context with { TenantId = tenantId };
        context = context.WithRememberedMfaDeviceToken("remembered-token");
        var claims = new Dictionary<string, string> { ["test"] = "value" };
        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success, claims));
        _policyEvaluatorMock.Setup(e => e.EvaluateAsync(_userMock.Object, context, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaPolicyEvaluation(true, new MfaRequirement(["totp"])));
        var rememberedMfaDeviceService = CreateRememberedDeviceService(
            new ValidateRememberedMfaDeviceResult(
                true,
                CreateRememberedDeviceSummary(_userMock.Object.Id, tenantId),
                RememberedMfaDeviceValidationStatus.Success));
        var orchestrator = CreateOrchestratorWithRememberedDevices(rememberedMfaDeviceService.Object);

        var result = await orchestrator.AuthenticateAsync(
            context,
            _assertionMock.Object,
            new MfaOrchestrationOptions { EnableRememberedMfaDevices = true });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Succeeded));
            Assert.That(result.User, Is.EqualTo(_userMock.Object));
            Assert.That(result.Claims?["test"], Is.EqualTo(["value"]));
            Assert.That(result.HandshakeToken, Is.Null);
            Assert.That(result.RequiredFactors, Is.Null);
            Assert.That(result.FreshMfaSatisfied, Is.False);
        }

        rememberedMfaDeviceService.Verify(s => s.ValidateAsync(
            _userMock.Object.Id,
            It.Is<ValidateRememberedMfaDeviceRequest>(r =>
                r.Token == "remembered-token" &&
                r.Tenant != null &&
                r.Tenant.TenantId == tenantId &&
                r.Audit != null &&
                r.Audit.ActorUserId == _userMock.Object.Id &&
                r.Audit.IpAddress == _context.IpAddress &&
                r.Audit.UserAgent == _context.UserAgent &&
                r.Audit.CorrelationId == _context.CorrelationId),
            It.IsAny<CancellationToken>()), Times.Once);
        _handshakeServiceMock.Verify(h => h.CreateHandshakeAsync(It.IsAny<CreateAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [TestCase(RememberedMfaDeviceValidationStatus.Failed)]
    [TestCase(RememberedMfaDeviceValidationStatus.Expired)]
    [TestCase(RememberedMfaDeviceValidationStatus.Revoked)]
    [TestCase(RememberedMfaDeviceValidationStatus.WrongUser)]
    [TestCase(RememberedMfaDeviceValidationStatus.WrongTenant)]
    public async Task AuthenticateAsyncFallsBackToMfaHandshakeWhenRememberedDeviceTokenIsInvalid(RememberedMfaDeviceValidationStatus status)
    {
        var context = _context.WithRememberedMfaDeviceToken("remembered-token");
        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));
        _policyEvaluatorMock.Setup(e => e.EvaluateAsync(_userMock.Object, context, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaPolicyEvaluation(true, new MfaRequirement(["totp"])));
        _handshakeServiceMock.Setup(h => h.CreateHandshakeAsync(It.IsAny<CreateAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(new AuthenticationHandshakeCreated(
                new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "totp" }, new HashSet<string>()),
                "handshake-token")));
        var rememberedMfaDeviceService = CreateRememberedDeviceService(new ValidateRememberedMfaDeviceResult(false, null, status));
        var orchestrator = CreateOrchestratorWithRememberedDevices(rememberedMfaDeviceService.Object);

        var result = await orchestrator.AuthenticateAsync(
            context,
            _assertionMock.Object,
            new MfaOrchestrationOptions { EnableRememberedMfaDevices = true });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.MfaRequired));
            Assert.That(result.HandshakeToken, Is.EqualTo("handshake-token"));
        }

        _handshakeServiceMock.Verify(h => h.CreateHandshakeAsync(It.IsAny<CreateAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task AuthenticateAsyncFallsBackToMfaHandshakeWhenRememberedDeviceTokenIsMissing()
    {
        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));
        _policyEvaluatorMock.Setup(e => e.EvaluateAsync(_userMock.Object, _context, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaPolicyEvaluation(true, new MfaRequirement(["totp"])));
        _handshakeServiceMock.Setup(h => h.CreateHandshakeAsync(It.IsAny<CreateAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(new AuthenticationHandshakeCreated(
                new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "totp" }, new HashSet<string>()),
                "handshake-token")));
        var rememberedMfaDeviceService = CreateRememberedDeviceService(new ValidateRememberedMfaDeviceResult(true, CreateRememberedDeviceSummary(_userMock.Object.Id, null), RememberedMfaDeviceValidationStatus.Success));
        var orchestrator = CreateOrchestratorWithRememberedDevices(rememberedMfaDeviceService.Object);

        var result = await orchestrator.AuthenticateAsync(
            _context,
            _assertionMock.Object,
            new MfaOrchestrationOptions { EnableRememberedMfaDevices = true });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.MfaRequired));
            Assert.That(result.HandshakeToken, Is.EqualTo("handshake-token"));
        }

        rememberedMfaDeviceService.Verify(s => s.ValidateAsync(It.IsAny<Guid>(), It.IsAny<ValidateRememberedMfaDeviceRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task AuthenticateAsyncDoesNotUseRememberedDeviceWhenSupportIsNotEnabled()
    {
        var context = _context.WithRememberedMfaDeviceToken("remembered-token");
        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));
        _policyEvaluatorMock.Setup(e => e.EvaluateAsync(_userMock.Object, context, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaPolicyEvaluation(true, new MfaRequirement(["totp"])));
        _handshakeServiceMock.Setup(h => h.CreateHandshakeAsync(It.IsAny<CreateAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(new AuthenticationHandshakeCreated(
                new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "totp" }, new HashSet<string>()),
                "handshake-token")));
        var rememberedMfaDeviceService = CreateRememberedDeviceService(new ValidateRememberedMfaDeviceResult(true, CreateRememberedDeviceSummary(_userMock.Object.Id, null), RememberedMfaDeviceValidationStatus.Success));
        var orchestrator = CreateOrchestratorWithRememberedDevices(rememberedMfaDeviceService.Object);

        var result = await orchestrator.AuthenticateAsync(context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.MfaRequired));
            Assert.That(result.HandshakeToken, Is.EqualTo("handshake-token"));
        }

        rememberedMfaDeviceService.Verify(s => s.ValidateAsync(It.IsAny<Guid>(), It.IsAny<ValidateRememberedMfaDeviceRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task AuthenticateAsyncFallsBackToMfaHandshakeWhenRememberedSupportHasNoRegisteredService()
    {
        var context = _context.WithRememberedMfaDeviceToken("remembered-token");
        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));
        _policyEvaluatorMock.Setup(e => e.EvaluateAsync(_userMock.Object, context, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaPolicyEvaluation(true, new MfaRequirement(["totp"])));
        _handshakeServiceMock.Setup(h => h.CreateHandshakeAsync(It.IsAny<CreateAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(new AuthenticationHandshakeCreated(
                new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "totp" }, new HashSet<string>()),
                "handshake-token")));
        var orchestrator = new AuthenticationOrchestrator(
            _pipelineMock.Object,
            _factorPipelineMock.Object,
            _handshakeServiceMock.Object,
            _policyEvaluatorMock.Object,
            _providerRegistry,
            new AuthenticationOrchestratorDependencies(ServiceProvider: new ServiceCollection().BuildServiceProvider()));

        var result = await orchestrator.AuthenticateAsync(
            context,
            _assertionMock.Object,
            new MfaOrchestrationOptions { EnableRememberedMfaDevices = true });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.MfaRequired));
            Assert.That(result.HandshakeToken, Is.EqualTo("handshake-token"));
        }
    }

    [Test]
    public async Task AuthenticateAsyncDoesNotBypassProviderForcedMfaWithRememberedDeviceToken()
    {
        var context = _context.WithRememberedMfaDeviceToken("remembered-token");
        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(false, _userMock.Object, AuthenticationStatus.MfaRequired));
        _policyEvaluatorMock.Setup(e => e.EvaluateAsync(_userMock.Object, context, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaPolicyEvaluation(true, new MfaRequirement(["totp"])));
        _handshakeServiceMock.Setup(h => h.CreateHandshakeAsync(It.IsAny<CreateAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(new AuthenticationHandshakeCreated(
                new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "totp" }, new HashSet<string>()),
                "handshake-token")));
        var rememberedMfaDeviceService = CreateRememberedDeviceService(new ValidateRememberedMfaDeviceResult(true, CreateRememberedDeviceSummary(_userMock.Object.Id, null), RememberedMfaDeviceValidationStatus.Success));
        var orchestrator = CreateOrchestratorWithRememberedDevices(rememberedMfaDeviceService.Object);

        var result = await orchestrator.AuthenticateAsync(
            context,
            _assertionMock.Object,
            new MfaOrchestrationOptions { EnableRememberedMfaDevices = true });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.MfaRequired));
            Assert.That(result.HandshakeToken, Is.EqualTo("handshake-token"));
        }

        rememberedMfaDeviceService.Verify(s => s.ValidateAsync(It.IsAny<Guid>(), It.IsAny<ValidateRememberedMfaDeviceRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task AuthenticateAsyncStoresPrimaryCredentialKeyInHandshakeMetadata()
    {
        var providerKey = new AuthenticationProviderKey(ProviderType.Passkey, "passkey");
        var assertion = new TestCredentialKeyAssertion(providerKey, "credential-id");
        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), assertion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));
        _policyEvaluatorMock.Setup(e => e.EvaluateAsync(_userMock.Object, _context, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaPolicyEvaluation(true, new MfaRequirement(["passkey"])));
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "passkey" }, new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.CreateHandshakeAsync(It.IsAny<CreateAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(new AuthenticationHandshakeCreated(handshake, "token")));

        await _orchestrator.AuthenticateAsync(_context, assertion);

        _handshakeServiceMock.Verify(h => h.CreateHandshakeAsync(
            It.Is<CreateAuthenticationHandshakeRequest>(r =>
                r.Metadata != null
                && r.Metadata["primary_provider_type"] == providerKey.Type.Value
                && r.Metadata["primary_provider_name"] == providerKey.Name
                && r.Metadata["primary_credential_key"] == "credential-id"),
            It.IsAny<CancellationToken>()));
    }

    [Test]
    public async Task AuthenticateAsyncReturnsMfaRequiredWhenProviderRequiresMfa()
    {
        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(false, _userMock.Object, AuthenticationStatus.MfaRequired));

        var requiredFactors = new[] { "email_code" };
        _policyEvaluatorMock.Setup(e => e.EvaluateAsync(_userMock.Object, _context, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaPolicyEvaluation(true, new MfaRequirement(requiredFactors)));

        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, requiredFactors.ToHashSet(), new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.CreateHandshakeAsync(It.IsAny<CreateAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(new AuthenticationHandshakeCreated(handshake, "token")));

        var result = await _orchestrator.AuthenticateAsync(_context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.MfaRequired));
            Assert.That(result.HandshakeToken, Is.EqualTo("token"));
        }
    }

    [Test]
    public async Task AuthenticateAsyncUsesProviderMfaFactorsWhenPolicyHasNone()
    {
        var claims = new Dictionary<string, string> { ["mfa_factors"] = "totp, email_code, " };
        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(false, _userMock.Object, AuthenticationStatus.MfaRequired, claims));

        _policyEvaluatorMock.Setup(e => e.EvaluateAsync(_userMock.Object, _context, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaPolicyEvaluation(false));

        var requiredFactors = new HashSet<string> { "totp", "email_code" };
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, requiredFactors, new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.CreateHandshakeAsync(It.IsAny<CreateAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(new AuthenticationHandshakeCreated(handshake, "token")));

        var result = await _orchestrator.AuthenticateAsync(_context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.MfaRequired));
            Assert.That(result.HandshakeToken, Is.EqualTo("token"));
            Assert.That(result.RequiredFactors, Is.EquivalentTo(requiredFactors));
        }

        _handshakeServiceMock.Verify(h => h.CreateHandshakeAsync(
            It.Is<CreateAuthenticationHandshakeRequest>(r =>
                r.RequiredFactors.SequenceEqual(requiredFactors) &&
                r.Metadata != null && r.Metadata["claim:mfa_factors"] == "[\"totp, email_code, \"]"),
            It.IsAny<CancellationToken>()));
    }

    [Test]
    public async Task AuthenticateAsyncUsesConfiguredProviderMfaFactorsClaimName()
    {
        var claims = new Dictionary<string, string> { ["provider_factors"] = "email_code" };
        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(false, _userMock.Object, AuthenticationStatus.MfaRequired, claims));

        _policyEvaluatorMock.Setup(e => e.EvaluateAsync(_userMock.Object, _context, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaPolicyEvaluation(false));

        var requiredFactors = new HashSet<string> { "email_code" };
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, requiredFactors, new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.CreateHandshakeAsync(It.IsAny<CreateAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(new AuthenticationHandshakeCreated(handshake, "token")));

        var result = await _orchestrator.AuthenticateAsync(
            _context,
            _assertionMock.Object,
            new MfaOrchestrationOptions { ProviderFactorsClaimName = "provider_factors" });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.MfaRequired));
            Assert.That(result.RequiredFactors, Is.EquivalentTo(requiredFactors));
        }
    }

    [Test]
    public async Task AuthenticateAsyncUsesGlobalProviderMfaFactorsClaimNameWhenCallOptionsAreNull()
    {
        _orchestrator = new AuthenticationOrchestrator(
            _pipelineMock.Object,
            _factorPipelineMock.Object,
            _handshakeServiceMock.Object,
            _policyEvaluatorMock.Object,
            _providerRegistry,
            new AuthenticationOrchestratorDependencies(Options.Create(new MfaOrchestrationOptions { ProviderFactorsClaimName = "provider_factors" })));

        var claims = new Dictionary<string, string> { ["provider_factors"] = "email_code" };
        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(false, _userMock.Object, AuthenticationStatus.MfaRequired, claims));

        _policyEvaluatorMock.Setup(e => e.EvaluateAsync(_userMock.Object, _context, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaPolicyEvaluation(false));

        var requiredFactors = new HashSet<string> { "email_code" };
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, requiredFactors, new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.CreateHandshakeAsync(It.IsAny<CreateAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(new AuthenticationHandshakeCreated(handshake, "token")));

        var result = await _orchestrator.AuthenticateAsync(_context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.MfaRequired));
            Assert.That(result.RequiredFactors, Is.EquivalentTo(requiredFactors));
        }
    }

    [Test]
    public async Task AuthenticateAsyncFailsWhenProviderMfaFactorsClaimIsNull()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        var claims = new Dictionary<string, string> { ["mfa_factors"] = null! };
        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(false, _userMock.Object, AuthenticationStatus.MfaRequired, claims));

        _policyEvaluatorMock.Setup(e => e.EvaluateAsync(_userMock.Object, _context, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaPolicyEvaluation(false));

        var result = await _orchestrator.AuthenticateAsync(_context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(result.ErrorMessage, Is.EqualTo("MFA is required but no factors are configured."));
        }

        _handshakeServiceMock.Verify(h => h.CreateHandshakeAsync(It.IsAny<CreateAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task AuthenticateAsyncFailsWhenProviderMfaFactorsClaimIsWhitespace()
    {
        var claims = new Dictionary<string, string> { ["mfa_factors"] = "   " };
        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(false, _userMock.Object, AuthenticationStatus.MfaRequired, claims));
        _policyEvaluatorMock.Setup(e => e.EvaluateAsync(_userMock.Object, _context, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaPolicyEvaluation(false));

        var result = await _orchestrator.AuthenticateAsync(_context, _assertionMock.Object);

        Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
        _handshakeServiceMock.Verify(h => h.CreateHandshakeAsync(It.IsAny<CreateAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task AuthenticateAsyncFailsWhenProviderMfaFactorsClaimIsMissing()
    {
        var claims = new Dictionary<string, string>();
        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(false, _userMock.Object, AuthenticationStatus.MfaRequired, claims));
        _policyEvaluatorMock.Setup(e => e.EvaluateAsync(_userMock.Object, _context, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaPolicyEvaluation(false));

        var result = await _orchestrator.AuthenticateAsync(_context, _assertionMock.Object);

        Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
        _handshakeServiceMock.Verify(h => h.CreateHandshakeAsync(It.IsAny<CreateAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task AuthenticateAsyncDeduplicatesMfaFactorsIgnoringCase()
    {
        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));

        var requiredFactors = new[] { "TOTP", "totp" };
        _policyEvaluatorMock.Setup(e => e.EvaluateAsync(_userMock.Object, _context, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaPolicyEvaluation(true, new MfaRequirement(requiredFactors)));

        var handshakeFactors = new HashSet<string> { "TOTP" };
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, handshakeFactors, new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.CreateHandshakeAsync(It.IsAny<CreateAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(new AuthenticationHandshakeCreated(handshake, "token")));

        var result = await _orchestrator.AuthenticateAsync(_context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.MfaRequired));
            Assert.That(result.RequiredFactors, Is.EquivalentTo(handshakeFactors));
        }

        _handshakeServiceMock.Verify(h => h.CreateHandshakeAsync(
            It.Is<CreateAuthenticationHandshakeRequest>(r => r.RequiredFactors.SequenceEqual(handshakeFactors)),
            It.IsAny<CancellationToken>()));
    }

    [Test]
    public async Task AuthenticateAsyncPrefersPolicyFactorsOverProviderFactorsClaim()
    {
        var claims = new Dictionary<string, string> { ["mfa_factors"] = "email_code" };
        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success, claims));
        _policyEvaluatorMock.Setup(e => e.EvaluateAsync(_userMock.Object, _context, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaPolicyEvaluation(true, new MfaRequirement(["totp"])));
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "totp" }, new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.CreateHandshakeAsync(It.IsAny<CreateAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(new AuthenticationHandshakeCreated(handshake, "token")));

        var result = await _orchestrator.AuthenticateAsync(_context, _assertionMock.Object);

        Assert.That(result.RequiredFactors, Is.EquivalentTo(handshake.RequiredFactors));
    }

    [Test]
    public async Task AuthenticateAsyncTrimsAndDropsBlankPolicyFactors()
    {
        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));

        // ReSharper disable once NullableWarningSuppressionIsUsed
        var requiredFactors = new[] { " totp ", "", "   ", null! };
        _policyEvaluatorMock.Setup(e => e.EvaluateAsync(_userMock.Object, _context, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaPolicyEvaluation(true, new MfaRequirement(requiredFactors)));

        var handshakeFactors = new HashSet<string> { "totp" };
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, handshakeFactors, new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.CreateHandshakeAsync(It.IsAny<CreateAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(new AuthenticationHandshakeCreated(handshake, "token")));

        var result = await _orchestrator.AuthenticateAsync(_context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.MfaRequired));
            Assert.That(result.RequiredFactors, Is.EquivalentTo(handshakeFactors));
        }

        _handshakeServiceMock.Verify(h => h.CreateHandshakeAsync(
            It.Is<CreateAuthenticationHandshakeRequest>(r => r.RequiredFactors.SequenceEqual(handshakeFactors)),
            It.IsAny<CancellationToken>()));
    }

    [Test]
    public async Task AuthenticateAsyncFailsWhenPrimaryAuthFails()
    {
        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(false, Status: AuthenticationStatus.Failed));

        var result = await _orchestrator.AuthenticateAsync(_context, _assertionMock.Object);

        Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
    }

    [Test]
    public async Task AuthenticateAsyncFailsWhenUserIsDisabled()
    {
        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(false, _userMock.Object, AuthenticationStatus.Disabled));

        var result = await _orchestrator.AuthenticateAsync(_context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(result.ErrorMessage, Is.EqualTo("Authentication failed."));
        }
    }

    [Test]
    public async Task AuthenticateAsyncReturnsRateLimitedMessageWhenPrimaryAuthIsRateLimited()
    {
        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(false, Status: AuthenticationStatus.RateLimited));

        var result = await _orchestrator.AuthenticateAsync(_context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.RateLimited));
            Assert.That(result.ErrorMessage, Is.EqualTo("Rate limit exceeded."));
        }
    }

    [Test]
    public async Task AuthenticateAsyncFailsWhenUserIsNull()
    {
        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, User: null, Status: AuthenticationStatus.Success));

        var result = await _orchestrator.AuthenticateAsync(_context, _assertionMock.Object);

        Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
    }

    [Test]
    public async Task VerifyFactorAsyncSucceedsAndReturnsHandshakeIncomplete()
    {
        var handshakeId = Guid.NewGuid();
        var userId = _userMock.Object.Id;
        var requiredFactors = new HashSet<string> { "totp", "sms" };
        var remainingFactors = new[] { "sms" };
        var handshake = new AuthenticationHandshake(handshakeId, userId, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, requiredFactors, new HashSet<string>());

        _handshakeServiceMock.Setup(h => h.BeginFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(handshake));

        _factorPipelineMock.Setup(p => p.VerifyFactorAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));

        var updatedHandshake = handshake with { VerifiedFactors = new HashSet<string> { "totp" } };
        _handshakeServiceMock.Setup(h => h.CompleteFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(updatedHandshake));

        var result = await _orchestrator.VerifyFactorAsync("token", "totp", _context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.HandshakeIncomplete));
            Assert.That(result.User, Is.EqualTo(_userMock.Object));
            Assert.That(result.HandshakeToken, Is.EqualTo("token"));
            Assert.That(result.RequiredFactors, Is.EquivalentTo(remainingFactors));
        }
    }

    [Test]
    public async Task VerifyFactorAsyncUsesSecondaryFactorPipelineScopeOnly()
    {
        var pipeline = new Mock<IAuthenticationPipeline>(MockBehavior.Strict);
        var factorPipeline = new Mock<IAuthenticationFactorPipeline>(MockBehavior.Strict);
        var handshakeService = new Mock<IAuthenticationHandshakeService>(MockBehavior.Strict);
        var policyEvaluator = new Mock<IMfaPolicyEvaluator>(MockBehavior.Strict);
        var orchestrator = new AuthenticationOrchestrator(pipeline.Object, factorPipeline.Object, handshakeService.Object, policyEvaluator.Object, _providerRegistry);
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "totp", "sms" }, new HashSet<string>());
        var updatedHandshake = handshake with { VerifiedFactors = new HashSet<string> { "totp" } };

        handshakeService
            .Setup(h => h.BeginFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(handshake));
        factorPipeline
            .Setup(p => p.VerifyFactorAsync(
                It.IsAny<AuthenticationContext>(),
                _assertionMock.Object,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));
        handshakeService
            .Setup(h => h.CompleteFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(updatedHandshake));

        var result = await orchestrator.VerifyFactorAsync("token", "totp", _context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.HandshakeIncomplete));
            pipeline.Verify(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()), Times.Never);
            factorPipeline.Verify(p => p.VerifyFactorAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [Test]
    public async Task VerifyFactorAsyncFiltersPendingFactorsUsingFactorMatchingRules()
    {
        var handshakeId = Guid.NewGuid();
        var userId = _userMock.Object.Id;
        var requiredFactors = new HashSet<string> { "TOTP", "sms" };
        var remainingFactors = new[] { "sms" };
        var handshake = new AuthenticationHandshake(handshakeId, userId, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, requiredFactors, new HashSet<string>());

        _handshakeServiceMock.Setup(h => h.BeginFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(handshake));

        _factorPipelineMock.Setup(p => p.VerifyFactorAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));

        var updatedHandshake = handshake with { VerifiedFactors = new HashSet<string> { "totp" } };
        _handshakeServiceMock.Setup(h => h.CompleteFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(updatedHandshake));

        var result = await _orchestrator.VerifyFactorAsync("token", "TOTP", _context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.HandshakeIncomplete));
            Assert.That(result.RequiredFactors, Is.EquivalentTo(remainingFactors));
        }
    }

    [Test]
    public async Task VerifyFactorAsyncSucceedsAndReturnsSucceededWhenHandshakeCompleted()
    {
        var handshakeId = Guid.NewGuid();
        var userId = _userMock.Object.Id;
        var metadata = new Dictionary<string, string> { ["claim:role"] = "[\"admin\"]" };
        var handshake = new AuthenticationHandshake(handshakeId, userId, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "totp" }, new HashSet<string>(), metadata);

        _handshakeServiceMock.Setup(h => h.BeginFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(handshake));

        _factorPipelineMock.Setup(p => p.VerifyFactorAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success, new Dictionary<string, string> { ["new_claim"] = "new_val" }));

        var completedHandshake = handshake with { VerifiedFactors = new HashSet<string> { "totp" }, IsCompleted = true, Metadata = new Dictionary<string, string>(metadata) { ["claim:new_claim"] = "[\"new_val\"]" } };
        _handshakeServiceMock.Setup(h => h.CompleteFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(completedHandshake));

        var result = await _orchestrator.VerifyFactorAsync("token", "totp", _context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Succeeded));
            Assert.That(result.User, Is.EqualTo(_userMock.Object));
            Assert.That(result.Claims?["role"], Is.EqualTo(["admin"]));
            Assert.That(result.Claims?["new_claim"], Is.EqualTo(["new_val"]));
            Assert.That(result.FreshMfaSatisfied, Is.True);
        }
    }

    [Test]
    public async Task VerifyFactorAsyncFailsWhenHandshakeNotFound()
    {
        var logger = new RecordingLogger<AuthenticationOrchestrator>();
        var orchestrator = CreateOrchestrator(logger);
        _handshakeServiceMock.Setup(h => h.BeginFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure<AuthenticationHandshake>(AshlarFailureCodes.HandshakeNotFound));

        var result = await orchestrator.VerifyFactorAsync("token", "totp", _context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(result.ErrorMessage, Is.EqualTo("Handshake not found."));
            Assert.That(logger.Entries, Has.Some.Matches<LogEntry>(entry =>
                entry.Level == LogLevel.Debug
                && entry.Message.Contains("MFA factor verification rejected", StringComparison.Ordinal)
                && entry.Message.Contains("Reason=handshake_not_found", StringComparison.Ordinal)));
        }
    }

    [Test]
    public async Task VerifyFactorAsyncFailsWhenBeginReturnsNoHandshake()
    {
        var logger = new RecordingLogger<AuthenticationOrchestrator>();
        var orchestrator = CreateOrchestrator(logger);
        _handshakeServiceMock.Setup(h => h.BeginFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success<AuthenticationHandshake>(null!));

        var result = await orchestrator.VerifyFactorAsync("token", "totp", _context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(result.ErrorMessage, Is.EqualTo("Factor verification failed."));
            Assert.That(logger.Entries, Has.Some.Matches<LogEntry>(entry =>
                entry.Level == LogLevel.Debug
                && entry.Message.Contains("Reason=handshake_verification_failed", StringComparison.Ordinal)));
        }
    }

    [Test]
    public async Task VerifyFactorAsyncFailsWhenAssertionFails()
    {
        var logger = new RecordingLogger<AuthenticationOrchestrator>();
        var orchestrator = CreateOrchestrator(logger);
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "totp" }, new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.BeginFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(handshake));

        _factorPipelineMock.Setup(p => p.VerifyFactorAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(false, Status: AuthenticationStatus.Failed));

        var result = await orchestrator.VerifyFactorAsync("token", "totp", _context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(result.ErrorMessage, Is.EqualTo("Factor verification failed."));
            Assert.That(logger.Entries, Has.Some.Matches<LogEntry>(entry =>
                entry.Level == LogLevel.Debug
                && entry.Message.Contains("MFA factor verification rejected for handshake", StringComparison.Ordinal)
                && entry.Message.Contains("Reason=factor_authentication_failed", StringComparison.Ordinal)
                && entry.Message.Contains($"UserId={handshake.UserId}", StringComparison.Ordinal)));
        }
    }

    [Test]
    public async Task VerifyFactorAsyncFailsBeforeAuthenticationWhenHandshakeVerificationIsRateLimited()
    {
        var logger = new RecordingLogger<AuthenticationOrchestrator>();
        var orchestrator = CreateOrchestrator(logger);
        _handshakeServiceMock.Setup(h => h.BeginFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure<AuthenticationHandshake>(AshlarFailureCodes.RateLimitExceeded));

        var result = await orchestrator.VerifyFactorAsync("token", "totp", _context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.RateLimited));
            Assert.That(result.ErrorMessage, Is.EqualTo("Rate limit exceeded."));
            Assert.That(logger.Entries, Has.Some.Matches<LogEntry>(entry =>
                entry.Level == LogLevel.Debug
                && entry.Message.Contains("MFA factor verification rejected", StringComparison.Ordinal)
                && entry.Message.Contains("Reason=rate_limit_exceeded", StringComparison.Ordinal)));
        }

        _factorPipelineMock.Verify(p => p.VerifyFactorAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()), Times.Never);
        _handshakeServiceMock.Verify(h => h.CompleteFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task VerifyFactorAsyncFailsWhenAssertionReturnsNoUser()
    {
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "totp" }, new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.BeginFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(handshake));

        _factorPipelineMock.Setup(p => p.VerifyFactorAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, User: null, AuthenticationStatus.Success));

        var result = await _orchestrator.VerifyFactorAsync("token", "totp", _context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(result.ErrorMessage, Is.EqualTo("Factor verification failed."));
        }
    }

    [Test]
    public async Task VerifyFactorAsyncMapsDisabledUserConsistently()
    {
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "totp" }, new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.BeginFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(handshake));

        _factorPipelineMock.Setup(p => p.VerifyFactorAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(false, _userMock.Object, AuthenticationStatus.Disabled));

        var result = await _orchestrator.VerifyFactorAsync("token", "totp", _context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(result.ErrorMessage, Is.EqualTo("Authentication failed."));
        }
    }

    [Test]
    public async Task VerifyFactorAsyncMapsFactorRateLimitConsistently()
    {
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "totp" }, new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.BeginFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(handshake));

        _factorPipelineMock.Setup(p => p.VerifyFactorAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(false, Status: AuthenticationStatus.RateLimited));

        var result = await _orchestrator.VerifyFactorAsync("token", "totp", _context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.RateLimited));
            Assert.That(result.ErrorMessage, Is.EqualTo("Rate limit exceeded."));
        }
    }

    [Test]
    public async Task VerifyFactorAsyncFailsWhenAssertionProviderDoesNotMatchFactor()
    {
        var logger = new RecordingLogger<AuthenticationOrchestrator>();
        var orchestrator = CreateOrchestrator(logger);
        var passwordAssertion = new Mock<IAuthenticationAssertion>();
        passwordAssertion.Setup(a => a.ProviderIdentity).Returns(AuthenticationProviderKey.Local);
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "totp" }, new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.BeginFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(handshake));

        var result = await orchestrator.VerifyFactorAsync("token", "totp", _context, passwordAssertion.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(result.ErrorMessage, Is.EqualTo("Factor verification failed."));
            Assert.That(logger.Entries, Has.Some.Matches<LogEntry>(entry =>
                entry.Level == LogLevel.Debug
                && entry.Message.Contains("MFA factor verification rejected for handshake", StringComparison.Ordinal)
                && entry.Message.Contains("Reason=assertion_not_authorized_for_factor", StringComparison.Ordinal)
                && entry.Message.Contains($"UserId={handshake.UserId}", StringComparison.Ordinal)));
        }

        _factorPipelineMock.Verify(p => p.VerifyFactorAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()), Times.Never);
        _handshakeServiceMock.Verify(h => h.CompleteFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task VerifyFactorAsyncFailsBeforeAuthenticationWhenFactorReusesPrimaryCredential()
    {
        var logger = new RecordingLogger<AuthenticationOrchestrator>();
        var orchestrator = CreateOrchestrator(logger);
        var providerKey = new AuthenticationProviderKey(ProviderType.Passkey, "passkey");
        var assertion = new TestCredentialKeyAssertion(providerKey, "credential-id");
        var metadata = new Dictionary<string, string>
        {
            ["primary_provider_type"] = providerKey.Type.Value,
            ["primary_provider_name"] = providerKey.Name,
            ["primary_credential_key"] = "credential-id"
        };
        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            _userMock.Object.Id,
            "hash",
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddMinutes(5),
            false,
            false,
            new HashSet<string> { "passkey" },
            new HashSet<string>(),
            metadata);
        _handshakeServiceMock.Setup(h => h.BeginFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(handshake));

        var result = await orchestrator.VerifyFactorAsync("token", "passkey", _context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(result.ErrorMessage, Is.EqualTo("Factor verification failed."));
            Assert.That(logger.Entries, Has.Some.Matches<LogEntry>(entry =>
                entry.Level == LogLevel.Debug
                && entry.Message.Contains("MFA factor verification rejected for handshake", StringComparison.Ordinal)
                && entry.Message.Contains("Reason=factor_reuses_primary_credential", StringComparison.Ordinal)
                && entry.Message.Contains($"UserId={handshake.UserId}", StringComparison.Ordinal)));
        }

        _factorPipelineMock.Verify(p => p.VerifyFactorAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()), Times.Never);
        _handshakeServiceMock.Verify(h => h.CompleteFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task VerifyFactorAsyncAllowsCredentialAssertionWhenPrimaryMetadataIsIncomplete()
    {
        var assertion = new TestCredentialKeyAssertion(new AuthenticationProviderKey(ProviderType.Passkey, "passkey"), "credential-id");
        var metadataValues = new[]
        {
            [],
            new Dictionary<string, string> { ["primary_provider_type"] = ProviderType.Passkey.Value },
            new Dictionary<string, string> { ["primary_provider_type"] = ProviderType.Passkey.Value, ["primary_provider_name"] = "passkey" },
            new Dictionary<string, string>
            {
                ["primary_provider_type"] = ProviderType.Local.Value,
                ["primary_provider_name"] = "passkey",
                ["primary_credential_key"] = "credential-id"
            },
            new Dictionary<string, string>
            {
                ["primary_provider_type"] = ProviderType.Passkey.Value,
                ["primary_provider_name"] = "other",
                ["primary_credential_key"] = "credential-id"
            },
            new Dictionary<string, string>
            {
                ["primary_provider_type"] = ProviderType.Passkey.Value,
                ["primary_provider_name"] = "passkey",
                ["primary_credential_key"] = "other"
            }
        };

        foreach (var metadata in metadataValues)
        {
            var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "passkey" }, new HashSet<string>(), metadata);
            _handshakeServiceMock.Reset();
            _pipelineMock.Reset();
            _handshakeServiceMock.Setup(h => h.BeginFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result.Success(handshake));
            _factorPipelineMock.Setup(p => p.VerifyFactorAsync(It.IsAny<AuthenticationContext>(), assertion, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));
            _handshakeServiceMock.Setup(h => h.CompleteFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result.Success(handshake with { IsCompleted = true, VerifiedFactors = new HashSet<string> { "passkey" } }));

            var result = await _orchestrator.VerifyFactorAsync("token", "passkey", _context, assertion);

            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Succeeded));
        }
    }

    [Test]
    public async Task VerifyFactorAsyncFailsBeforeAuthenticationWhenFactorIsNotRequired()
    {
        var logger = new RecordingLogger<AuthenticationOrchestrator>();
        var orchestrator = CreateOrchestrator(logger);
        _handshakeServiceMock.Setup(h => h.BeginFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure<AuthenticationHandshake>(AshlarFailureCodes.InvalidFactorType));

        var result = await orchestrator.VerifyFactorAsync("token", "totp", _context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(result.ErrorMessage, Is.EqualTo("Invalid factor type."));
            Assert.That(logger.Entries, Has.Some.Matches<LogEntry>(entry =>
                entry.Level == LogLevel.Debug
                && entry.Message.Contains("MFA factor verification rejected", StringComparison.Ordinal)
                && entry.Message.Contains("Reason=invalid_factor_type", StringComparison.Ordinal)));
        }

        _factorPipelineMock.Verify(p => p.VerifyFactorAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()), Times.Never);
        _handshakeServiceMock.Verify(h => h.CompleteFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task VerifyFactorAsyncRejectsWhitespaceOnlyRequiredFactor()
    {
        _handshakeServiceMock.Setup(h => h.BeginFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure<AuthenticationHandshake>(AshlarFailureCodes.InvalidFactorType));

        var result = await _orchestrator.VerifyFactorAsync("token", "_", _context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(result.ErrorMessage, Is.EqualTo("Invalid factor type."));
        }

        _factorPipelineMock.Verify(p => p.VerifyFactorAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task VerifyFactorAsyncForwardsCanonicalRequiredFactor()
    {
        var assertion = new Mock<IAuthenticationAssertion>();
        assertion.Setup(a => a.ProviderIdentity).Returns(new AuthenticationProviderKey("totp", "totp"));
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "TOTP" }, new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.BeginFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(handshake));

        _factorPipelineMock.Setup(p => p.VerifyFactorAsync(It.IsAny<AuthenticationContext>(), assertion.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));

        var completedHandshake = handshake with { VerifiedFactors = new HashSet<string> { "TOTP" }, IsCompleted = true };
        _handshakeServiceMock.Setup(h => h.CompleteFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(completedHandshake));

        var result = await _orchestrator.VerifyFactorAsync("token", "totp", _context, assertion.Object);

        Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Succeeded));
        _handshakeServiceMock.Verify(h => h.CompleteFactorVerificationAsync(
            It.Is<VerifyAuthenticationHandshakeRequest>(r => r.FactorType == "TOTP"),
            It.IsAny<CancellationToken>()));
    }

    [Test]
    public async Task VerifyFactorAsyncRejectsInconsistentHandshakeFactor()
    {
        var assertion = new Mock<IAuthenticationAssertion>();
        assertion.Setup(a => a.ProviderIdentity).Returns(new AuthenticationProviderKey("totp", "totp"));
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string>(), new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.BeginFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(handshake));

        var result = await _orchestrator.VerifyFactorAsync("token", "totp", _context, assertion.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(result.ErrorMessage, Is.EqualTo("Invalid factor type."));
        }

        _factorPipelineMock.Verify(p => p.VerifyFactorAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()), Times.Never);
        _handshakeServiceMock.Verify(h => h.CompleteFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task VerifyFactorAsyncAuthorizesCustomSecondaryProviderByFactorType()
    {
        var providerKey = new AuthenticationProviderKey("Custom", "StepUpThing");
        var assertion = new Mock<IAuthenticationAssertion>();
        assertion.Setup(a => a.ProviderIdentity).Returns(providerKey);
        var providerRegistry = CreateProviderRegistry(CreateSecondaryProvider(providerKey, "custom_step_up"));
        var orchestrator = new AuthenticationOrchestrator(
            _pipelineMock.Object,
            _factorPipelineMock.Object,
            _handshakeServiceMock.Object,
            _policyEvaluatorMock.Object,
            providerRegistry);
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "custom_step_up" }, new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.BeginFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(handshake));

        _factorPipelineMock.Setup(p => p.VerifyFactorAsync(It.IsAny<AuthenticationContext>(), assertion.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));

        var completedHandshake = handshake with { VerifiedFactors = new HashSet<string> { "custom_step_up" }, IsCompleted = true };
        _handshakeServiceMock.Setup(h => h.CompleteFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(completedHandshake));

        var result = await orchestrator.VerifyFactorAsync("token", "custom-step-up", _context, assertion.Object);

        Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Succeeded));
        _handshakeServiceMock.Verify(h => h.CompleteFactorVerificationAsync(
            It.Is<VerifyAuthenticationHandshakeRequest>(r => r.FactorType == "custom_step_up"),
            It.IsAny<CancellationToken>()));
    }

    [Test]
    public async Task VerifyFactorAsyncAllowsRecoveryCodeToSatisfyNextPendingFactor()
    {
        var providerKey = new AuthenticationProviderKey(ProviderType.RecoveryCode, "RecoveryCode");
        var assertion = new Mock<IAuthenticationAssertion>();
        assertion.Setup(a => a.ProviderIdentity).Returns(providerKey);
        var recoveryProvider = new Mock<ISecondaryAuthenticationFactorProvider>();
        recoveryProvider.SetupGet(item => item.Key).Returns(providerKey);
        recoveryProvider.SetupGet(item => item.FactorType).Returns(AuthenticationFactorTypes.RecoveryCode);
        recoveryProvider.Setup(item => item.CanSatisfyFactor(It.IsAny<string>())).Returns<string>(factorType => !string.IsNullOrWhiteSpace(factorType));
        var providerRegistry = CreateProviderRegistry(recoveryProvider.Object);
        var orchestrator = new AuthenticationOrchestrator(
            _pipelineMock.Object,
            _factorPipelineMock.Object,
            _handshakeServiceMock.Object,
            _policyEvaluatorMock.Object,
            providerRegistry);
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "totp", "passkey" }, new HashSet<string> { "totp" });
        _handshakeServiceMock.Setup(h => h.BeginFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(handshake));

        _factorPipelineMock.Setup(p => p.VerifyFactorAsync(It.IsAny<AuthenticationContext>(), assertion.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));

        var completedHandshake = handshake with { VerifiedFactors = new HashSet<string> { "totp", "passkey" }, IsCompleted = true };
        _handshakeServiceMock.Setup(h => h.CompleteFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(completedHandshake));

        var result = await orchestrator.VerifyFactorAsync("token", AuthenticationFactorTypes.RecoveryCode, _context, assertion.Object);

        Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Succeeded));
        _handshakeServiceMock.Verify(h => h.BeginFactorVerificationAsync(
            It.Is<VerifyAuthenticationHandshakeRequest>(r => r.FactorType == AuthenticationFactorTypes.RecoveryCode),
            It.IsAny<CancellationToken>()));
        _handshakeServiceMock.Verify(h => h.CompleteFactorVerificationAsync(
            It.Is<VerifyAuthenticationHandshakeRequest>(r => r.FactorType == "passkey"),
            It.IsAny<CancellationToken>()));
    }

    [Test]
    public async Task VerifyFactorAsyncFailsBeforeAuthenticationWhenFactorAlreadyVerified()
    {
        var logger = new RecordingLogger<AuthenticationOrchestrator>();
        var orchestrator = CreateOrchestrator(logger);
        _handshakeServiceMock.Setup(h => h.BeginFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure<AuthenticationHandshake>(AshlarFailureCodes.FactorAlreadyVerified));

        var result = await orchestrator.VerifyFactorAsync("token", "TOTP", _context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(result.ErrorMessage, Is.EqualTo("Factor already verified."));
            Assert.That(logger.Entries, Has.Some.Matches<LogEntry>(entry =>
                entry.Level == LogLevel.Debug
                && entry.Message.Contains("MFA factor verification rejected", StringComparison.Ordinal)
                && entry.Message.Contains("Reason=factor_already_verified", StringComparison.Ordinal)));
        }

        _factorPipelineMock.Verify(p => p.VerifyFactorAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()), Times.Never);
        _handshakeServiceMock.Verify(h => h.CompleteFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task VerifyFactorAsyncFailsWhenAssertionProviderIdentityIsUninitialized()
    {
        var assertion = new Mock<IAuthenticationAssertion>();
        assertion.Setup(a => a.ProviderIdentity).Returns(default(AuthenticationProviderKey));
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "totp" }, new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.BeginFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(handshake));

        var result = await _orchestrator.VerifyFactorAsync("token", "totp", _context, assertion.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(result.ErrorMessage, Is.EqualTo("Factor verification failed."));
        }

        _factorPipelineMock.Verify(p => p.VerifyFactorAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task VerifyFactorAsyncDoesNotMatchDifferentSymbolOnlyFactors()
    {
        var assertion = new Mock<IAuthenticationAssertion>();
        var providerKey = new AuthenticationProviderKey("Custom", "SymbolFactor");
        assertion.Setup(a => a.ProviderIdentity).Returns(providerKey);
        var providerRegistry = CreateProviderRegistry(CreateSecondaryProvider(providerKey, "-"));
        var orchestrator = new AuthenticationOrchestrator(
            _pipelineMock.Object,
            _factorPipelineMock.Object,
            _handshakeServiceMock.Object,
            _policyEvaluatorMock.Object,
            providerRegistry);
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "_" }, new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.BeginFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(handshake));

        var result = await orchestrator.VerifyFactorAsync("token", "_", _context, assertion.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(result.ErrorMessage, Is.EqualTo("Factor verification failed."));
        }

        _factorPipelineMock.Verify(p => p.VerifyFactorAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task VerifyFactorAsyncFailsWhenUserIdMismatch()
    {
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), Guid.NewGuid(), "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "totp" }, new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.BeginFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(handshake));

        _factorPipelineMock.Setup(p => p.VerifyFactorAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));

        var result = await _orchestrator.VerifyFactorAsync("token", "totp", _context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(result.ErrorMessage, Is.EqualTo("Factor verification failed."));
        }
    }

    [Test]
    public async Task VerifyFactorAsyncFailsWhenHandshakeServiceFails()
    {
        var logger = new RecordingLogger<AuthenticationOrchestrator>();
        var orchestrator = CreateOrchestrator(logger);
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "totp" }, new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.BeginFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(handshake));

        _factorPipelineMock.Setup(p => p.VerifyFactorAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));

        _handshakeServiceMock.Setup(h => h.CompleteFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure<AuthenticationHandshake>(AshlarFailureCodes.HandshakeExpired));

        var result = await orchestrator.VerifyFactorAsync("token", "totp", _context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(result.ErrorMessage, Is.EqualTo("Handshake has expired."));
            Assert.That(logger.Entries, Has.Some.Matches<LogEntry>(entry =>
                entry.Level == LogLevel.Warning
                && entry.Message.Contains("MFA handshake operation failed", StringComparison.Ordinal)
                && entry.Message.Contains("FailureReason=handshake_expired", StringComparison.Ordinal)
                && entry.Message.Contains($"UserId={handshake.UserId}", StringComparison.Ordinal)));
        }
    }

    [TestCase("empty_token", "Handshake token is required.")]
    [TestCase("handshake_not_found", "Handshake not found.")]
    [TestCase("handshake_revoked", "Handshake is no longer valid.")]
    [TestCase("handshake_already_completed", "Handshake has already been completed.")]
    [TestCase("rate_limit_exceeded", "Rate limit exceeded.")]
    [TestCase("invalid_factor_type", "Invalid factor type.")]
    [TestCase("factor_already_verified", "Factor already verified.")]
    [TestCase("invalid_metadata", "Invalid metadata.")]
    public async Task VerifyFactorAsyncMapsHandshakeFailureReasonsToPublicMessages(string failureReason, string expectedMessage)
    {
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "totp" }, new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.BeginFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(handshake));

        _factorPipelineMock.Setup(p => p.VerifyFactorAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));

        _handshakeServiceMock.Setup(h => h.CompleteFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure<AuthenticationHandshake>(new AshlarFailureCode(failureReason)));

        var result = await _orchestrator.VerifyFactorAsync("token", "totp", _context, _assertionMock.Object);

        Assert.That(result.ErrorMessage, Is.EqualTo(expectedMessage));
    }

    [Test]
    public async Task VerifyFactorAsyncUsesDefaultErrorWhenHandshakeServiceFailsWithUnknownReason()
    {
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "totp" }, new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.BeginFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(handshake));

        _factorPipelineMock.Setup(p => p.VerifyFactorAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));

        _handshakeServiceMock.Setup(h => h.CompleteFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure<AuthenticationHandshake>(new AshlarFailureCode("unexpected_internal_reason")));

        var result = await _orchestrator.VerifyFactorAsync("token", "totp", _context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(result.ErrorMessage, Is.EqualTo("Factor verification failed."));
        }
    }

    [Test]
    public async Task VerifyFactorAsyncUsesDefaultErrorWhenHandshakeServiceFailsWithoutDetails()
    {
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "totp" }, new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.BeginFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(handshake));

        _factorPipelineMock.Setup(p => p.VerifyFactorAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));

        _handshakeServiceMock.Setup(h => h.CompleteFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Result<AuthenticationHandshake>(false));

        var result = await _orchestrator.VerifyFactorAsync("token", "totp", _context, _assertionMock.Object);

        Assert.That(result.ErrorMessage, Is.EqualTo("Factor verification failed."));
    }

    [TestCase("no_factors_specified", "MFA is required but no factors are configured.")]
    [TestCase("invalid_metadata", "Invalid metadata.")]
    [TestCase("unexpected_internal_reason", "Failed to create MFA handshake.")]
    public async Task AuthenticateAsyncMapsHandshakeCreationFailureReasonsToPublicMessages(string failureReason, string expectedMessage)
    {
        var logger = new RecordingLogger<AuthenticationOrchestrator>();
        var orchestrator = CreateOrchestrator(logger);
        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));

        _policyEvaluatorMock.Setup(e => e.EvaluateAsync(_userMock.Object, _context, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaPolicyEvaluation(true, new MfaRequirement(["totp"])));

        _handshakeServiceMock.Setup(h => h.CreateHandshakeAsync(It.IsAny<CreateAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure<AuthenticationHandshakeCreated>(new AshlarFailureCode(failureReason)));

        var result = await orchestrator.AuthenticateAsync(_context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(result.ErrorMessage, Is.EqualTo(expectedMessage));
            Assert.That(logger.Entries, Has.Some.Matches<LogEntry>(entry =>
                entry.Level == LogLevel.Warning
                && entry.Message.Contains("MFA handshake operation failed", StringComparison.Ordinal)
                && entry.Message.Contains($"FailureReason={failureReason}", StringComparison.Ordinal)
                && entry.Message.Contains($"UserId={_userMock.Object.Id}", StringComparison.Ordinal)));
        }
    }

    [Test]
    public async Task AuthenticateAsyncUsesDefaultErrorWhenHandshakeCreationFailsWithoutDetails()
    {
        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));

        _policyEvaluatorMock.Setup(e => e.EvaluateAsync(_userMock.Object, _context, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaPolicyEvaluation(true, new MfaRequirement(["totp"])));

        _handshakeServiceMock.Setup(h => h.CreateHandshakeAsync(It.IsAny<CreateAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Result<AuthenticationHandshakeCreated>(false));

        var result = await _orchestrator.AuthenticateAsync(_context, _assertionMock.Object);

        Assert.That(result.ErrorMessage, Is.EqualTo("Failed to create MFA handshake."));
    }

    [Test]
    public void VerifyFactorAsyncThrowsWhenAssertionIsNull()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(() => _orchestrator.VerifyFactorAsync("token", "totp", _context, assertion: null!));
    }

    [Test]
    public async Task MfaPolicyEvaluatorDefaultsToNoMfa()
    {
        var evaluator = new MfaPolicyEvaluator();
        var result = await evaluator.EvaluateAsync(_userMock.Object, _context);
        Assert.That(result.IsMfaRequired, Is.False);
    }

    [Test]
    public void RememberedMfaDeviceContextHelpersHandleNullAndWhitespaceItems()
    {
        var context = new AuthenticationContext().WithRememberedMfaDeviceToken("remembered-token");
        var contextWithExistingItems = new AuthenticationContext(Items: new Dictionary<string, string> { ["other"] = "value" })
            .WithRememberedMfaDeviceToken("existing-items-token");
        var blankContext = new AuthenticationContext(Items: new Dictionary<string, string>
        {
            [AuthenticationContextItemKeys.RememberedMfaDeviceToken] = " "
        });

        var found = context.TryGetRememberedMfaDeviceToken(out var token);
        var blankFound = blankContext.TryGetRememberedMfaDeviceToken(out var blankToken);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(found, Is.True);
            Assert.That(token, Is.EqualTo("remembered-token"));
            Assert.That(contextWithExistingItems.Items?["other"], Is.EqualTo("value"));
            Assert.That(contextWithExistingItems.Items?[AuthenticationContextItemKeys.RememberedMfaDeviceToken], Is.EqualTo("existing-items-token"));
            Assert.That(blankFound, Is.False);
            Assert.That(blankToken, Is.Empty);
            Assert.Throws<ArgumentNullException>(() => AuthenticationContextItemExtensions.WithRememberedMfaDeviceToken(null!, "token"));
            Assert.Throws<ArgumentException>(() => new AuthenticationContext().WithRememberedMfaDeviceToken(" "));
            Assert.Throws<ArgumentNullException>(() => AuthenticationContextItemExtensions.TryGetRememberedMfaDeviceToken(null!, out _));
        }
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void MfaPolicyEvaluatorThrowsWhenArgumentsAreNull()
    {
        var evaluator = new MfaPolicyEvaluator();

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentNullException>(() => evaluator.EvaluateAsync(null!, _context));
            Assert.ThrowsAsync<ArgumentNullException>(() => evaluator.EvaluateAsync(_userMock.Object, null!));
        }
    }

    [Test]
    public async Task AuthenticateAsyncReturnsFailedWhenPolicyRequiresMfaButNoFactorsSpecified()
    {
        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));

        _policyEvaluatorMock.Setup(e => e.EvaluateAsync(_userMock.Object, _context, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaPolicyEvaluation(true));

        var result = await _orchestrator.AuthenticateAsync(_context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(result.ErrorMessage, Is.EqualTo("MFA is required but no factors are configured."));
        }
    }

    [Test]
    public async Task VerifyFactorAsyncSucceedsWhenHandshakeMetadataIsNull()
    {
        var handshakeId = Guid.NewGuid();
        var userId = _userMock.Object.Id;
        var handshake = new AuthenticationHandshake(handshakeId, userId, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "totp" }, new HashSet<string>());

        _handshakeServiceMock.Setup(h => h.BeginFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(handshake));

        _factorPipelineMock.Setup(p => p.VerifyFactorAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));

        var completedHandshake = handshake with { VerifiedFactors = new HashSet<string> { "totp" }, IsCompleted = true };
        _handshakeServiceMock.Setup(h => h.CompleteFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(completedHandshake));

        var result = await _orchestrator.VerifyFactorAsync("token", "totp", _context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Succeeded));
            Assert.That(result.User, Is.EqualTo(_userMock.Object));
            Assert.That(result.Claims, Is.Empty);
        }
    }

    [Test]
    public async Task VerifyFactorAsyncSucceedsWhenHandshakeMetadataHasNoClaims()
    {
        var handshakeId = Guid.NewGuid();
        var userId = _userMock.Object.Id;
        var metadata = new Dictionary<string, string> { ["other"] = "value" };
        var handshake = new AuthenticationHandshake(handshakeId, userId, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "totp" }, new HashSet<string>(), metadata);

        _handshakeServiceMock.Setup(h => h.BeginFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(handshake));

        _factorPipelineMock.Setup(p => p.VerifyFactorAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));

        var completedHandshake = handshake with { VerifiedFactors = new HashSet<string> { "totp" }, IsCompleted = true, Metadata = metadata };
        _handshakeServiceMock.Setup(h => h.CompleteFactorVerificationAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(completedHandshake));

        var result = await _orchestrator.VerifyFactorAsync("token", "totp", _context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Succeeded));
            Assert.That(result.User, Is.EqualTo(_userMock.Object));
            Assert.That(result.Claims, Is.Empty);
        }
    }

    private AuthenticationOrchestrator CreateOrchestrator(RecordingLogger<AuthenticationOrchestrator> logger)
    {
        return new AuthenticationOrchestrator(
            _pipelineMock.Object,
            _factorPipelineMock.Object,
            _handshakeServiceMock.Object,
            _policyEvaluatorMock.Object,
            _providerRegistry,
            new AuthenticationOrchestratorDependencies(Logger: logger));
    }

    private AuthenticationOrchestrator CreateOrchestratorWithRememberedDevices(IRememberedMfaDeviceService rememberedMfaDeviceService)
    {
        var services = new ServiceCollection();
        services.AddSingleton(rememberedMfaDeviceService);
        var provider = services.BuildServiceProvider();
        return new AuthenticationOrchestrator(
            _pipelineMock.Object,
            _factorPipelineMock.Object,
            _handshakeServiceMock.Object,
            _policyEvaluatorMock.Object,
            _providerRegistry,
            new AuthenticationOrchestratorDependencies(ServiceProvider: provider));
    }

    private static Mock<IRememberedMfaDeviceService> CreateRememberedDeviceService(ValidateRememberedMfaDeviceResult result)
    {
        var service = new Mock<IRememberedMfaDeviceService>();
        service
            .Setup(s => s.ValidateAsync(It.IsAny<Guid>(), It.IsAny<ValidateRememberedMfaDeviceRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(result);
        return service;
    }

    private static RememberedMfaDeviceSummary CreateRememberedDeviceSummary(Guid userId, Guid? tenantId)
    {
        var now = DateTimeOffset.UtcNow;
        return new RememberedMfaDeviceSummary(Guid.NewGuid(), userId, tenantId, null, now, now, now.AddDays(30), null, null, true);
    }

    private static AuthenticationProviderRegistry CreateProviderRegistry(params IAuthenticationProvider[] providers)
    {
        return new AuthenticationProviderRegistry(
        [
            CreatePrimaryProvider(AuthenticationProviderKey.Local),
            CreateSecondaryProvider(new AuthenticationProviderKey("totp", "totp"), AuthenticationFactorTypes.Totp),
            CreatePasskeyProvider(),
            .. providers
        ]);
    }

    private static IAuthenticationProvider CreatePrimaryProvider(AuthenticationProviderKey providerKey)
    {
        var provider = new Mock<IPrimaryAuthenticationProvider>();
        provider.SetupGet(item => item.Key).Returns(providerKey);
        return provider.Object;
    }

    private static IAuthenticationProvider CreateSecondaryProvider(AuthenticationProviderKey providerKey, string factorType)
    {
        var provider = new Mock<ISecondaryAuthenticationFactorProvider>();
        provider.SetupGet(item => item.Key).Returns(providerKey);
        provider.SetupGet(item => item.FactorType).Returns(factorType);
        provider.Setup(item => item.CanSatisfyFactor(It.IsAny<string>()))
            .Returns<string>(requiredFactor => AuthenticationFactorTypes.Matches(factorType, requiredFactor));
        return provider.Object;
    }

    private static IAuthenticationProvider CreatePasskeyProvider()
    {
        var provider = new Mock<IPrimaryAuthenticationProvider>();
        provider.SetupGet(item => item.Key).Returns(AuthenticationProviderKey.Passkey);
        provider.As<ISecondaryAuthenticationFactorProvider>()
            .SetupGet(item => item.Key)
            .Returns(AuthenticationProviderKey.Passkey);
        provider.As<ISecondaryAuthenticationFactorProvider>()
            .SetupGet(item => item.FactorType)
            .Returns(AuthenticationFactorTypes.Passkey);
        provider.As<ISecondaryAuthenticationFactorProvider>()
            .Setup(item => item.CanSatisfyFactor(It.IsAny<string>()))
            .Returns<string>(requiredFactor => AuthenticationFactorTypes.Matches(AuthenticationFactorTypes.Passkey, requiredFactor));
        return provider.Object;
    }

    private sealed record TestCredentialKeyAssertion(AuthenticationProviderKey ProviderIdentity, string CredentialKey) : ICredentialKeyAuthenticationAssertion;
}
