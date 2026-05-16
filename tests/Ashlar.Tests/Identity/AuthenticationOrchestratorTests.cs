using System.Diagnostics.CodeAnalysis;
using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Microsoft.Extensions.Options;
using Moq;

namespace Ashlar.Tests.Identity;

[TestFixture]
public class AuthenticationOrchestratorTests
{
    private Mock<IAuthenticationPipeline> _pipelineMock;
    private Mock<IAuthenticationHandshakeService> _handshakeServiceMock;
    private Mock<IMfaPolicyEvaluator> _policyEvaluatorMock;
    private AuthenticationOrchestrator _orchestrator;
    private AuthenticationContext _context;
    private Mock<IAuthenticationAssertion> _assertionMock;
    private Mock<IUser> _userMock;

    [SetUp]
    public void SetUp()
    {
        _pipelineMock = new Mock<IAuthenticationPipeline>();
        _handshakeServiceMock = new Mock<IAuthenticationHandshakeService>();
        _policyEvaluatorMock = new Mock<IMfaPolicyEvaluator>();
        _orchestrator = new AuthenticationOrchestrator(
            _pipelineMock.Object,
            _handshakeServiceMock.Object,
            _policyEvaluatorMock.Object);

        _context = new AuthenticationContext(IpAddress: "127.0.0.1", UserAgent: "TestAgent");
        _assertionMock = new Mock<IAuthenticationAssertion>();
        _assertionMock.Setup(a => a.ProviderIdentity).Returns(new AuthenticationProviderKey("totp", "totp"));
        _userMock = new Mock<IUser>();
        _userMock.Setup(u => u.Id).Returns(Guid.NewGuid());
        _userMock.Setup(u => u.IsActive).Returns(true);
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
            Assert.That(result.Claims, Is.EqualTo(claims));
        }
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void ConstructorThrowsWhenDependenciesAreNull()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationOrchestrator(null!, _handshakeServiceMock.Object, _policyEvaluatorMock.Object));
            Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationOrchestrator(_pipelineMock.Object, null!, _policyEvaluatorMock.Object));
            Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationOrchestrator(_pipelineMock.Object, _handshakeServiceMock.Object, null!));
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
                r.Metadata != null && r.Metadata["claim:test"] == "value"),
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
                r.Metadata != null && r.Metadata["claim:mfa_factors"] == "totp, email_code, "),
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
            _handshakeServiceMock.Object,
            _policyEvaluatorMock.Object,
            Options.Create(new MfaOrchestrationOptions { ProviderFactorsClaimName = "provider_factors" }));

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
            Assert.That(result.ErrorMessage, Is.EqualTo("User is disabled."));
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

        _handshakeServiceMock.Setup(h => h.GetHandshakeAsync("token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));

        var updatedHandshake = handshake with { VerifiedFactors = new HashSet<string> { "totp" } };
        _handshakeServiceMock.Setup(h => h.VerifyFactorAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
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
    public async Task VerifyFactorAsyncFiltersPendingFactorsUsingFactorMatchingRules()
    {
        var handshakeId = Guid.NewGuid();
        var userId = _userMock.Object.Id;
        var requiredFactors = new HashSet<string> { "TOTP", "sms" };
        var remainingFactors = new[] { "sms" };
        var handshake = new AuthenticationHandshake(handshakeId, userId, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, requiredFactors, new HashSet<string>());

        _handshakeServiceMock.Setup(h => h.GetHandshakeAsync("token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));

        var updatedHandshake = handshake with { VerifiedFactors = new HashSet<string> { "totp" } };
        _handshakeServiceMock.Setup(h => h.VerifyFactorAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
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
        var metadata = new Dictionary<string, string> { ["claim:role"] = "admin" };
        var handshake = new AuthenticationHandshake(handshakeId, userId, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "totp" }, new HashSet<string>(), metadata);

        _handshakeServiceMock.Setup(h => h.GetHandshakeAsync("token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success, new Dictionary<string, string> { ["new_claim"] = "new_val" }));

        var completedHandshake = handshake with { VerifiedFactors = new HashSet<string> { "totp" }, IsCompleted = true, Metadata = new Dictionary<string, string>(metadata) { ["claim:new_claim"] = "new_val" } };
        _handshakeServiceMock.Setup(h => h.VerifyFactorAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(completedHandshake));

        var result = await _orchestrator.VerifyFactorAsync("token", "totp", _context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Succeeded));
            Assert.That(result.User, Is.EqualTo(_userMock.Object));
            Assert.That(result.Claims?["role"], Is.EqualTo("admin"));
            Assert.That(result.Claims?["new_claim"], Is.EqualTo("new_val"));
        }
    }

    [Test]
    public async Task VerifyFactorAsyncFailsWhenHandshakeNotFound()
    {
        _handshakeServiceMock.Setup(h => h.GetHandshakeAsync("token", It.IsAny<CancellationToken>()))
            .ReturnsAsync((AuthenticationHandshake?)null);

        var result = await _orchestrator.VerifyFactorAsync("token", "totp", _context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(result.ErrorMessage, Is.EqualTo("Handshake not found."));
        }
    }

    [Test]
    public async Task VerifyFactorAsyncFailsWhenAssertionFails()
    {
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "totp" }, new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.GetHandshakeAsync("token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(false, Status: AuthenticationStatus.Failed));

        var result = await _orchestrator.VerifyFactorAsync("token", "totp", _context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(result.ErrorMessage, Is.EqualTo("Factor verification failed."));
        }
    }

    [Test]
    public async Task VerifyFactorAsyncFailsWhenAssertionReturnsNoUser()
    {
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "totp" }, new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.GetHandshakeAsync("token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
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
        _handshakeServiceMock.Setup(h => h.GetHandshakeAsync("token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(false, _userMock.Object, AuthenticationStatus.Disabled));

        var result = await _orchestrator.VerifyFactorAsync("token", "totp", _context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(result.ErrorMessage, Is.EqualTo("User is disabled."));
        }
    }

    [Test]
    public async Task VerifyFactorAsyncFailsWhenAssertionProviderDoesNotMatchFactor()
    {
        var passwordAssertion = new Mock<IAuthenticationAssertion>();
        passwordAssertion.Setup(a => a.ProviderIdentity).Returns(AuthenticationProviderKey.Local);
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "totp" }, new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.GetHandshakeAsync("token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        var result = await _orchestrator.VerifyFactorAsync("token", "totp", _context, passwordAssertion.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(result.ErrorMessage, Is.EqualTo("Factor verification failed."));
        }

        _pipelineMock.Verify(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()), Times.Never);
        _handshakeServiceMock.Verify(h => h.VerifyFactorAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task VerifyFactorAsyncFailsBeforeAuthenticationWhenFactorIsNotRequired()
    {
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "sms" }, new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.GetHandshakeAsync("token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        var result = await _orchestrator.VerifyFactorAsync("token", "totp", _context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(result.ErrorMessage, Is.EqualTo("Invalid factor type."));
        }

        _pipelineMock.Verify(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()), Times.Never);
        _handshakeServiceMock.Verify(h => h.VerifyFactorAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task VerifyFactorAsyncForwardsCanonicalRequiredFactor()
    {
        var assertion = new Mock<IAuthenticationAssertion>();
        assertion.Setup(a => a.ProviderIdentity).Returns(new AuthenticationProviderKey("totp", "totp"));
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "TOTP" }, new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.GetHandshakeAsync("token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), assertion.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));

        var completedHandshake = handshake with { VerifiedFactors = new HashSet<string> { "TOTP" }, IsCompleted = true };
        _handshakeServiceMock.Setup(h => h.VerifyFactorAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(completedHandshake));

        var result = await _orchestrator.VerifyFactorAsync("token", "totp", _context, assertion.Object);

        Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Succeeded));
        _handshakeServiceMock.Verify(h => h.VerifyFactorAsync(
            It.Is<VerifyAuthenticationHandshakeRequest>(r => r.FactorType == "TOTP"),
            It.IsAny<CancellationToken>()));
    }

    [Test]
    public async Task VerifyFactorAsyncFailsBeforeAuthenticationWhenFactorAlreadyVerified()
    {
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "TOTP", "sms" }, new HashSet<string> { "totp" });
        _handshakeServiceMock.Setup(h => h.GetHandshakeAsync("token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        var result = await _orchestrator.VerifyFactorAsync("token", "TOTP", _context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(result.ErrorMessage, Is.EqualTo("Factor already verified."));
        }

        _pipelineMock.Verify(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()), Times.Never);
        _handshakeServiceMock.Verify(h => h.VerifyFactorAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task VerifyFactorAsyncFailsWhenAssertionProviderIdentityIsUninitialized()
    {
        var assertion = new Mock<IAuthenticationAssertion>();
        assertion.Setup(a => a.ProviderIdentity).Returns(default(AuthenticationProviderKey));
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "totp" }, new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.GetHandshakeAsync("token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        var result = await _orchestrator.VerifyFactorAsync("token", "totp", _context, assertion.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(result.ErrorMessage, Is.EqualTo("Factor verification failed."));
        }

        _pipelineMock.Verify(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task VerifyFactorAsyncDoesNotMatchDifferentSymbolOnlyFactors()
    {
        var assertion = new Mock<IAuthenticationAssertion>();
        assertion.Setup(a => a.ProviderIdentity).Returns(new AuthenticationProviderKey("-", "-"));
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "_" }, new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.GetHandshakeAsync("token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        var result = await _orchestrator.VerifyFactorAsync("token", "_", _context, assertion.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(result.ErrorMessage, Is.EqualTo("Factor verification failed."));
        }

        _pipelineMock.Verify(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task VerifyFactorAsyncFailsWhenUserIdMismatch()
    {
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), Guid.NewGuid(), "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "totp" }, new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.GetHandshakeAsync("token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
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
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "totp" }, new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.GetHandshakeAsync("token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));

        _handshakeServiceMock.Setup(h => h.VerifyFactorAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure<AuthenticationHandshake>("handshake_expired"));

        var result = await _orchestrator.VerifyFactorAsync("token", "totp", _context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(result.ErrorMessage, Is.EqualTo("Handshake has expired."));
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
        _handshakeServiceMock.Setup(h => h.GetHandshakeAsync("token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));

        _handshakeServiceMock.Setup(h => h.VerifyFactorAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure<AuthenticationHandshake>(failureReason));

        var result = await _orchestrator.VerifyFactorAsync("token", "totp", _context, _assertionMock.Object);

        Assert.That(result.ErrorMessage, Is.EqualTo(expectedMessage));
    }

    [Test]
    public async Task VerifyFactorAsyncUsesDefaultErrorWhenHandshakeServiceFailsWithUnknownReason()
    {
        var handshake = new AuthenticationHandshake(Guid.NewGuid(), _userMock.Object.Id, "hash", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), false, false, new HashSet<string> { "totp" }, new HashSet<string>());
        _handshakeServiceMock.Setup(h => h.GetHandshakeAsync("token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));

        _handshakeServiceMock.Setup(h => h.VerifyFactorAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure<AuthenticationHandshake>("unexpected_internal_reason"));

        var result = await _orchestrator.VerifyFactorAsync("token", "totp", _context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(result.ErrorMessage, Is.EqualTo("Factor verification failed."));
        }
    }

    [TestCase("no_factors_specified", "MFA is required but no factors are configured.")]
    [TestCase("invalid_metadata", "Invalid metadata.")]
    [TestCase("unexpected_internal_reason", "Failed to create MFA handshake.")]
    public async Task AuthenticateAsyncMapsHandshakeCreationFailureReasonsToPublicMessages(string failureReason, string expectedMessage)
    {
        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));

        _policyEvaluatorMock.Setup(e => e.EvaluateAsync(_userMock.Object, _context, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaPolicyEvaluation(true, new MfaRequirement(["totp"])));

        _handshakeServiceMock.Setup(h => h.CreateHandshakeAsync(It.IsAny<CreateAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure<AuthenticationHandshakeCreated>(failureReason));

        var result = await _orchestrator.AuthenticateAsync(_context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(result.ErrorMessage, Is.EqualTo(expectedMessage));
        }
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

        _handshakeServiceMock.Setup(h => h.GetHandshakeAsync("token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));

        var completedHandshake = handshake with { VerifiedFactors = new HashSet<string> { "totp" }, IsCompleted = true };
        _handshakeServiceMock.Setup(h => h.VerifyFactorAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
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

        _handshakeServiceMock.Setup(h => h.GetHandshakeAsync("token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        _pipelineMock.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), _assertionMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, _userMock.Object, AuthenticationStatus.Success));

        var completedHandshake = handshake with { VerifiedFactors = new HashSet<string> { "totp" }, IsCompleted = true, Metadata = metadata };
        _handshakeServiceMock.Setup(h => h.VerifyFactorAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(completedHandshake));

        var result = await _orchestrator.VerifyFactorAsync("token", "totp", _context, _assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.Succeeded));
            Assert.That(result.User, Is.EqualTo(_userMock.Object));
            Assert.That(result.Claims, Is.Empty);
        }
    }
}
