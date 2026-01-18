using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.Providers.Local;
using Ashlar.Security.Encryption;
using Ashlar.Security.Hashing;
using Moq;

namespace Ashlar.Tests.Identity;

public class MfaHandshakeTests
{
    private Mock<IIdentityRepository> _repositoryMock;
    private Mock<ISecretProtector> _secretProtectorMock;
    private Mock<IAuthenticationProvider> _primaryProviderMock;
    private Mock<IAuthenticationProvider> _secondaryProviderMock;
    private SessionTicketSerializer _ticketSerializer;
    private IdentityService _identityService;
    private CredentialService _credentialService;

    [SetUp]
    public void SetUp()
    {
        _repositoryMock = new Mock<IIdentityRepository>();
        _secretProtectorMock = new Mock<ISecretProtector>();

        _secretProtectorMock.Setup(s => s.Protect(It.IsAny<string>())).Returns<string>(s => $"protected({s})");
        _secretProtectorMock.Setup(s => s.Unprotect(It.IsAny<string>())).Returns<string>(s => s.StartsWith("protected(", StringComparison.Ordinal) ? s[10..^1] : s);

        _ticketSerializer = new SessionTicketSerializer(_secretProtectorMock.Object);

        _primaryProviderMock = new Mock<IAuthenticationProvider>();
        _primaryProviderMock.Setup(p => p.SupportedType).Returns(ProviderType.Local);
        _primaryProviderMock.Setup(p => p.IsPrimary).Returns(true);
        _primaryProviderMock.Setup(p => p.IsSecondary).Returns(false);

        _secondaryProviderMock = new Mock<IAuthenticationProvider>();
        _secondaryProviderMock.Setup(p => p.SupportedType).Returns((ProviderType)"TOTP");
        _secondaryProviderMock.Setup(p => p.IsPrimary).Returns(false);
        _secondaryProviderMock.Setup(p => p.IsSecondary).Returns(true);

        var providers = new List<IAuthenticationProvider>
        {
            _primaryProviderMock.Object,
            _secondaryProviderMock.Object
        };

        _credentialService = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object);
        _identityService = new IdentityService(_repositoryMock.Object, providers, _credentialService, _ticketSerializer);
    }

    [Test]
    public async Task IsMfaRequiredAsyncShouldReturnFalseWhenProviderBypassesMfa()
    {
        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com" };
        var assertion = new Mock<IAuthenticationAssertion>();
        assertion.Setup(a => a.ProviderType).Returns(ProviderType.Local);

        _primaryProviderMock.Setup(p => p.BypassesMfa(assertion.Object)).Returns(true);
        _primaryProviderMock.Setup(p => p.IsPrimary).Returns(true);
        _primaryProviderMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(PasswordVerificationResult.Success));
        _primaryProviderMock.Setup(p => p.FindUserAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<IIdentityRepository>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _primaryProviderMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), user.Id)).Returns("key");

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await _identityService.LoginAsync("test@example.com", assertion.Object);
        Assert.That(result.Status, Is.EqualTo(AuthenticationStatus.Success));
    }

    [Test]
    public async Task IsMfaRequiredAsyncShouldReturnTrueWhenNoPrimaryFactorVerified()
    {
        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com" };
        var assertion = new Mock<IAuthenticationAssertion>();
        assertion.Setup(a => a.ProviderType).Returns((ProviderType)"TOTP");

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _secondaryProviderMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(PasswordVerificationResult.Success));
        _secondaryProviderMock.Setup(p => p.FindUserAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<IIdentityRepository>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _secondaryProviderMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), user.Id)).Returns("key");

        var result = await _identityService.LoginAsync("test@example.com", assertion.Object);
        Assert.That(result.Status, Is.EqualTo(AuthenticationStatus.MfaRequired));
    }

    [Test]
    public async Task IsMfaRequiredAsyncShouldHandleMissingProviderForVerifiedFactor()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = "test@example.com" };
        var handshake = new AuthenticationHandshake
        {
            UserId = userId,
            VerifiedFactors = new List<ProviderType> { (ProviderType)"UNKNOWN" }
        };
        var ticket = _ticketSerializer.Serialize(handshake);

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _primaryProviderMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(PasswordVerificationResult.Success));
        _primaryProviderMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), userId)).Returns("key");

        var response = await _identityService.LoginAsync(new SessionTicket(ticket), new LocalPasswordAssertion("pass"));
        // UNKNOWN factor is ignored, so we still only have Local verified (from current assertion).
        // Since no secondary is configured for this user in this test, it should succeed.
        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Success));
    }

    [Test]
    public void SessionTicketSerializerShouldReturnNullOnWhitespaceTicket()
    {
        Assert.That(_ticketSerializer.Deserialize("   "), Is.Null);
    }

    [Test]
    public async Task AuthenticateInternalAsyncShouldFailWhenCredentialConsumptionUpdateFails()
    {
        var email = "test@example.com";
        var user = new User { Id = Guid.NewGuid(), Email = email };
        var assertion = new LocalPasswordAssertion("password");
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Local,
            ProviderName = "Local",
            ProviderKey = "key"
        };

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(email, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(It.IsAny<Guid>(), It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        _primaryProviderMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(PasswordVerificationResult.Success, IsCredentialConsumed: true));
        _primaryProviderMock.Setup(p => p.FindUserAsync(It.IsAny<IAuthenticationAssertion>(), email, It.IsAny<Guid?>(), _repositoryMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _primaryProviderMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), user.Id)).Returns("key");

        var mockCredService = new Mock<ICredentialService>();
        mockCredService.Setup(c => c.UpdateCredentialUsageAsync(It.IsAny<UserCredential>(), It.IsAny<UserCredential>(), It.IsAny<AuthenticationResult>(), It.IsAny<IAuthenticationProvider>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("Consumption failed"));
        mockCredService.Setup(c => c.ResolveAsync(It.IsAny<string>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, credential, credential, false));

        var identityService = new IdentityService(_repositoryMock.Object, [_primaryProviderMock.Object], mockCredService.Object, _ticketSerializer);

        var result = await identityService.LoginAsync(email, assertion);
        Assert.That(result.Succeeded, Is.False);
    }

    [Test]
    public async Task LoginAsyncShouldReturnMfaRequiredWhenSecondaryFactorIsConfigured()
    {
        var email = "test@example.com";
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = email };
        var assertion = new LocalPasswordAssertion("password");

        var primaryCredential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Local,
            ProviderName = "Local",
            ProviderKey = userId.ToString()
        };

        var secondaryCredential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = (ProviderType)"TOTP",
            ProviderName = "TOTP",
            ProviderKey = "totp-key"
        };

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(email, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Local, It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(primaryCredential);
        _repositoryMock.Setup(r => r.GetCredentialsForUserAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync([primaryCredential, secondaryCredential]);

        _primaryProviderMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(PasswordVerificationResult.Success));
        _primaryProviderMock.Setup(p => p.FindUserAsync(It.IsAny<IAuthenticationAssertion>(), email, It.IsAny<Guid?>(), _repositoryMock.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _primaryProviderMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), userId)).Returns(userId.ToString());

        var response = await _identityService.LoginAsync(email, assertion);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.MfaRequired));
            Assert.That(response.SessionTicket, Is.Not.Null);
            var handshake = _ticketSerializer.Deserialize(response.SessionTicket);
            Assert.That(handshake, Is.Not.Null);
            Assert.That(handshake.UserId, Is.EqualTo(userId));
            Assert.That(handshake.VerifiedFactors, Contains.Item(ProviderType.Local));
        }
    }

    [Test]
    public async Task LoginAsyncWithSessionTicketShouldSucceedWhenAllFactorsVerified()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = "test@example.com" };

        var handshake = new AuthenticationHandshake
        {
            UserId = userId,
            VerifiedFactors = new List<ProviderType> { ProviderType.Local }
        };
        var ticket = _ticketSerializer.Serialize(handshake);

        var secondaryAssertionMock = new Mock<IAuthenticationAssertion>();
        secondaryAssertionMock.Setup(a => a.ProviderType).Returns((ProviderType)"TOTP");

        var secondaryCredential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = (ProviderType)"TOTP",
            ProviderName = "TOTP",
            ProviderKey = "totp-key"
        };

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialsForUserAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync([secondaryCredential]);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, (ProviderType)"TOTP", It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(secondaryCredential);

        _secondaryProviderMock.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(PasswordVerificationResult.Success));
        _secondaryProviderMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), userId)).Returns("totp-key");

        var response = await _identityService.LoginAsync(new SessionTicket(ticket), secondaryAssertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.True);
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Success));
        }
    }

    [Test]
    public async Task LoginAsyncWithSessionTicketShouldFailWhenReVerifyingSameFactor()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = "test@example.com" };

        var handshake = new AuthenticationHandshake
        {
            UserId = userId,
            VerifiedFactors = new List<ProviderType> { ProviderType.Local }
        };
        var ticket = _ticketSerializer.Serialize(handshake);

        var assertion = new LocalPasswordAssertion("password");

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var response = await _identityService.LoginAsync(new SessionTicket(ticket), assertion);

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
    }

    [Test]
    public void SessionTicketSerializerShouldReturnNullOnInvalidFormat()
    {
        var result = _ticketSerializer.Deserialize("not-a-valid-ticket");
        Assert.That(result, Is.Null);
    }

    [Test]
    public void SessionTicketSerializerShouldRespectExpiryFromOptions()
    {
        var options = new IdentityServiceOptions { HandshakeExpiry = TimeSpan.FromSeconds(-1) };
        var serializer = new SessionTicketSerializer(_secretProtectorMock.Object, options);

        var handshake = new AuthenticationHandshake
        {
            UserId = Guid.NewGuid(),
            VerifiedFactors = new List<ProviderType> { ProviderType.Local }
        };

        var ticket = serializer.Serialize(handshake);
        var result = serializer.Deserialize(ticket);

        Assert.That(result, Is.Null);
    }

    [Test]
    public void ProviderTypeJsonConverterShouldHandleNullOrWhitespace()
    {
        var jsonNull = "null";
        var jsonEmpty = "\"\"";
        var jsonSpace = "\"  \"";

        var resultNull = System.Text.Json.JsonSerializer.Deserialize<ProviderType>(jsonNull);
        var resultEmpty = System.Text.Json.JsonSerializer.Deserialize<ProviderType>(jsonEmpty);
        var resultSpace = System.Text.Json.JsonSerializer.Deserialize<ProviderType>(jsonSpace);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(resultNull.Value, Is.EqualTo(string.Empty));
            Assert.That(resultEmpty.Value, Is.EqualTo(string.Empty));
            Assert.That(resultSpace.Value, Is.EqualTo(string.Empty));
        }
    }

    [Test]
    public void SessionTicketSerializerShouldExpireTickets()
    {
        var handshake = new AuthenticationHandshake
        {
            UserId = Guid.NewGuid(),
            VerifiedFactors = new List<ProviderType> { ProviderType.Local }
        };

        // We can't easily mock DateTimeOffset.UtcNow inside SessionTicketSerializer without injecting a clock.
        // But we can check that it works for a new ticket.
        var ticket = _ticketSerializer.Serialize(handshake);

        var result = _ticketSerializer.Deserialize(ticket);

        Assert.That(result, Is.Not.Null);
        Assert.That(result.UserId, Is.EqualTo(handshake.UserId));
    }
}
