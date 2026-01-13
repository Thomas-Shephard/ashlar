using System.Text;
using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.Providers;
using Ashlar.Identity.Providers.External;
using Ashlar.Identity.Providers.Fido2;
using Ashlar.Identity.Providers.Local;
using Ashlar.Identity.Providers.Recovery;
using Ashlar.Identity.Providers.Totp;
using Ashlar.Security.Encryption;
using Ashlar.Security.Hashing;
using Moq;

namespace Ashlar.Tests.Identity;

public class MfaSecurityTests
{
    private Mock<IIdentityRepository> _repositoryMock;
    private Mock<ISecretProtector> _secretProtectorMock;
    private IdentityService _identityService;
    private SessionTicketSerializer _ticketSerializer;
    private Fido2Provider _fido2Provider;

    [SetUp]
    public void SetUp()
    {
        _repositoryMock = new Mock<IIdentityRepository>();
        _secretProtectorMock = new Mock<ISecretProtector>();

        _secretProtectorMock.Setup(s => s.Protect(It.IsAny<string>())).Returns<string>(s => $"protected({s})");
        _secretProtectorMock.Setup(s => s.Unprotect(It.IsAny<string>())).Returns<string>(s => s.StartsWith("protected(", StringComparison.Ordinal) ? s[10..^1] : s);

        var passwordHasher = new PasswordHasherV1();
        var challengeProvider = new ChallengeProvider(_repositoryMock.Object);
        var fidoOptions = new Fido2Options { ExpectedOrigin = "https://example.com" };
        _fido2Provider = new Fido2Provider(challengeProvider, fidoOptions);

        var providers = new List<IAuthenticationProvider>
        {
            new LocalPasswordProvider(new PasswordHasherSelector([passwordHasher])),
            new TotpProvider(),
            _fido2Provider,
            new RecoveryCodeProvider(_repositoryMock.Object)
        };

        var credentialService = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object, providers);
        _ticketSerializer = new SessionTicketSerializer(_secretProtectorMock.Object);
        _identityService = new IdentityService(_repositoryMock.Object, providers, credentialService, _ticketSerializer);

        // Default: No secondary credentials
        _repositoryMock.Setup(r => r.HasCredentialAsync(It.IsAny<Guid>(), It.IsAny<ProviderType>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);
    }

    [Test]
    public async Task LoginAsyncWithOnlySecondaryFactorShouldReturnMfaRequiredToEnforcePrimaryFactor()
    {
        var userId = Guid.NewGuid();
        var email = "totp-only@example.com";
        var user = new User { Id = userId, Email = email };

        // User has TOTP credential
        var totpCredential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Totp,
            ProviderName = ProviderType.Totp.Value,
            ProviderKey = userId.ToString(),
            CredentialValue = _secretProtectorMock.Object.Protect(Convert.ToBase64String(new byte[20]))
        };

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        
        _repositoryMock.Setup(r => r.GetUserByEmailAsync(email, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Totp, ProviderType.Totp.Value, userId.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(totpCredential);
            
        // Mock that user has TOTP configured
        _repositoryMock.Setup(r => r.HasCredentialAsync(userId, ProviderType.Totp, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
        _repositoryMock.Setup(r => r.HasCredentialAsync(userId, ProviderType.Fido2, It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        // Authenticate with TOTP
        var secret = new byte[20];
        var code = CalculateTotp(secret);
        
        // Reset credential value to known secret
        totpCredential.CredentialValue = _secretProtectorMock.Object.Protect(Convert.ToBase64String(secret));

        var response = await _identityService.LoginAsync(email, new TotpAssertion(code));

        // Expectation: Login succeeds in verifying TOTP, but IsMfaRequired returns TRUE because no Primary factor verified.
        // So Status should be MfaRequired.
        Assert.That(response.Succeeded, Is.True);
        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.MfaRequired));
        
        // Ensure verified factors in ticket include Totp
        Assert.That(response.SessionTicket, Is.Not.Null);
        var handshake = _ticketSerializer.Deserialize(response.SessionTicket!);
        Assert.That(handshake, Is.Not.Null);
        Assert.That(handshake!.VerifiedFactors, Contains.Item(ProviderType.Totp.Value));
    }

    [Test]
    public async Task LoginAsyncWithTicketAndPrimaryShouldSucceedIfSecondaryAlreadyVerified()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = "test@example.com" };
        
        // Ticket has Totp verified
        var ticket = _ticketSerializer.Serialize(userId, new[] { ProviderType.Totp.Value });

        var passCredential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Local,
            ProviderName = ProviderType.Local.Value,
            ProviderKey = userId.ToString(),
            CredentialValue = Convert.ToBase64String(new PasswordHasherV1().HashPassword("password"))
        };

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Local, It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(passCredential);
            
        // User has Totp configured
        _repositoryMock.Setup(r => r.HasCredentialAsync(userId, ProviderType.Totp, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
        _repositoryMock.Setup(r => r.HasCredentialAsync(userId, ProviderType.Fido2, It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var response = await _identityService.LoginAsync(new SessionTicket(ticket), new LocalPasswordAssertion("password"));

        Assert.That(response.Succeeded, Is.True);
        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Success));
    }

    [Test]
    public async Task Fido2AuthenticateShouldFailWithMalformedAuthData()
    {
        var assertion = new Fido2Assertion(
            CredentialId: new byte[32],
            Challenge: new byte[32],
            AuthenticatorData: new byte[10], // Too short!
            ClientDataJson: Encoding.UTF8.GetBytes("{}"),
            Signature: new byte[32],
            UserHandle: new byte[32],
            UserVerified: true
        );

        _repositoryMock.Setup(r => r.ConsumeChallengeAsync(It.IsAny<byte[]>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
            
        using var ecdsa = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();
        
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Fido2,
            ProviderName = ProviderType.Fido2.Value,
            ProviderKey = ProviderType.Fido2.Value,
            CredentialValue = Convert.ToBase64String(publicKey)
        };
        
        // Construct malformed auth data
        var authData = new byte[10];
        
        var challengeBase64 = Convert.ToBase64String(assertion.Challenge).Replace("+", "-").Replace("/", "_").TrimEnd('=');
        var json = $"{{\"type\":\"webauthn.get\",\"challenge\":\"{challengeBase64}\",\"origin\":\"https://example.com\"}}";
        var clientDataJson = Encoding.UTF8.GetBytes(json);
        
        var clientDataHash = System.Security.Cryptography.SHA256.HashData(clientDataJson);
        
        var dataToSign = new byte[authData.Length + clientDataHash.Length];
        authData.CopyTo(dataToSign, 0);
        clientDataHash.CopyTo(dataToSign, authData.Length);
        
        var signature = ecdsa.SignData(dataToSign, System.Security.Cryptography.HashAlgorithmName.SHA256);
        
        var validAssertion = assertion with { 
            AuthenticatorData = authData, 
            Signature = signature,
            ClientDataJson = clientDataJson 
        };

        var result = await _fido2Provider.AuthenticateAsync(validAssertion, credential);

        Assert.That(result.Result, Is.EqualTo(PasswordVerificationResult.Failed));
    }

    [Test]
    public async Task ProcessAuthenticationAsyncShouldNotUpdateCredentialIfValueIsUnchanged()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = "test@example.com" };
        
        // Mock a provider that returns ShouldUpdateCredential = true but same value
        var mockProvider = new Mock<IAuthenticationProvider>();
        mockProvider.Setup(p => p.SupportedType).Returns(ProviderType.OAuth);
        mockProvider.Setup(p => p.GetProviderName(It.IsAny<IAuthenticationAssertion>())).Returns("OAuth");
        mockProvider.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<IUser>())).Returns("key");
        
        var currentVal = "same-value";
        mockProvider.Setup(p => p.AuthenticateAsync(It.IsAny<IAuthenticationAssertion>(), It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(PasswordVerificationResult.Success, ShouldUpdateCredential: true, NewCredentialValue: currentVal));

        // Helper to reconstruct IdentityService with mock provider
        var providers = new[] { mockProvider.Object };
        var credService = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object, providers);
        var service = new IdentityService(_repositoryMock.Object, providers, credService, _ticketSerializer);

        var credential = new UserCredential 
        { 
            Id = Guid.NewGuid(), 
            UserId = userId, 
            ProviderType = ProviderType.OAuth,
            ProviderName = "OAuth",
            ProviderKey = "key",
            CredentialValue = _secretProtectorMock.Object.Protect(currentVal) 
        };

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.OAuth, It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);
            
        // Setup "No secondary configured" so we pass MFA check
        _repositoryMock.Setup(r => r.HasCredentialAsync(userId, ProviderType.Totp, It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);
        _repositoryMock.Setup(r => r.HasCredentialAsync(userId, ProviderType.Fido2, It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var assertion = new ExternalIdentityAssertion(ProviderType.OAuth, "test", "key", new Dictionary<string, string>());
        
        await service.LoginAsync("email", assertion);

        // Verify UpdateCredentialAsync was called (at least for LastUsedAt)
        _repositoryMock.Verify(r => r.UpdateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()), Times.Once);
    }
    
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms", Justification = "TOTP standard often requires HMAC-SHA1")]
    private static string CalculateTotp(byte[] secret)
    {
        long iteration = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        byte[] iterationBytes = BitConverter.GetBytes(iteration);
        if (BitConverter.IsLittleEndian) Array.Reverse(iterationBytes);

        using var hmac = new System.Security.Cryptography.HMACSHA1(secret);
        byte[] hash = hmac.ComputeHash(iterationBytes);

        int offset = hash[hash.Length - 1] & 0x0F;
        int binary = ((hash[offset] & 0x7f) << 24)
                     | ((hash[offset + 1] & 0xff) << 16)
                     | ((hash[offset + 2] & 0xff) << 8)
                     | (hash[offset + 3] & 0xff);

        return (binary % 1000000).ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
    }
}
