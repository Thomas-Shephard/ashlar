using System.Text;
using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.Providers;
using Ashlar.Identity.Providers.Fido2;
using Ashlar.Identity.Providers.Local;
using Ashlar.Identity.Providers.Recovery;
using Ashlar.Identity.Providers.Totp;
using Ashlar.Security.Encryption;
using Ashlar.Security.Hashing;
using Moq;

namespace Ashlar.Tests.Identity;

public class MfaTests
{
    private Mock<IIdentityRepository> _repositoryMock;
    private Mock<ISecretProtector> _secretProtectorMock;
    private IdentityService _identityService;
    private SessionTicketSerializer _ticketSerializer;
    private CredentialService _credentialService;

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

        var providers = new List<IAuthenticationProvider>
        {
            new LocalPasswordProvider(new PasswordHasherSelector([passwordHasher])),
            new TotpProvider(),
            new Fido2Provider(challengeProvider, fidoOptions),
            new RecoveryCodeProvider(_repositoryMock.Object)
        };

        _credentialService = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object, providers);
        _ticketSerializer = new SessionTicketSerializer(_secretProtectorMock.Object);
        _identityService = new IdentityService(_repositoryMock.Object, providers, _credentialService, _ticketSerializer);

        _repositoryMock.Setup(r => r.GetCredentialsForUserAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Array.Empty<UserCredential>());
    }

    [Test]
    public async Task LoginAsyncWithMfaRequiredShouldReturnMfaRequiredStatusAndTicket()
    {
        var email = "mfa@example.com";
        var password = "password123";
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = email };
        
        var hasher = new PasswordHasherV1();
        var hashedPass = Convert.ToBase64String(hasher.HashPassword(password));

        var passCredential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Local,
            ProviderName = ProviderType.Local.Value,
            ProviderKey = userId.ToString(),
            CredentialValue = hashedPass
        };

        var totpCredential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Totp,
            ProviderName = ProviderType.Totp.Value,
            ProviderKey = userId.ToString(),
            CredentialValue = _secretProtectorMock.Object.Protect(Convert.ToBase64String(new byte[20]))
        };

        _repositoryMock.Setup(r => r.GetUserByEmailAsync(email, It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Local, ProviderType.Local.Value, userId.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(passCredential);
        
        _repositoryMock.Setup(r => r.GetCredentialsForUserAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new[] { passCredential, totpCredential });

        var response = await _identityService.LoginAsync(email, new LocalPasswordAssertion(password));

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.MfaRequired));
        Assert.That(response.SessionTicket, Is.Not.Null);
    }

    [Test]
    public async Task LoginWithTicketAndTotpShouldSucceed()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = "mfa@example.com" };
        var verifiedFactors = new List<string> { ProviderType.Local.Value };
        var ticketValue = _ticketSerializer.Serialize(userId, verifiedFactors);
        
        var secret = new byte[20];
        var totpCredential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Totp,
            ProviderName = ProviderType.Totp.Value,
            ProviderKey = userId.ToString(),
            CredentialValue = _secretProtectorMock.Object.Protect(Convert.ToBase64String(secret))
        };

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Totp, ProviderType.Totp.Value, userId.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(totpCredential);
        
        _repositoryMock.Setup(r => r.GetCredentialsForUserAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new[] { totpCredential });

        var code = CalculateTotp(secret, System.Security.Cryptography.HashAlgorithmName.SHA1);

        var response = await _identityService.LoginAsync(new SessionTicket(ticketValue), new TotpAssertion(code));

        Assert.That(response.Succeeded, Is.True);
        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Success));
        Assert.That(response.VerifiedFactors, Contains.Item(ProviderType.Local.Value));
        Assert.That(response.VerifiedFactors, Contains.Item(ProviderType.Totp.Value));
    }

    [Test]
    public async Task LoginWithTicketAndTotpSha256ShouldSucceed()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = "mfa@example.com" };
        var ticketValue = _ticketSerializer.Serialize(userId, new[] { ProviderType.Local.Value });
        
        var secret = new byte[32];
        var totpCredential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Totp,
            ProviderName = ProviderType.Totp.Value,
            ProviderKey = userId.ToString(),
            CredentialValue = _secretProtectorMock.Object.Protect(Convert.ToBase64String(secret))
        };

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Totp, ProviderType.Totp.Value, userId.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(totpCredential);
        
        _repositoryMock.Setup(r => r.GetCredentialsForUserAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new[] { totpCredential });

        var code = CalculateTotp(secret, System.Security.Cryptography.HashAlgorithmName.SHA1);

        var response = await _identityService.LoginAsync(new SessionTicket(ticketValue), new TotpAssertion(code));

        Assert.That(response.Succeeded, Is.True);
    }

    [Test]
    public async Task LoginWithTicketAndRecoveryCodeShouldSucceedAndDeleteCode()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = "mfa@example.com" };
        var ticketValue = _ticketSerializer.Serialize(userId, new[] { ProviderType.Local.Value });
        
        var recoveryCode = "REC-123-456";
        var hashedCode = Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(recoveryCode)));
        
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.RecoveryCode,
            ProviderName = ProviderType.RecoveryCode.Value,
            ProviderKey = hashedCode,
            CredentialValue = hashedCode
        };

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.RecoveryCode, ProviderType.RecoveryCode.Value, hashedCode, It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);
        
        _repositoryMock.Setup(r => r.GetCredentialsForUserAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new[] { credential });
        
        _repositoryMock.Setup(r => r.ConsumeCredentialAsync(credential.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var response = await _identityService.LoginAsync(new SessionTicket(ticketValue), new RecoveryCodeAssertion(recoveryCode));

        Assert.That(response.Succeeded, Is.True);
        _repositoryMock.Verify(r => r.ConsumeCredentialAsync(credential.Id, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task LoginWithTicketAndFido2ShouldSucceed()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = "mfa@example.com" };
        var ticketValue = _ticketSerializer.Serialize(userId, new[] { ProviderType.Local.Value });
        
        using var ecdsa = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();
        
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Fido2,
            ProviderName = ProviderType.Fido2.Value,
            ProviderKey = ProviderType.Fido2.Value,
            CredentialValue = Convert.ToBase64String(publicKey)
        };

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Fido2, It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);
        
        _repositoryMock.Setup(r => r.GetCredentialsForUserAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new[] { credential });

        var authenticatorData = new byte[37];
        var challenge = new byte[32];
        var challengeString = Convert.ToBase64String(challenge).Replace("+", "-").Replace("/", "_").TrimEnd('=');
        var clientDataJson = Encoding.UTF8.GetBytes($"{{\"type\":\"webauthn.get\",\"challenge\":\"{challengeString}\",\"origin\":\"https://example.com\"}}");
        var clientDataHash = System.Security.Cryptography.SHA256.HashData(clientDataJson);
        
        var dataToSign = new byte[authenticatorData.Length + clientDataHash.Length];
        authenticatorData.CopyTo(dataToSign, 0);
        clientDataHash.CopyTo(dataToSign, authenticatorData.Length);
        
        var signature = ecdsa.SignData(dataToSign, System.Security.Cryptography.HashAlgorithmName.SHA256);

        var assertion = new Fido2Assertion(
            CredentialId: new byte[32],
            Challenge: challenge,
            AuthenticatorData: authenticatorData,
            ClientDataJson: clientDataJson,
            Signature: signature,
            UserHandle: new byte[32],
            UserVerified: true);

        _repositoryMock.Setup(r => r.ConsumeChallengeAsync(It.IsAny<byte[]>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var response = await _identityService.LoginAsync(new SessionTicket(ticketValue), assertion);

        Assert.That(response.Succeeded, Is.True);
        Assert.That(response.VerifiedFactors, Contains.Item(ProviderType.Local.Value));
        Assert.That(response.VerifiedFactors, Contains.Item(ProviderType.Fido2.Value));
    }

    [Test]
    public async Task CreateVerificationHandshakeAsyncShouldSupportStepUp()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = "stepup@example.com" };
        
        var totpCredential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Totp,
            ProviderName = ProviderType.Totp.Value,
            ProviderKey = ProviderType.Totp.Value,
            CredentialValue = "secret"
        };

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        
        _repositoryMock.Setup(r => r.GetCredentialsForUserAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new[] { totpCredential });

        var response = await _identityService.CreateVerificationHandshakeAsync(userId, new[] { ProviderType.Local.Value });

        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.MfaRequired));
        Assert.That(response.SessionTicket, Is.Not.Null);
    }

    [Test]
    public async Task LoginWithTicketAndRecoveryCodeWithoutPrimaryShouldReturnMfaRequired()
    {
        // Case: User starts login flow directly with a Recovery Code (e.g. lost password page? or just hitting the endpoint)
        // Since Recovery Code is NOT a primary factor, it should not fully authenticate the user if primary is missing.
        
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = "mfa@example.com" };
        var ticketValue = _ticketSerializer.Serialize(userId, new List<string>()); // Empty factors
        
        var recoveryCode = "REC-123-456";
        var hashedCode = Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(recoveryCode)));
        
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.RecoveryCode,
            ProviderName = ProviderType.RecoveryCode.Value,
            ProviderKey = hashedCode,
            CredentialValue = hashedCode
        };

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.RecoveryCode, ProviderType.RecoveryCode.Value, hashedCode, It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);
        
        _repositoryMock.Setup(r => r.GetCredentialsForUserAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new[] { credential });

        _repositoryMock.Setup(r => r.ConsumeCredentialAsync(credential.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var response = await _identityService.LoginAsync(new SessionTicket(ticketValue), new RecoveryCodeAssertion(recoveryCode));

        // Expectation: It succeeded in verifying the code (so it's added to verified factors)
        // Recovery Code acts as a primary fallback, so status should be Success.
        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Success));
        Assert.That(response.VerifiedFactors, Contains.Item(ProviderType.RecoveryCode.Value));
        
        // Ensure credential was deleted (one-time use)
        _repositoryMock.Verify(r => r.ConsumeCredentialAsync(credential.Id, It.IsAny<CancellationToken>()), Times.Once);
    }
    
    [Test]
    public async Task LoginWithPasswordAndRecoveryCodeShouldSucceed()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = "mfa@example.com" };
        var ticketValue = _ticketSerializer.Serialize(userId, new[] { ProviderType.Local.Value }); // Primary satisfied
        
        var recoveryCode = "REC-123-456";
        var hashedCode = Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(recoveryCode)));
        
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.RecoveryCode,
            ProviderName = ProviderType.RecoveryCode.Value,
            ProviderKey = hashedCode,
            CredentialValue = hashedCode
        };

        var totpCredential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Totp,
            ProviderName = ProviderType.Totp.Value,
            ProviderKey = userId.ToString(),
            CredentialValue = "secret"
        };

        var assertion = new RecoveryCodeAssertion(recoveryCode);

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        
        // Re-inject updated provider list for this specific test case
        var challengeProvider = new ChallengeProvider(_repositoryMock.Object);
        var fidoOptions = new Fido2Options { ExpectedOrigin = "https://example.com" };
        var providers = new List<IAuthenticationProvider>
        {
            new LocalPasswordProvider(new PasswordHasherSelector([new PasswordHasherV1()])),
            new TotpProvider(),
            new Fido2Provider(challengeProvider, fidoOptions),
            new RecoveryCodeProvider(_repositoryMock.Object)
        };

        _credentialService = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object, providers);
        _identityService = new IdentityService(_repositoryMock.Object, providers, _credentialService, _ticketSerializer);

        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.RecoveryCode, ProviderType.RecoveryCode.Value, hashedCode, It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);
        
        _repositoryMock.Setup(r => r.GetCredentialsForUserAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new[] { credential, totpCredential });

        _repositoryMock.Setup(r => r.ConsumeCredentialAsync(credential.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var response = await _identityService.LoginAsync(new SessionTicket(ticketValue), assertion);

        Assert.That(response.Succeeded, Is.True);
        Assert.That(response.VerifiedFactors, Contains.Item(ProviderType.Local.Value));
        Assert.That(response.VerifiedFactors, Contains.Item(ProviderType.RecoveryCode.Value));
    }

    [Test]
    public void DeserializeShouldReturnNullForFutureTicket()
    {
        var ticket = _secretProtectorMock.Object.Protect(System.Text.Json.JsonSerializer.Serialize(new {
            UserId = Guid.NewGuid(),
            VerifiedFactors = new List<string>(),
            CreatedAt = DateTimeOffset.UtcNow.AddMinutes(2)
        }));

        var result = _ticketSerializer.Deserialize(ticket);
        Assert.That(result, Is.Null);
    }

    [Test]
    public void DeserializeShouldSucceedForTicketWithSmallFutureSkew()
    {
        var userId = Guid.NewGuid();
        var ticket = _secretProtectorMock.Object.Protect(System.Text.Json.JsonSerializer.Serialize(new {
            UserId = userId,
            VerifiedFactors = new List<string>(),
            CreatedAt = DateTimeOffset.UtcNow.AddSeconds(30)
        }));

        var result = _ticketSerializer.Deserialize(ticket);
        Assert.That(result, Is.Not.Null);
        Assert.That(result!.UserId, Is.EqualTo(userId));
    }

    [Test]
    public void DeserializeShouldReturnNullForExpiredTicket()
    {
        var ticket = _secretProtectorMock.Object.Protect(System.Text.Json.JsonSerializer.Serialize(new {
            UserId = Guid.NewGuid(),
            VerifiedFactors = new List<string>(),
            CreatedAt = DateTimeOffset.UtcNow.AddMinutes(-20)
        }));

        var result = _ticketSerializer.Deserialize(ticket);
        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task LoginWithTicketShouldFailIfUserIsDisabled()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = "disabled@example.com", IsActive = false };
        var ticketValue = _ticketSerializer.Serialize(userId, new[] { ProviderType.Local.Value });
        
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
        _repositoryMock.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.Totp, ProviderType.Totp.Value, userId.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(totpCredential);
        
        _repositoryMock.Setup(r => r.GetCredentialsForUserAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new[] { totpCredential });

        var code = CalculateTotp(new byte[20], System.Security.Cryptography.HashAlgorithmName.SHA1);
        var response = await _identityService.LoginAsync(new SessionTicket(ticketValue), new TotpAssertion(code));

        Assert.That(response.Succeeded, Is.False);
        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Disabled));
    }

    [Test]
    public async Task LoginWithInvalidTicketShouldReturnFailed()
    {
        // "invalid-ticket" will cause Unprotect to throw or return garbage, forcing Deserialize to return null
        var response = await _identityService.LoginAsync(new SessionTicket("invalid-ticket"), new TotpAssertion("123456"));

        Assert.That(response.Succeeded, Is.False);
        Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms", Justification = "TOTP standard often requires HMAC-SHA1")]
    private static string CalculateTotp(byte[] secret, System.Security.Cryptography.HashAlgorithmName algorithm)
    {
        long iteration = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        byte[] iterationBytes = BitConverter.GetBytes(iteration);
        if (BitConverter.IsLittleEndian) Array.Reverse(iterationBytes);

        using var hmac = algorithm == System.Security.Cryptography.HashAlgorithmName.SHA256 
            ? (System.Security.Cryptography.HMAC)new System.Security.Cryptography.HMACSHA256(secret) 
            : new System.Security.Cryptography.HMACSHA1(secret);
            
        byte[] hash = hmac.ComputeHash(iterationBytes);

        int offset = hash[hash.Length - 1] & 0x0F;
        int binary = ((hash[offset] & 0x7f) << 24)
                     | ((hash[offset + 1] & 0xff) << 16)
                     | ((hash[offset + 2] & 0xff) << 8)
                     | (hash[offset + 3] & 0xff);

        return (binary % 1000000).ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
    }
}
