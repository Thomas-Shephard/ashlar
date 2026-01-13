using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.Providers;
using Ashlar.Identity.Providers.Fido2;
using Ashlar.Security.Hashing;
using Moq;

namespace Ashlar.Tests.Identity;

public class Fido2ProviderTests
{
    private Mock<IChallengeProvider> _challengeProviderMock;
    private Fido2Provider _provider;
    private Fido2Options _options;

    [SetUp]
    public void SetUp()
    {
        _challengeProviderMock = new Mock<IChallengeProvider>();
        _options = new Fido2Options { ExpectedOrigin = "https://example.com" };
        _provider = new Fido2Provider(_challengeProviderMock.Object, _options);
    }

    [Test]
    public async Task AuthenticateAsyncWithZeroCounterAndPreviousHistoryShouldFail()
    {
        // 1. Setup existing credential with LastSignatureCount = 10
        var metadata = new { LastSignatureCount = 10u };
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Fido2,
            ProviderName = "Fido2",
            ProviderKey = "key",
            CredentialValue = Convert.ToBase64String(GetValidPublicKey()), 
            Metadata = JsonSerializer.Serialize(metadata)
        };

        // 2. Create assertion with Counter = 0
        var assertion = CreateValidAssertion(credential.UserId, counter: 0, GetValidPrivateKey());

        // 3. Mock challenge validation
        _challengeProviderMock.Setup(c => c.ValidateChallengeAsync(It.IsAny<byte[]>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        // 4. Act
        var result = await _provider.AuthenticateAsync(assertion, credential);

        // 5. Assert
        Assert.That(result.Result, Is.EqualTo(PasswordVerificationResult.Failed), "Should fail if counter resets to 0 when history exists.");
    }

    [Test]
    public async Task AuthenticateAsyncWithInvalidOriginShouldFail()
    {
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Fido2,
            ProviderName = "Fido2",
            ProviderKey = "key",
            CredentialValue = Convert.ToBase64String(GetValidPublicKey())
        };

        // Create assertion with wrong origin
        var assertion = CreateValidAssertion(credential.UserId, 1, GetValidPrivateKey(), origin: "https://malicious.com");

        _challengeProviderMock.Setup(c => c.ValidateChallengeAsync(It.IsAny<byte[]>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var result = await _provider.AuthenticateAsync(assertion, credential);

        Assert.That(result.Result, Is.EqualTo(PasswordVerificationResult.Failed));
    }

    [Test]
    public async Task AuthenticateAsyncWithInvalidTypeShouldFail()
    {
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Fido2,
            ProviderName = "Fido2",
            ProviderKey = "key",
            CredentialValue = Convert.ToBase64String(GetValidPublicKey())
        };

        // Create assertion with wrong type
        var assertion = CreateValidAssertion(credential.UserId, 1, GetValidPrivateKey(), type: "webauthn.create");

        _challengeProviderMock.Setup(c => c.ValidateChallengeAsync(It.IsAny<byte[]>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var result = await _provider.AuthenticateAsync(assertion, credential);

        Assert.That(result.Result, Is.EqualTo(PasswordVerificationResult.Failed));
    }

    private byte[] GetValidPublicKey()
    {
        return GetPublicKeyFromPrivate();
    }

    private byte[]? _privateKeyBlob;
    private byte[] GetValidPrivateKey()
    {
        if (_privateKeyBlob == null)
        {
             using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
             _privateKeyBlob = ecdsa.ExportECPrivateKey();
        }
        return _privateKeyBlob;
    }
    
    private byte[] GetPublicKeyFromPrivate()
    {
         using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
         ecdsa.ImportECPrivateKey(GetValidPrivateKey(), out _);
         return ecdsa.ExportSubjectPublicKeyInfo();
    }

    private static Fido2Assertion CreateValidAssertion(Guid userId, uint counter, byte[] privateKey, string origin = "https://example.com", string type = "webauthn.get")
    {
        var challenge = new byte[32];
        RandomNumberGenerator.Fill(challenge);
        var challengeString = Convert.ToBase64String(challenge).Replace("+", "-").Replace("/", "_").TrimEnd('=');
        
        var json = "{\"type\":\"" + type + "\",\"challenge\":\"" + challengeString + "\",\"origin\":\"" + origin + "\"}";
        var clientDataJson = Encoding.UTF8.GetBytes(json);
        var clientDataHash = SHA256.HashData(clientDataJson);

        var authData = new byte[37];
        // RP ID Hash (32 bytes)
        authData[32] = 0x05;
        // Counter (4 bytes) - Big Endian
        authData[33] = (byte)((counter >> 24) & 0xFF);
        authData[34] = (byte)((counter >> 16) & 0xFF);
        authData[35] = (byte)((counter >> 8) & 0xFF);
        authData[36] = (byte)(counter & 0xFF);

        var dataToSign = new byte[authData.Length + clientDataHash.Length];
        authData.CopyTo(dataToSign, 0);
        clientDataHash.CopyTo(dataToSign, authData.Length);

        using var ecdsa = ECDsa.Create();
        ecdsa.ImportECPrivateKey(privateKey, out _);
        var signature = ecdsa.SignData(dataToSign, HashAlgorithmName.SHA256);

        return new Fido2Assertion(
            CredentialId: new byte[16],
            Challenge: challenge,
            AuthenticatorData: authData,
            ClientDataJson: clientDataJson,
            Signature: signature,
            UserHandle: userId.ToByteArray(),
            UserVerified: true
        );
    }
    
    [Test]
    public async Task AuthenticateAsyncWithNonCryptographicExceptionInVerifySignatureShouldFailGracefully()
    {
         var credential = new UserCredential
         {
             Id = Guid.NewGuid(),
             UserId = Guid.NewGuid(),
             ProviderType = ProviderType.Fido2,
             ProviderName = "Fido2",
             ProviderKey = "key",
             CredentialValue = Convert.ToBase64String(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }) // Garbage key
         };

         var assertion = CreateValidAssertion(credential.UserId, 1, GetValidPrivateKey());
         _challengeProviderMock.Setup(c => c.ValidateChallengeAsync(It.IsAny<byte[]>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

         var result = await _provider.AuthenticateAsync(assertion, credential);
         
         Assert.That(result.Result, Is.EqualTo(PasswordVerificationResult.Failed));
    }

    [Test]
    public async Task AuthenticateAsyncWithCorruptedMetadataShouldSafeFailOrReset()
    {
        // 1. Setup credential with corrupted JSON metadata
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Fido2,
            ProviderName = "Fido2",
            ProviderKey = "key",
            CredentialValue = Convert.ToBase64String(GetValidPublicKey()), 
            Metadata = "{ invalid json }"
        };

        // 2. Create assertion with Counter = 5
        var assertion = CreateValidAssertion(credential.UserId, counter: 5, GetValidPrivateKey());

        _challengeProviderMock.Setup(c => c.ValidateChallengeAsync(It.IsAny<byte[]>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        // 3. Act
        var result = await _provider.AuthenticateAsync(assertion, credential);

        // 4. Assert - Should succeed because we treat corrupted metadata as empty/reset
        Assert.That(result.Result, Is.EqualTo(PasswordVerificationResult.Success));
        Assert.That(result.NewMetadata, Does.Contain("\"LastSignatureCount\":5"));
    }

    [Test]
    public async Task AuthenticateAsyncWithOversizedPayloadShouldFail()
    {
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Fido2,
            ProviderName = ProviderType.Fido2.Value,
            ProviderKey = "key",
            CredentialValue = Convert.ToBase64String(GetValidPublicKey())
        };

        var assertion = CreateValidAssertion(credential.UserId, 1, GetValidPrivateKey());
        
        // Mock oversized ClientDataJson
        var oversizedAssertion = assertion with { ClientDataJson = new byte[4097] };

        var result = await _provider.AuthenticateAsync(oversizedAssertion, credential);

        Assert.That(result.Result, Is.EqualTo(PasswordVerificationResult.Failed), "Should fail if ClientDataJson is too large.");
    }
}    