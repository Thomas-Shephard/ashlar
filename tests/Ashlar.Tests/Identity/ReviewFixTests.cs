using System.Security.Cryptography;
using System.Text;
using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.Providers;
using Ashlar.Identity.Providers.Recovery;
using Ashlar.Identity.Providers.Totp;
using Ashlar.Security.Encryption;
using Ashlar.Security.Hashing;
using Moq;

namespace Ashlar.Tests.Identity;

public class ReviewFixTests
{
    private Mock<IIdentityRepository> _repositoryMock;
    private Mock<ISecretProtector> _secretProtectorMock;

    [SetUp]
    public void SetUp()
    {
        _repositoryMock = new Mock<IIdentityRepository>();
        _secretProtectorMock = new Mock<ISecretProtector>();
    }

    [Test]
    public void TotpProviderGetProviderKeyReturnsUserId()
    {
        var provider = new TotpProvider();
        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com" };
        var assertion = new TotpAssertion("123456");

        var key = provider.GetProviderKey(assertion, user);

        Assert.That(key, Is.EqualTo(user.Id.ToString()));
    }

    [Test]
    public void RecoveryCodeProviderGetProviderKeyReturnsHashOfCode()
    {
        var provider = new RecoveryCodeProvider(_repositoryMock.Object);
        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com" };
        var code = "REC-123-456";
        var assertion = new RecoveryCodeAssertion(code);

        var key = provider.GetProviderKey(assertion, user);

        var expectedHash = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(code)));
        Assert.That(key, Is.EqualTo(expectedHash));
    }

    [Test]
    public async Task RecoveryCodeProviderAuthenticateAsyncWithDirectMatchReturnsSuccessAndDeletes()
    {
        var provider = new RecoveryCodeProvider(_repositoryMock.Object);
        var code = "REC-123-456";
        var assertion = new RecoveryCodeAssertion(code);
        
        var expectedHash = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(code)));
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = "test@example.com" };
        
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.RecoveryCode,
            ProviderName = ProviderType.RecoveryCode.Value,
            ProviderKey = expectedHash,
            CredentialValue = expectedHash // In real flow, CredentialResolver unprotects this. Here we simulate unprotected.
        };

        _repositoryMock.Setup(r => r.ConsumeCredentialAsync(credential.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var result = await provider.AuthenticateAsync(assertion, credential);

        Assert.That(result.Result, Is.EqualTo(PasswordVerificationResult.Success));
        _repositoryMock.Verify(r => r.ConsumeCredentialAsync(credential.Id, It.IsAny<CancellationToken>()), Times.Once);
        // Verify we DID NOT scan
        _repositoryMock.Verify(r => r.GetCredentialsForUserAsync(It.IsAny<Guid>(), It.IsAny<ProviderType>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task RecoveryCodeProviderAuthenticateAsyncWithMismatchReturnsFailed()
    {
        var provider = new RecoveryCodeProvider(_repositoryMock.Object);
        var code = "REC-123-456";
        var assertion = new RecoveryCodeAssertion(code);
        
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.RecoveryCode,
            ProviderName = ProviderType.RecoveryCode.Value,
            ProviderKey = "some-key",
            CredentialValue = "MismatchHash"
        };

        var result = await provider.AuthenticateAsync(assertion, credential);

        Assert.That(result.Result, Is.EqualTo(PasswordVerificationResult.Failed));
        _repositoryMock.Verify(r => r.ConsumeCredentialAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task RecoveryCodeProviderAuthenticateAsyncShouldFailIfConsumeFails()
    {
        var provider = new RecoveryCodeProvider(_repositoryMock.Object);
        var code = "REC-123-456";
        var assertion = new RecoveryCodeAssertion(code);
        var expectedHash = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(code)));
        
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.RecoveryCode,
            ProviderName = ProviderType.RecoveryCode.Value,
            ProviderKey = expectedHash,
            CredentialValue = expectedHash
        };

        // Simulate concurrent consumption failure (atomic consume returns false)
        _repositoryMock.Setup(r => r.ConsumeCredentialAsync(credential.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        var result = await provider.AuthenticateAsync(assertion, credential);

        Assert.That(result.Result, Is.EqualTo(PasswordVerificationResult.Failed), "Should fail if atomic consumption fails (e.g. concurrent usage).");
    }

    [Test]
    public void IdentityServiceConstructorThrowsOnDuplicateProvider()
    {
        var providers = new IAuthenticationProvider[]
        {
            new TotpProvider(),
            new TotpProvider() // Duplicate type
        };

        var credentialService = new Mock<ICredentialService>().Object;
        var ticketSerializer = new SessionTicketSerializer(_secretProtectorMock.Object);

        var ex = Assert.Throws<ArgumentException>(() => new IdentityService(
            _repositoryMock.Object, 
            providers, 
            credentialService, 
            ticketSerializer));

        Assert.That(ex.Message, Contains.Substring("Duplicate provider registered"));
    }
}