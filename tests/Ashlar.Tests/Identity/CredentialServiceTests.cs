using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.Providers;
using Ashlar.Identity.Providers.Fido2;
using Ashlar.Security.Encryption;
using Moq;

namespace Ashlar.Tests.Identity;

public class CredentialServiceTests
{
    private Mock<IIdentityRepository> _repositoryMock;
    private Mock<ISecretProtector> _secretProtectorMock;
    private CredentialService _service;
    private Mock<IAuthenticationProvider> _providerMock;

    [SetUp]
    public void SetUp()
    {
        _repositoryMock = new Mock<IIdentityRepository>();
        _secretProtectorMock = new Mock<ISecretProtector>();
        _providerMock = new Mock<IAuthenticationProvider>();

        _secretProtectorMock.Setup(s => s.Protect(It.IsAny<string>())).Returns<string>(s => $"protected({s})");
        _secretProtectorMock.Setup(s => s.Unprotect(It.IsAny<string>())).Returns<string>(s => s.StartsWith("protected(", StringComparison.Ordinal) ? s[10..^1] : s);

        _providerMock.Setup(p => p.SupportedType).Returns((ProviderType)"MOCK");
        _providerMock.Setup(p => p.GetProviderName(It.IsAny<IAuthenticationAssertion>())).Returns("MOCK");
        _providerMock.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<IUser>())).Returns("key");

        _service = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object, new[] { _providerMock.Object });
    }

    [Test]
    public async Task ResolveAsyncWithFido2UsernamelessShouldResolveUserByHandle()
    {
        var userId = Guid.NewGuid();
        var userHandle = userId.ToByteArray();
        var handleKey = Convert.ToBase64String(userHandle);
        var assertion = new Fido2Assertion(Array.Empty<byte>(), Array.Empty<byte>(), Array.Empty<byte>(), Array.Empty<byte>(), Array.Empty<byte>(), userHandle, true);
        var user = new User { Id = userId, Email = "fido@example.com" };

        _repositoryMock.Setup(r => r.GetUserByProviderKeyAsync(ProviderType.Fido2, "FIDO2_HANDLE", handleKey, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        // We need a FIDO2 provider for this specific logic path
        var fidoProvider = new Mock<IAuthenticationProvider>();
        fidoProvider.Setup(p => p.SupportedType).Returns(ProviderType.Fido2);
        fidoProvider.Setup(p => p.GetProviderName(It.IsAny<IAuthenticationAssertion>())).Returns(ProviderType.Fido2.Value);
        fidoProvider.Setup(p => p.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<IUser>())).Returns("key");
        
        var service = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object, new[] { fidoProvider.Object });

        var (resolvedUser, _, _) = await service.ResolveAsync(null, assertion);

        Assert.That(resolvedUser, Is.EqualTo(user));
    }

    [Test]
    public async Task ResolveAsyncWithFido2UsernamelessAndInvalidGuidShouldReturnNullUser()
    {
        var userHandle = new byte[] { 1, 2, 3 }; // Invalid GUID length
        var assertion = new Fido2Assertion(Array.Empty<byte>(), Array.Empty<byte>(), Array.Empty<byte>(), Array.Empty<byte>(), Array.Empty<byte>(), userHandle, true);

        var fidoProvider = new Mock<IAuthenticationProvider>();
        fidoProvider.Setup(p => p.SupportedType).Returns(ProviderType.Fido2);
        
        var service = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object, new[] { fidoProvider.Object });

        var (resolvedUser, _, _) = await service.ResolveAsync(null, assertion);

        Assert.That(resolvedUser, Is.Null);
    }

    [Test]
    public async Task ResolveAsyncWithFido2UsernamelessAndUnknownUserShouldReturnNullUser()
    {
        var userId = Guid.NewGuid();
        var userHandle = userId.ToByteArray();
        var assertion = new Fido2Assertion(Array.Empty<byte>(), Array.Empty<byte>(), Array.Empty<byte>(), Array.Empty<byte>(), Array.Empty<byte>(), userHandle, true);

        _repositoryMock.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((IUser?)null);

        var fidoProvider = new Mock<IAuthenticationProvider>();
        fidoProvider.Setup(p => p.SupportedType).Returns(ProviderType.Fido2);
        
        var service = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object, new[] { fidoProvider.Object });

        var (resolvedUser, _, _) = await service.ResolveAsync(null, assertion);

        Assert.That(resolvedUser, Is.Null);
    }

    [Test]
    public async Task ResolveAsyncWithFido2UsernamelessAndOversizedHandleShouldReturnNullUser()
    {
        var userHandle = new byte[65]; // Exceeds limit of 64
        var assertion = new Fido2Assertion(Array.Empty<byte>(), Array.Empty<byte>(), Array.Empty<byte>(), Array.Empty<byte>(), Array.Empty<byte>(), userHandle, true);

        var fidoProvider = new Mock<IAuthenticationProvider>();
        fidoProvider.Setup(p => p.SupportedType).Returns(ProviderType.Fido2);
        
        var service = new CredentialService(_repositoryMock.Object, _secretProtectorMock.Object, new[] { fidoProvider.Object });

        var (resolvedUser, _, _) = await service.ResolveAsync(null, assertion);

        Assert.That(resolvedUser, Is.Null);
    }

    [Test]
    public async Task ResolveAsyncWithUnsupportedProviderShouldReturnNulls()
    {
        var assertionMock = new Mock<IAuthenticationAssertion>();
        assertionMock.Setup(a => a.ProviderType).Returns((ProviderType)"Unsupported");

        var (user, credential, failed) = await _service.ResolveAsync("email", assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(user, Is.Null);
            Assert.That(credential, Is.Null);
            Assert.That(failed, Is.False);
        }
    }

    [Test]
    public async Task ResolveAsyncByIdWithUnsupportedProviderShouldReturnNulls()
    {
        var assertionMock = new Mock<IAuthenticationAssertion>();
        assertionMock.Setup(a => a.ProviderType).Returns((ProviderType)"Unsupported");

        var (user, credential, failed) = await _service.ResolveAsync(Guid.NewGuid(), assertionMock.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(user, Is.Null);
            Assert.That(credential, Is.Null);
            Assert.That(failed, Is.False);
        }
    }
}
