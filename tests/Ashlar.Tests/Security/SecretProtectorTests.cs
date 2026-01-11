using Ashlar.Security.Encryption;
using Microsoft.AspNetCore.DataProtection;
using Moq;

namespace Ashlar.Tests.Security;

public class SecretProtectorTests
{
    [Test]
    public void ProtectShouldCallDataProtector()
    {
        var providerMock = new Mock<IDataProtectionProvider>();
        var protectorMock = new Mock<IDataProtector>();

        providerMock.Setup(p => p.CreateProtector("Ashlar.Identity.Credentials"))
            .Returns(protectorMock.Object);

        protectorMock.Setup(p => p.Protect(It.IsAny<byte[]>()))
            .Returns<byte[]>(data => data); // Return as-is for mock

        var secretProtector = new DataProtectionSecretProtector(providerMock.Object);
        var result = secretProtector.Protect("plain");

        Assert.That(result, Is.Not.Null);
        protectorMock.Verify(p => p.Protect(It.IsAny<byte[]>()), Times.Once);
    }

    [Test]
    public void UnprotectShouldCallDataProtector()
    {
        var providerMock = new Mock<IDataProtectionProvider>();
        var protectorMock = new Mock<IDataProtector>();

        providerMock.Setup(p => p.CreateProtector("Ashlar.Identity.Credentials"))
            .Returns(protectorMock.Object);

        protectorMock.Setup(p => p.Unprotect(It.IsAny<byte[]>()))
            .Returns<byte[]>(data => data); // Return as-is for mock

        var secretProtector = new DataProtectionSecretProtector(providerMock.Object);

        // We need a valid base64 string for the extension method to work before calling Unprotect(byte[])
        var input = Convert.ToBase64String("protected"u8.ToArray());
        var result = secretProtector.Unprotect(input);

        Assert.That(result, Is.Not.Null);
        protectorMock.Verify(p => p.Unprotect(It.IsAny<byte[]>()), Times.Once);
    }

    [Test]
    public void UnprotectShouldThrowCryptographicExceptionOnInvalidBase64()
    {
        var providerMock = new Mock<IDataProtectionProvider>();
        var protectorMock = new Mock<IDataProtector>();

        providerMock.Setup(p => p.CreateProtector("Ashlar.Identity.Credentials"))
            .Returns(protectorMock.Object);

        var secretProtector = new DataProtectionSecretProtector(providerMock.Object);

        Assert.Throws<System.Security.Cryptography.CryptographicException>(() => secretProtector.Unprotect("not-base64!"));
    }

    [Test]
    public void ConstructorShouldThrowOnNullProvider()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new DataProtectionSecretProtector(null!));
    }
}
