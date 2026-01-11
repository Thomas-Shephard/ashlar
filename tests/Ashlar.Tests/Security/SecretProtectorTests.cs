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
        var result = ((ISecretProtector)secretProtector).Protect("plain");

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
        var result = ((ISecretProtector)secretProtector).Unprotect(input);

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

        Assert.Throws<System.Security.Cryptography.CryptographicException>(() => ((ISecretProtector)secretProtector).Unprotect("not-base64!"));
    }

    [Test]
    public void ConstructorShouldThrowOnNullProvider()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new DataProtectionSecretProtector(null!));
    }

    [Test]
    public void ProtectShouldThrowOnNullPlainText()
    {
        var providerMock = new Mock<IDataProtectionProvider>();
        providerMock.Setup(p => p.CreateProtector(It.IsAny<string>())).Returns(new Mock<IDataProtector>().Object);
        var secretProtector = new DataProtectionSecretProtector(providerMock.Object);

        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => ((ISecretProtector)secretProtector).Protect((string)null!));
    }

    [Test]
    public void UnprotectShouldThrowOnNullCipherText()
    {
        var providerMock = new Mock<IDataProtectionProvider>();
        providerMock.Setup(p => p.CreateProtector(It.IsAny<string>())).Returns(new Mock<IDataProtector>().Object);
        var secretProtector = new DataProtectionSecretProtector(providerMock.Object);

        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<System.Security.Cryptography.CryptographicException>(() => ((ISecretProtector)secretProtector).Unprotect((string)null!));
    }

    [Test]
    public void UnprotectShouldThrowOnEmptyCipherText()
    {
        var providerMock = new Mock<IDataProtectionProvider>();
        providerMock.Setup(p => p.CreateProtector(It.IsAny<string>())).Returns(new Mock<IDataProtector>().Object);
        var secretProtector = new DataProtectionSecretProtector(providerMock.Object);

        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<System.Security.Cryptography.CryptographicException>(() => ((ISecretProtector)secretProtector).Unprotect(string.Empty));
    }

    [Test]
    public void UnprotectShouldPropagateCryptographicException()
    {
        var providerMock = new Mock<IDataProtectionProvider>();
        var protectorMock = new Mock<IDataProtector>();
        providerMock.Setup(p => p.CreateProtector(It.IsAny<string>())).Returns(protectorMock.Object);

        protectorMock.Setup(p => p.Unprotect(It.IsAny<byte[]>()))
            .Throws(new System.Security.Cryptography.CryptographicException());

        var secretProtector = new DataProtectionSecretProtector(providerMock.Object);
        var input = Convert.ToBase64String("valid-base64"u8.ToArray());

        Assert.Throws<System.Security.Cryptography.CryptographicException>(() => ((ISecretProtector)secretProtector).Unprotect(input));
    }

    [Test]
    public void UnprotectShouldWrapFormatExceptionInCryptographicException()
    {
        var providerMock = new Mock<IDataProtectionProvider>();
        providerMock.Setup(p => p.CreateProtector(It.IsAny<string>())).Returns(new Mock<IDataProtector>().Object);
        var secretProtector = new DataProtectionSecretProtector(providerMock.Object);

        var ex = Assert.Throws<System.Security.Cryptography.CryptographicException>(() => ((ISecretProtector)secretProtector).Unprotect("!@#$%^&*()"));
        Assert.That(ex.InnerException, Is.InstanceOf<FormatException>());
    }
}
