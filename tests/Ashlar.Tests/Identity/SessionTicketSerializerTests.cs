using System.Security.Cryptography;
using Ashlar.Identity;
using Ashlar.Security.Encryption;
using Moq;

namespace Ashlar.Tests.Identity;

public class SessionTicketSerializerTests
{
    private Mock<ISecretProtector> _secretProtectorMock;
    private SessionTicketSerializer _serializer;

    [SetUp]
    public void SetUp()
    {
        _secretProtectorMock = new Mock<ISecretProtector>();
        _serializer = new SessionTicketSerializer(_secretProtectorMock.Object);
    }

    [Test]
    public void DeserializeWithMalformedJsonShouldReturnNull()
    {
        _secretProtectorMock.Setup(s => s.Unprotect(It.IsAny<string>())).Returns("{ invalid json }");

        var result = _serializer.Deserialize("ticket");

        Assert.That(result, Is.Null);
    }

    [Test]
    public void DeserializeWithUnprotectFailureShouldReturnNull()
    {
        _secretProtectorMock.Setup(s => s.Unprotect(It.IsAny<string>())).Throws<CryptographicException>();

        var result = _serializer.Deserialize("ticket");

        Assert.That(result, Is.Null);
    }
}