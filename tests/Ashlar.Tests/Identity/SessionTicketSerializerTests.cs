using Ashlar.Identity;
using Ashlar.Identity.Models;
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
        _secretProtectorMock.Setup(s => s.Protect(It.IsAny<string>())).Returns<string>(s => $"protected({s})");
        _secretProtectorMock.Setup(s => s.Unprotect(It.IsAny<string>())).Returns<string>(s => s.StartsWith("protected(", StringComparison.Ordinal) ? s[10..^1] : s);
        _serializer = new SessionTicketSerializer(_secretProtectorMock.Object);
    }

    [Test]
    public void ConstructorShouldThrowOnNullProtector()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new SessionTicketSerializer(null!));
    }

    [Test]
    public void DeserializeShouldReturnNullWhenDtoIsNull()
    {
        // Protected "null" string
        var nullTicket = _secretProtectorMock.Object.Protect("null");
        var result = _serializer.Deserialize(nullTicket);
        Assert.That(result, Is.Null);
    }

    [Test]
    public void DeserializeShouldReturnNullOnInvalidFormat()
    {
        var result = _serializer.Deserialize("not-a-valid-ticket");
        Assert.That(result, Is.Null);
    }

    [Test]
    public void DeserializeShouldReturnNullOnWhitespaceTicket()
    {
        Assert.That(_serializer.Deserialize("   "), Is.Null);
    }

    [Test]
    public void ShouldRespectExpiryFromOptions()
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
}
