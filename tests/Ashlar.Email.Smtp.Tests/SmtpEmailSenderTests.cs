using Ashlar.Messaging;
using Moq;

namespace Ashlar.Email.Smtp.Tests;

[TestFixture]
internal sealed class SmtpEmailSenderTests
{
    [Test]
    public async Task SendAsyncShouldDelegateToTransport()
    {
        var mockTransport = new Mock<IEmailTransport>();
        var sender = new SmtpEmailSender(mockTransport.Object);
        var message = new EmailMessage(to: "r@e.com", subject: "S", sensitivity: EmailMessageSensitivity.Normal, textBody: "B");

        await sender.SendAsync(message);

        mockTransport.Verify(x => x.DeliverAsync(message, It.IsAny<CancellationToken>()), Times.Once);
    }
}
