using Ashlar.Messaging;

namespace Ashlar.Tests.Messaging;

internal sealed class NullEmailSenderTests
{
    [Test]
    public async Task NullEmailSenderCompletesSuccessfully()
    {
        var sender = new NullEmailSender();
        var message = new EmailMessage("user@example.com", "Subject", "Body");

        await sender.SendAsync(message);

        Assert.Pass();
    }

    [Test]
    public void NullEmailSenderRejectsNullMessage()
    {
        var sender = new NullEmailSender();

        var exception = Assert.ThrowsAsync<ArgumentNullException>(() => sender.SendAsync(null!));

        Assert.That(exception.ParamName, Is.EqualTo("message"));
    }
}
