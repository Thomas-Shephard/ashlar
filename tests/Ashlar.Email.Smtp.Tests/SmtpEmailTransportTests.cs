using Ashlar.Messaging;
using Ashlar.Security;
using MailKit;
using MailKit.Net.Smtp;
using Microsoft.Extensions.Options;
using MimeKit;
using Moq;

namespace Ashlar.Email.Smtp.Tests;

[TestFixture]
public class SmtpEmailTransportTests
{
    private Mock<ISmtpClient> _mockSmtpClient;
    private SmtpEmailOptions _options;
    private TestSmtpEmailTransport _transport;

    [SetUp]
    public void SetUp()
    {
        _mockSmtpClient = new Mock<ISmtpClient>();
        _options = new SmtpEmailOptions
        {
            Host = "localhost",
            Port = 25,
            DefaultFromAddress = "default@example.com"
        };
        _transport = new TestSmtpEmailTransport(Options.Create(_options), _mockSmtpClient.Object);
    }

    [Test]
    public void ConstructorShouldValidateOptions()
    {
        var options = new SmtpEmailOptions { Host = "" };
        Assert.Throws<ArgumentException>(() => _ = new SmtpEmailTransport(Options.Create(options)));

        options = new SmtpEmailOptions { Host = "localhost", Port = 0 };
        Assert.Throws<ArgumentException>(() => _ = new SmtpEmailTransport(Options.Create(options)));

        options = new SmtpEmailOptions { Host = "localhost", Username = "user", Password = "" };
        Assert.Throws<ArgumentException>(() => _ = new SmtpEmailTransport(Options.Create(options)));
    }

    [Test]
    public void CreateSmtpClientShouldReturnMailKitSmtpClient()
    {
        using var client = ExposedSmtpEmailTransport.CreateDefaultClient(Options.Create(_options));

        Assert.That(client, Is.TypeOf<SmtpClient>());
    }

    [Test]
    public async Task DeliverAsyncShouldIgnoreReservedHeaders()
    {
        var message = new EmailMessage(
            to: "recipient@example.com",
            subject: "Test Subject",
            textBody: "Hello",
            options: new EmailMessageOptions
            {
                Headers = new Dictionary<string, string>
                {
                    { "From", "hacked@example.com" },
                    { "To", "hacked@example.com" },
                    { "Subject", "Hacked" },
                    { "Cc", "hacked@example.com" },
                    { "Bcc", "hacked@example.com" },
                    { "X-Custom", "KeepMe" }
                }
            });

        MimeMessage? sentMessage = null;
        _mockSmtpClient.Setup(x => x.SendAsync(It.IsAny<MimeMessage>(), It.IsAny<CancellationToken>(), It.IsAny<ITransferProgress>()))
            .Callback<MimeMessage, CancellationToken, ITransferProgress?>((m, _, _) => sentMessage = m)
            .Returns(Task.FromResult("OK"));

        await _transport.DeliverAsync(message);

        Assert.That(sentMessage, Is.Not.Null);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(sentMessage.From[0].ToString(), Is.EqualTo("default@example.com"));
            Assert.That(sentMessage.To[0].ToString(), Is.EqualTo("recipient@example.com"));
            Assert.That(sentMessage.Subject, Is.EqualTo("Test Subject"));
            Assert.That(sentMessage.Cc, Is.Empty);
            Assert.That(sentMessage.Bcc, Is.Empty);
            Assert.That(sentMessage.Headers["X-Custom"], Is.EqualTo("KeepMe"));
        }
    }

    [Test]
    public async Task DeliverAsyncShouldSendCorrectMimeMessage()
    {
        var message = new EmailMessage(
            to: "recipient@example.com",
            subject: "Test Subject",
            textBody: "Hello Text",
            htmlBody: "<b>Hello HTML</b>",
            options: new EmailMessageOptions
            {
                From = "sender@example.com",
                ReplyTo = "replyto@example.com",
                Cc = "cc@example.com",
                Bcc = "bcc@example.com",
                Headers = new Dictionary<string, string> { { "X-Custom", "Value" } }
            });

        MimeMessage? sentMessage = null;
        _mockSmtpClient.Setup(x => x.SendAsync(It.IsAny<MimeMessage>(), It.IsAny<CancellationToken>(), It.IsAny<ITransferProgress>()))
            .Callback<MimeMessage, CancellationToken, ITransferProgress?>((m, c, p) =>
            {
                var ms = new MemoryStream();
                m.WriteTo(ms);
                ms.Position = 0;
                sentMessage = MimeMessage.Load(ms);
            })
            .Returns(Task.FromResult("OK"));

        await _transport.DeliverAsync(message);

        Assert.That(sentMessage, Is.Not.Null);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(sentMessage.To[0].ToString(), Is.EqualTo("recipient@example.com"));
            Assert.That(sentMessage.From[0].ToString(), Is.EqualTo("sender@example.com"));
            Assert.That(sentMessage.ReplyTo[0].ToString(), Is.EqualTo("replyto@example.com"));
            Assert.That(sentMessage.Cc[0].ToString(), Is.EqualTo("cc@example.com"));
            Assert.That(sentMessage.Bcc[0].ToString(), Is.EqualTo("bcc@example.com"));
            Assert.That(sentMessage.Subject, Is.EqualTo("Test Subject"));
            Assert.That(sentMessage.Headers["X-Custom"], Is.EqualTo("Value"));
        }

        var multipart = sentMessage.Body as MultipartAlternative;
        Assert.That(multipart, Is.Not.Null);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(multipart, Has.Count.EqualTo(2));
            Assert.That(multipart[0].ToString(), Contains.Substring("Hello Text"));
            Assert.That(multipart[1].ToString(), Contains.Substring("<b>Hello HTML</b>"));
        }

        _mockSmtpClient.Verify(x => x.ConnectAsync("localhost", 25, It.IsAny<MailKit.Security.SecureSocketOptions>(), It.IsAny<CancellationToken>()), Times.Once);
        _mockSmtpClient.Verify(x => x.DisconnectAsync(true, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task DeliverAsyncShouldUseDefaultFromWhenMessageFromIsNull()
    {
        var message = new EmailMessage(
            to: "recipient@example.com",
            subject: "Test Subject",
            textBody: "Hello Text");

        MimeMessage? sentMessage = null;
        _mockSmtpClient.Setup(x => x.SendAsync(It.IsAny<MimeMessage>(), It.IsAny<CancellationToken>(), It.IsAny<ITransferProgress>()))
            .Callback<MimeMessage, CancellationToken, ITransferProgress?>((m, _, _) => sentMessage = m)
            .Returns(Task.FromResult("OK"));

        await _transport.DeliverAsync(message);

        Assert.That(sentMessage, Is.Not.Null);
        Assert.That(sentMessage.From[0].ToString(), Is.EqualTo("default@example.com"));
    }

    [Test]
    public void DeliverAsyncShouldThrowWhenFromIsMissing()
    {
        _options.DefaultFromAddress = null;
        var message = new EmailMessage(
            to: "recipient@example.com",
            subject: "Test Subject",
            textBody: "Hello Text");

        Assert.ThrowsAsync<InvalidOperationException>(() => _transport.DeliverAsync(message));
    }

    [Test]
    public async Task DeliverAsyncShouldSupportTextOnlyBody()
    {
        var message = new EmailMessage(
            to: "recipient@example.com",
            subject: "Test Subject",
            textBody: "Hello Text");

        string? sentContentType = null;
        string? sentBodyText = null;

        _mockSmtpClient.Setup(x => x.SendAsync(It.IsAny<MimeMessage>(), It.IsAny<CancellationToken>(), It.IsAny<ITransferProgress>()))
            .Callback<MimeMessage, CancellationToken, ITransferProgress?>((m, _, _) =>
            {
                sentContentType = m.Body!.ContentType.MimeType;
                sentBodyText = m.Body.ToString();
            })
            .Returns(Task.FromResult("OK"));

        await _transport.DeliverAsync(message);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(sentContentType, Is.EqualTo("text/plain"));
            Assert.That(sentBodyText, Contains.Substring("Hello Text"));
        }
    }

    [Test]
    public async Task DeliverAsyncShouldSupportHtmlOnlyBody()
    {
        var message = new EmailMessage(
            to: "recipient@example.com",
            subject: "Test Subject",
            htmlBody: "<b>Hello HTML</b>");

        string? sentContentType = null;
        string? sentBodyText = null;

        _mockSmtpClient.Setup(x => x.SendAsync(It.IsAny<MimeMessage>(), It.IsAny<CancellationToken>(), It.IsAny<ITransferProgress>()))
            .Callback<MimeMessage, CancellationToken, ITransferProgress?>((m, _, _) =>
            {
                sentContentType = m.Body!.ContentType.MimeType;
                sentBodyText = m.Body.ToString();
            })
            .Returns(Task.FromResult("OK"));

        await _transport.DeliverAsync(message);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(sentContentType, Is.EqualTo("text/html"));
            Assert.That(sentBodyText, Contains.Substring("<b>Hello HTML</b>"));
        }
    }

    [Test]
    public async Task DeliverAsyncShouldAuthenticateWhenUsernameIsProvided()
    {
        _options.Username = "user";
        _options.Password = "secure_password";
        var message = new EmailMessage(to: "r@e.com", subject: "S", textBody: "B");

        await _transport.DeliverAsync(message);

        _mockSmtpClient.Verify(x => x.AuthenticateAsync("user", "secure_password", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task DeliverAsyncShouldAuthenticateWithEmptyPasswordWhenPasswordIsNull()
    {
        _options.Username = "user";
        _options.Password = null;
        var message = new EmailMessage(to: "r@e.com", subject: "S", textBody: "B");

        await _transport.DeliverAsync(message);

        _mockSmtpClient.Verify(x => x.AuthenticateAsync("user", string.Empty, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public void DeliverAsyncShouldSanitizeExceptionWhenPasswordIsLeakedInOuterMessage()
    {
        _options.Username = "user";
        _options.Password = "secret_password";
        var message = new EmailMessage(to: "r@e.com", subject: "S", textBody: "B");

        _mockSmtpClient.Setup(x => x.SendAsync(It.IsAny<MimeMessage>(), It.IsAny<CancellationToken>(), It.IsAny<ITransferProgress>()))
            .ThrowsAsync(new InvalidOperationException("Error with secret_password in it"));

        var ex = Assert.ThrowsAsync<InvalidOperationException>(() => _transport.DeliverAsync(message));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(ex.Message, Does.StartWith("Failed to deliver email via SMTP. Exception details redacted for security:"));
            Assert.That(ex.Message, Does.Contain(SecretRedactor.RedactedPlaceholder));
            Assert.That(ex.Message, Does.Not.Contain("secret_password"));
            Assert.That(ex.InnerException, Is.Null);
        }
    }

    [Test]
    public void DeliverAsyncShouldSanitizeExceptionWhenPasswordIsLeakedInInnerException()
    {
        _options.Username = "user";
        _options.Password = "secret_password";
        var message = new EmailMessage(to: "r@e.com", subject: "S", textBody: "B");

        var inner = new InvalidOperationException("Inner error with secret_password");
        var outer = new InvalidOperationException("Outer error", inner);

        _mockSmtpClient.Setup(x => x.SendAsync(It.IsAny<MimeMessage>(), It.IsAny<CancellationToken>(), It.IsAny<ITransferProgress>()))
            .ThrowsAsync(outer);

        var ex = Assert.ThrowsAsync<InvalidOperationException>(() => _transport.DeliverAsync(message));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(ex.Message, Does.StartWith("Failed to deliver email via SMTP. Exception details redacted for security:"));
            Assert.That(ex.Message, Does.Contain(SecretRedactor.RedactedPlaceholder));
            Assert.That(ex.Message, Does.Not.Contain("secret_password"));
            Assert.That(ex.InnerException, Is.Null);
        }
    }

    [Test]
    public void DeliverAsyncShouldRespectCancellationToken()
    {
        var cts = new CancellationTokenSource();
        cts.Cancel();
        var message = new EmailMessage(to: "r@e.com", subject: "S", textBody: "B");

        _mockSmtpClient.Setup(x => x.ConnectAsync(It.IsAny<string>(), It.IsAny<int>(), It.IsAny<MailKit.Security.SecureSocketOptions>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new OperationCanceledException());

        Assert.ThrowsAsync<OperationCanceledException>(() => _transport.DeliverAsync(message, cts.Token));
    }
    [Test]
    public async Task DeliverAsyncShouldSetTimeoutAndSecurityOptions()
    {
        _options.Timeout = 5000;
        _options.SecurityOptions = MailKit.Security.SecureSocketOptions.SslOnConnect;
        var message = new EmailMessage(to: "r@e.com", subject: "S", textBody: "B");

        await _transport.DeliverAsync(message);

        _mockSmtpClient.VerifySet(x => x.Timeout = 5000, Times.Once);
        _mockSmtpClient.Verify(x => x.ConnectAsync(It.IsAny<string>(), It.IsAny<int>(), MailKit.Security.SecureSocketOptions.SslOnConnect, It.IsAny<CancellationToken>()), Times.Once);
    }

    private sealed class TestSmtpEmailTransport(IOptions<SmtpEmailOptions> options, ISmtpClient client) : SmtpEmailTransport(options)
    {
        protected override ISmtpClient CreateSmtpClient()
        {
            return client;
        }
    }

    private sealed class ExposedSmtpEmailTransport(IOptions<SmtpEmailOptions> options) : SmtpEmailTransport(options)
    {
        public static ISmtpClient CreateDefaultClient(IOptions<SmtpEmailOptions> options)
        {
            return new ExposedSmtpEmailTransport(options).CreateSmtpClient();
        }
    }
}
