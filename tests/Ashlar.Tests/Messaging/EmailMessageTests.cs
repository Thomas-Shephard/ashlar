using System.Collections.ObjectModel;
using Ashlar.Messaging;

namespace Ashlar.Tests.Messaging;

internal sealed class EmailMessageTests
{
    [Test]
    public void EmailMessageAcceptsValidTextEmail()
    {
        var message = new EmailMessage("user@example.com", "Sign in", "Use this code.");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(message.To, Is.EqualTo("user@example.com"));
            Assert.That(message.Subject, Is.EqualTo("Sign in"));
            Assert.That(message.TextBody, Is.EqualTo("Use this code."));
            Assert.That(message.HtmlBody, Is.Null);
            Assert.That(message.From, Is.Null);
            Assert.That(message.ReplyTo, Is.Null);
            Assert.That(message.Headers, Is.Null);
            Assert.That(message.Metadata, Is.Null);
            Assert.That(message.Sensitivity, Is.EqualTo(EmailMessageSensitivity.Normal));
        }
    }

    [Test]
    public void EmailMessageCopiesSensitivityFromOptions()
    {
        var message = new EmailMessage(
            "user@example.com",
            "Sign in",
            "Use this link.",
            options: new EmailMessageOptions { Sensitivity = EmailMessageSensitivity.ContainsLiveSecret });

        Assert.That(message.Sensitivity, Is.EqualTo(EmailMessageSensitivity.ContainsLiveSecret));
    }

    [Test]
    public void EmailMessageAcceptsValidHtmlOnlyEmail()
    {
        var message = new EmailMessage(
            "user@example.com",
            "Sign in",
            htmlBody: "<p>Use this link.</p>",
            options: new EmailMessageOptions
            {
                From = "security@example.com",
                ReplyTo = "support@example.com"
            });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(message.TextBody, Is.Null);
            Assert.That(message.HtmlBody, Is.EqualTo("<p>Use this link.</p>"));
            Assert.That(message.From, Is.EqualTo("security@example.com"));
            Assert.That(message.ReplyTo, Is.EqualTo("support@example.com"));
        }
    }

    [Test]
    public void EmailMessageAcceptsCcAndBccOptions()
    {
        var message = new EmailMessage(
            "user@example.com",
            "Sign in",
            "Use this code.",
            options: new EmailMessageOptions
            {
                Cc = "cc@example.com",
                Bcc = "bcc@example.com"
            });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(message.Cc, Is.EqualTo("cc@example.com"));
            Assert.That(message.Bcc, Is.EqualTo("bcc@example.com"));
        }
    }

    [Test]
    public void EmailMessageRejectsEmptyTo()
    {
        var exception = Assert.Throws<ArgumentException>(() => _ = new EmailMessage(" ", "Subject", "Body"));

        Assert.That(exception.ParamName, Is.EqualTo("to"));
    }

    [Test]
    public void EmailMessageRejectsEmptySubject()
    {
        var exception = Assert.Throws<ArgumentException>(() => _ = new EmailMessage("user@example.com", "\t", "Body"));

        Assert.That(exception.ParamName, Is.EqualTo("subject"));
    }

    [Test]
    public void EmailMessageRejectsMissingBody()
    {
        var exception = Assert.Throws<ArgumentException>(() => _ = new EmailMessage("user@example.com", "Subject", " ", "\r\n"));

        Assert.That(exception.ParamName, Is.EqualTo("textBody"));
    }

    [Test]
    public void HeadersAndMetadataArePreserved()
    {
        var headers = new Dictionary<string, string> { ["X-Flow"] = "passwordless" };
        var metadata = new Dictionary<string, string> { ["UserId"] = "123" };

        var message = new EmailMessage(
            "user@example.com",
            "Subject",
            "Body",
            options: new EmailMessageOptions
            {
                Headers = headers,
                Metadata = metadata
            });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(message.Headers, Is.Not.Null);
            Assert.That(message.Metadata, Is.Not.Null);
        }

        using (Assert.EnterMultipleScope())
        {
            Assert.That(message.Headers["X-Flow"], Is.EqualTo("passwordless"));
            Assert.That(message.Metadata["UserId"], Is.EqualTo("123"));
        }
    }

    [Test]
    public void HeadersAndMetadataCannotBeMutatedThroughOriginalDictionary()
    {
        var headers = new Dictionary<string, string> { ["X-Flow"] = "passwordless" };
        var metadata = new Dictionary<string, string> { ["UserId"] = "123" };

        var message = new EmailMessage(
            "user@example.com",
            "Subject",
            "Body",
            options: new EmailMessageOptions
            {
                Headers = headers,
                Metadata = metadata
            });
        headers["X-Flow"] = "reset";
        metadata["UserId"] = "456";

        using (Assert.EnterMultipleScope())
        {
            Assert.That(message.Headers, Is.Not.Null);
            Assert.That(message.Metadata, Is.Not.Null);
        }

        using (Assert.EnterMultipleScope())
        {
            Assert.That(message.Headers["X-Flow"], Is.EqualTo("passwordless"));
            Assert.That(message.Metadata["UserId"], Is.EqualTo("123"));
        }
    }

    [Test]
    public void HeadersAndMetadataCannotBeMutatedThroughExposedDictionary()
    {
        var message = new EmailMessage(
            "user@example.com",
            "Subject",
            "Body",
            options: new EmailMessageOptions
            {
                Headers = new Dictionary<string, string> { ["X-Flow"] = "passwordless" },
                Metadata = new Dictionary<string, string> { ["UserId"] = "123" }
            });

        var headers = message.Headers as IDictionary<string, string>;
        var metadata = message.Metadata as IDictionary<string, string>;
        using (Assert.EnterMultipleScope())
        {
            Assert.That(headers, Is.Not.Null);
            Assert.That(metadata, Is.Not.Null);
            Assert.That(message.Headers, Is.TypeOf<ReadOnlyDictionary<string, string>>());
            Assert.That(message.Metadata, Is.TypeOf<ReadOnlyDictionary<string, string>>());
        }

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<NotSupportedException>(() => headers["X-Flow"] = "reset");
            Assert.Throws<NotSupportedException>(() => metadata["UserId"] = "456");
            Assert.That(message.Headers["X-Flow"], Is.EqualTo("passwordless"));
            Assert.That(message.Metadata["UserId"], Is.EqualTo("123"));
        }
    }

    [Test]
    public void EmailMessageRejectsHeaderInjection()
    {
        Assert.Throws<ArgumentException>(() => _ = new EmailMessage(
            to: "recipient@example.com",
            subject: "Test Subject",
            textBody: "Hello",
            options: new EmailMessageOptions
            {
                Headers = new Dictionary<string, string> { { "X-Injected\nNewline", "Value" } }
            }));

        Assert.Throws<ArgumentException>(() => _ = new EmailMessage(
            to: "recipient@example.com",
            subject: "Test Subject",
            textBody: "Hello",
            options: new EmailMessageOptions
            {
                Headers = new Dictionary<string, string> { { "X-Normal", "Value\rInjection" } }
            }));

        Assert.Throws<ArgumentException>(() => _ = new EmailMessage(
            to: "recipient@example.com",
            subject: "Test Subject",
            textBody: "Hello",
            options: new EmailMessageOptions
            {
                Headers = new Dictionary<string, string> { { "X-Null", "Value\0Injection" } }
            }));
    }

    [Test]
    public void EmailMessageAcceptsNullHeaderValue()
    {
        var message = new EmailMessage(
            to: "recipient@example.com",
            subject: "Test Subject",
            textBody: "Hello",
            options: new EmailMessageOptions
            {
                Headers = new Dictionary<string, string> { { "X-Nullable", null! } }
            });

        Assert.That(message.Headers!["X-Nullable"], Is.Null);
    }

    [Test]
    public void EmailMessageRejectsSubjectInjection()
    {
        Assert.Throws<ArgumentException>(() => _ = new EmailMessage(
            to: "recipient@example.com",
            subject: "Test Subject\nInjected-Header: Value",
            textBody: "Hello"));
    }

    [Test]
    public void EmailMessageRejectsToInjection()
    {
        Assert.Throws<ArgumentException>(() => _ = new EmailMessage(
            to: "recipient@example.com\r\nBcc: victim@example.com",
            subject: "Subject",
            textBody: "Hello"));
    }

    [Test]
    public void EmailMessageRejectsCcAndBccInjection()
    {
        Assert.Throws<ArgumentException>(() => _ = new EmailMessage(
            to: "recipient@example.com",
            subject: "Subject",
            textBody: "Hello",
            options: new EmailMessageOptions { Cc = "cc@example.com\r\nBcc: victim@example.com" }));

        Assert.Throws<ArgumentException>(() => _ = new EmailMessage(
            to: "recipient@example.com",
            subject: "Subject",
            textBody: "Hello",
            options: new EmailMessageOptions { Bcc = "bcc@example.com\nCc: victim@example.com" }));
    }
}
