using Ashlar.Messaging;
using Ashlar.Security.Encryption;

namespace Ashlar.Tests.Messaging;

internal sealed class EmailOutboxDispatchTests
{
    [Test]
    public void ProtectBodiesForStorageLeavesNormalMessagesUnprotected()
    {
        var message = new EmailMessage("to@example.com", "Subject", "Text", "<p>Html</p>");

        var storedBodies = EmailOutboxDispatch.ProtectBodiesForStorage(message, new FakeSecretProtector());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(storedBodies.TextBody, Is.EqualTo("Text"));
            Assert.That(storedBodies.HtmlBody, Is.EqualTo("<p>Html</p>"));
            Assert.That(storedBodies.BodyProtection, Is.EqualTo(EmailOutboxBodyProtection.None));
        }
    }

    [Test]
    public void ProtectBodiesForStorageProtectsSensitiveMessages()
    {
        var message = new EmailMessage(
            "to@example.com",
            "Subject",
            "Live token",
            options: new EmailMessageOptions { Sensitivity = EmailMessageSensitivity.ContainsLiveSecret });

        var storedBodies = EmailOutboxDispatch.ProtectBodiesForStorage(message, new FakeSecretProtector());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(storedBodies.TextBody, Is.Not.EqualTo("Live token"));
            Assert.That(storedBodies.HtmlBody, Is.Null);
            Assert.That(storedBodies.BodyProtection, Is.EqualTo(EmailOutboxBodyProtection.SecretProtector));
        }
    }

    [Test]
    public void ProtectBodiesForStorageThrowsForSensitiveMessagesWithoutProtector()
    {
        var message = new EmailMessage(
            "to@example.com",
            "Subject",
            "Live token",
            options: new EmailMessageOptions { Sensitivity = EmailMessageSensitivity.ContainsLiveSecret });

        var exception = Assert.Throws<InvalidOperationException>(() => EmailOutboxDispatch.ProtectBodiesForStorage(message));

        Assert.That(exception!.Message, Does.Contain("ISecretProtector"));
    }

    [Test]
    public void MapToEmailMessageUnprotectsProtectedBodies()
    {
        ISecretProtector protector = new FakeSecretProtector();
        var entry = new EmailOutboxEntry
        {
            Id = Guid.NewGuid(),
            ToAddress = "to@example.com",
            Subject = "Subject",
            TextBody = protector.Protect("Live text"),
            HtmlBody = protector.Protect("<p>Live html</p>"),
            Sensitivity = EmailMessageSensitivity.ContainsLiveSecret,
            BodyProtection = EmailOutboxBodyProtection.SecretProtector
        };

        var message = EmailOutboxDispatch.MapToEmailMessage(entry, protector);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(message.TextBody, Is.EqualTo("Live text"));
            Assert.That(message.HtmlBody, Is.EqualTo("<p>Live html</p>"));
            Assert.That(message.Sensitivity, Is.EqualTo(EmailMessageSensitivity.ContainsLiveSecret));
        }
    }

    [Test]
    public void MapToEmailMessageMapsEnvelopeOptions()
    {
        var entry = new EmailOutboxEntry
        {
            Id = Guid.NewGuid(),
            ToAddress = "to@example.com",
            FromAddress = "from@example.com",
            ReplyToAddress = "reply@example.com",
            CcAddress = "cc@example.com",
            BccAddress = "bcc@example.com",
            Subject = "Subject",
            TextBody = "Text"
        };

        var message = EmailOutboxDispatch.MapToEmailMessage(entry);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(message.To, Is.EqualTo("to@example.com"));
            Assert.That(message.From, Is.EqualTo("from@example.com"));
            Assert.That(message.ReplyTo, Is.EqualTo("reply@example.com"));
            Assert.That(message.Cc, Is.EqualTo("cc@example.com"));
            Assert.That(message.Bcc, Is.EqualTo("bcc@example.com"));
        }
    }

    [Test]
    public void MapToEmailMessageThrowsForProtectedBodiesWithoutProtector()
    {
        ISecretProtector protector = new FakeSecretProtector();
        var entry = new EmailOutboxEntry
        {
            Id = Guid.NewGuid(),
            ToAddress = "to@example.com",
            Subject = "Subject",
            TextBody = protector.Protect("Live text"),
            BodyProtection = EmailOutboxBodyProtection.SecretProtector
        };

        var exception = Assert.Throws<InvalidOperationException>(() => EmailOutboxDispatch.MapToEmailMessage(entry));

        Assert.That(exception!.Message, Does.Contain("ISecretProtector"));
    }

    [Test]
    public void MapToEmailMessageThrowsForUnknownBodyProtection()
    {
        var entry = new EmailOutboxEntry
        {
            Id = Guid.NewGuid(),
            ToAddress = "to@example.com",
            Subject = "Subject",
            TextBody = "plain",
            BodyProtection = EmailOutboxBodyProtection.Unknown
        };

        Assert.Throws<InvalidOperationException>(() => EmailOutboxDispatch.MapToEmailMessage(entry, new FakeSecretProtector()));
    }

    [Test]
    public void MapToEmailMessageThrowsForSensitiveRowsWithoutProtectedBodies()
    {
        var entry = new EmailOutboxEntry
        {
            Id = Guid.NewGuid(),
            ToAddress = "to@example.com",
            Subject = "Subject",
            TextBody = "plain",
            Sensitivity = EmailMessageSensitivity.ContainsLiveSecret,
            BodyProtection = EmailOutboxBodyProtection.None
        };

        var exception = Assert.Throws<InvalidOperationException>(() => EmailOutboxDispatch.MapToEmailMessage(entry, new FakeSecretProtector()));

        Assert.That(exception!.Message, Does.Contain("without protected bodies"));
    }

    [Test]
    public void ParseBodyProtectionParsesKnownValuesCaseInsensitively()
    {
        Assert.That(EmailOutboxDispatch.ParseBodyProtection("secretprotector"), Is.EqualTo(EmailOutboxBodyProtection.SecretProtector));
    }

    [Test]
    public void ParseSensitivityParsesKnownValuesCaseInsensitively()
    {
        Assert.That(EmailOutboxDispatch.ParseSensitivity("containslivesecret"), Is.EqualTo(EmailMessageSensitivity.ContainsLiveSecret));
    }

    [Test]
    public void ParseSensitivityFallsBackToNormalForUnknownOrNumericValues()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(EmailOutboxDispatch.ParseSensitivity(null), Is.EqualTo(EmailMessageSensitivity.Normal));
            Assert.That(EmailOutboxDispatch.ParseSensitivity("Normal"), Is.EqualTo(EmailMessageSensitivity.Normal));
            Assert.That(EmailOutboxDispatch.ParseSensitivity("Unknown"), Is.EqualTo(EmailMessageSensitivity.Normal));
            Assert.That(EmailOutboxDispatch.ParseSensitivity("0"), Is.EqualTo(EmailMessageSensitivity.Normal));
            Assert.That(EmailOutboxDispatch.ParseSensitivity("1"), Is.EqualTo(EmailMessageSensitivity.Normal));
            Assert.That(EmailOutboxDispatch.ParseSensitivity("2"), Is.EqualTo(EmailMessageSensitivity.Normal));
        }
    }

    [Test]
    public void ParseBodyProtectionReturnsUnknownSentinelForUnknownValues()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(EmailOutboxDispatch.ParseBodyProtection("Unknown"), Is.EqualTo(EmailOutboxBodyProtection.Unknown));
            Assert.That(EmailOutboxDispatch.ParseBodyProtection("Bogus"), Is.EqualTo(EmailOutboxBodyProtection.Unknown));
            Assert.That(EmailOutboxDispatch.ParseBodyProtection("0"), Is.EqualTo(EmailOutboxBodyProtection.Unknown));
            Assert.That(EmailOutboxDispatch.ParseBodyProtection("1"), Is.EqualTo(EmailOutboxBodyProtection.Unknown));
            Assert.That(EmailOutboxDispatch.ParseBodyProtection("2"), Is.EqualTo(EmailOutboxBodyProtection.Unknown));
        }
    }

    [Test]
    public void CreateFailureUpdateSuppressesSensitiveErrorDetails()
    {
        var failure = EmailOutboxDispatch.CreateFailureUpdate(
            0,
            3,
            TimeSpan.FromSeconds(1),
            DateTimeOffset.UnixEpoch,
            new InvalidOperationException("live-token-link"),
            suppressErrorDetails: true);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(failure.LastError, Does.Contain("suppressed"));
            Assert.That(failure.LastError, Does.Not.Contain("live-token-link"));
        }
    }

    [Test]
    public void ShouldSuppressFailureDetailsForSensitiveOrProtectedEntries()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(EmailOutboxDispatch.ShouldSuppressFailureDetails(new EmailOutboxEntry
            {
                Id = Guid.NewGuid(),
                ToAddress = "to@example.com",
                Subject = "Subject"
            }), Is.False);
            Assert.That(EmailOutboxDispatch.ShouldSuppressFailureDetails(new EmailOutboxEntry
            {
                Id = Guid.NewGuid(),
                ToAddress = "to@example.com",
                Subject = "Subject",
                Sensitivity = EmailMessageSensitivity.ContainsLiveSecret
            }), Is.True);
            Assert.That(EmailOutboxDispatch.ShouldSuppressFailureDetails(new EmailOutboxEntry
            {
                Id = Guid.NewGuid(),
                ToAddress = "to@example.com",
                Subject = "Subject",
                BodyProtection = EmailOutboxBodyProtection.SecretProtector
            }), Is.True);
            Assert.That(EmailOutboxDispatch.ShouldSuppressFailureDetails(new EmailOutboxEntry
            {
                Id = Guid.NewGuid(),
                ToAddress = "to@example.com",
                Subject = "Subject",
                BodyProtection = EmailOutboxBodyProtection.Unknown
            }), Is.True);
        }
    }

    private sealed class FakeSecretProtector : ISecretProtector
    {
        private static readonly byte[] Prefix = "protected:"u8.ToArray();

        public byte[] Protect(byte[] data)
        {
            ArgumentNullException.ThrowIfNull(data);

            var protectedData = new byte[Prefix.Length + data.Length];
            Buffer.BlockCopy(Prefix, 0, protectedData, 0, Prefix.Length);
            Buffer.BlockCopy(data, 0, protectedData, Prefix.Length, data.Length);
            return protectedData;
        }

        public byte[] Unprotect(byte[] data)
        {
            ArgumentNullException.ThrowIfNull(data);

            return data.Skip(Prefix.Length).ToArray();
        }
    }
}
