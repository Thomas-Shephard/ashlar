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
    public async Task DispatchAsyncDeliversMessageAndMarksEntrySent()
    {
        var entry = CreateEntry();
        var transport = new RecordingEmailTransport();
        Guid? sentId = null;
        var failed = false;
        var context = CreateDispatchContext(
            transport,
            markAsSentAsync: (id, _) =>
            {
                sentId = id;
                return Task.CompletedTask;
            },
            markAsFailedAsync: (_, _, _) =>
            {
                failed = true;
                return Task.CompletedTask;
            });

        await EmailOutboxDispatch.DispatchAsync(entry, context, CancellationToken.None);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(transport.Messages, Has.Count.EqualTo(1));
            Assert.That(transport.Messages[0].TextBody, Is.EqualTo("Text"));
            Assert.That(sentId, Is.EqualTo(entry.Id));
            Assert.That(failed, Is.False);
        }
    }

    [Test]
    public async Task DispatchAsyncLogsAndMarksFailedWhenDeliveryFails()
    {
        var entry = CreateEntry(attemptCount: 1);
        var deliveryException = new InvalidOperationException("delivery failed");
        var transport = new RecordingEmailTransport { DeliverException = deliveryException };
        EmailOutboxEntry? failedEntry = null;
        Exception? failedException = null;
        Exception? loggedException = null;
        int? loggedAttemptCount = null;
        bool? loggedFinalFailure = null;
        var context = CreateDispatchContext(
            transport,
            maxAttempts: 2,
            markAsFailedAsync: (capturedEntry, exception, _) =>
            {
                failedEntry = capturedEntry;
                failedException = exception;
                return Task.CompletedTask;
            },
            logDeliveryFailed: (_, attemptCount, finalFailure, exception) =>
            {
                loggedAttemptCount = attemptCount;
                loggedFinalFailure = finalFailure;
                loggedException = exception;
            });

        await EmailOutboxDispatch.DispatchAsync(entry, context, CancellationToken.None);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(failedEntry, Is.SameAs(entry));
            Assert.That(failedException, Is.SameAs(deliveryException));
            Assert.That(loggedException, Is.SameAs(deliveryException));
            Assert.That(loggedAttemptCount, Is.EqualTo(2));
            Assert.That(loggedFinalFailure, Is.True);
        }
    }

    [Test]
    public async Task DispatchAsyncSuppressesLoggedFailureDetailsForSensitiveEntries()
    {
        ISecretProtector protector = new FakeSecretProtector();
        var entry = CreateEntry(
            textBody: protector.Protect("live-token"),
            sensitivity: EmailMessageSensitivity.ContainsLiveSecret,
            bodyProtection: EmailOutboxBodyProtection.SecretProtector);
        var deliveryException = new InvalidOperationException("live-token");
        var transport = new RecordingEmailTransport { DeliverException = deliveryException };
        Exception? failedException = null;
        Exception? loggedException = deliveryException;
        var context = CreateDispatchContext(
            transport,
            protector,
            markAsFailedAsync: (_, exception, _) =>
            {
                failedException = exception;
                return Task.CompletedTask;
            },
            logDeliveryFailed: (_, _, _, exception) => loggedException = exception);

        await EmailOutboxDispatch.DispatchAsync(entry, context, CancellationToken.None);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(transport.Messages[0].TextBody, Is.EqualTo("live-token"));
            Assert.That(failedException, Is.SameAs(deliveryException));
            Assert.That(loggedException, Is.Null);
        }
    }

    [Test]
    public void DispatchAsyncRethrowsRequestedCancellationWithoutMarkingFailed()
    {
        var entry = CreateEntry();
        using var cancellation = new CancellationTokenSource();
        var transport = new RecordingEmailTransport
        {
            OnDeliver = (_, _) =>
            {
                cancellation.Cancel();
                throw new OperationCanceledException();
            }
        };
        var failed = false;
        var context = CreateDispatchContext(
            transport,
            markAsFailedAsync: (_, _, _) =>
            {
                failed = true;
                return Task.CompletedTask;
            });

        Assert.ThrowsAsync<OperationCanceledException>(() =>
            EmailOutboxDispatch.DispatchAsync(entry, context, cancellation.Token));
        Assert.That(failed, Is.False);
    }

    [Test]
    public void DispatchAsyncThrowsForNullArguments()
    {
        var entry = CreateEntry();
        var context = CreateDispatchContext(new RecordingEmailTransport());

        Assert.Multiple(() =>
        {
            Assert.ThrowsAsync<ArgumentNullException>(() => EmailOutboxDispatch.DispatchAsync(null!, context, CancellationToken.None));
            Assert.ThrowsAsync<ArgumentNullException>(() => EmailOutboxDispatch.DispatchAsync(entry, null!, CancellationToken.None));
            Assert.ThrowsAsync<ArgumentNullException>(() => EmailOutboxDispatch.DispatchAsync(entry, context with { Transport = null! }, CancellationToken.None));
            Assert.ThrowsAsync<ArgumentNullException>(() => EmailOutboxDispatch.DispatchAsync(entry, context with { MarkAsSentAsync = null! }, CancellationToken.None));
            Assert.ThrowsAsync<ArgumentNullException>(() => EmailOutboxDispatch.DispatchAsync(entry, context with { MarkAsFailedAsync = null! }, CancellationToken.None));
            Assert.ThrowsAsync<ArgumentNullException>(() => EmailOutboxDispatch.DispatchAsync(entry, context with { LogDeliveryFailed = null! }, CancellationToken.None));
        });
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

    private static EmailOutboxEntry CreateEntry(
        int attemptCount = 0,
        string? textBody = "Text",
        EmailMessageSensitivity sensitivity = EmailMessageSensitivity.Normal,
        EmailOutboxBodyProtection bodyProtection = EmailOutboxBodyProtection.None)
    {
        return new EmailOutboxEntry
        {
            Id = Guid.NewGuid(),
            ToAddress = "to@example.com",
            Subject = "Subject",
            TextBody = textBody,
            Sensitivity = sensitivity,
            BodyProtection = bodyProtection,
            AttemptCount = attemptCount
        };
    }

    private static EmailOutboxDispatchContext CreateDispatchContext(
        IEmailTransport transport,
        ISecretProtector? secretProtector = null,
        int maxAttempts = 3,
        Func<Guid, CancellationToken, Task>? markAsSentAsync = null,
        Func<EmailOutboxEntry, Exception, CancellationToken, Task>? markAsFailedAsync = null,
        Action<Guid, int, bool, Exception?>? logDeliveryFailed = null)
    {
        return new EmailOutboxDispatchContext(
            transport,
            maxAttempts,
            markAsSentAsync ?? ((_, _) => Task.CompletedTask),
            markAsFailedAsync ?? ((_, _, _) => Task.CompletedTask),
            logDeliveryFailed ?? ((_, _, _, _) => { }),
            secretProtector);
    }

    private sealed class RecordingEmailTransport : IEmailTransport
    {
        public List<EmailMessage> Messages { get; } = [];

        public Exception? DeliverException { get; init; }

        public Action<EmailMessage, CancellationToken>? OnDeliver { get; init; }

        public Task DeliverAsync(EmailMessage message, CancellationToken cancellationToken = default)
        {
            Messages.Add(message);
            OnDeliver?.Invoke(message, cancellationToken);
            if (DeliverException != null)
            {
                throw DeliverException;
            }

            return Task.CompletedTask;
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
