using System.Diagnostics.CodeAnalysis;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.Models;
using Ashlar.Messaging;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Identity.Notifications;

[TestFixture]
internal sealed class SecurityNotificationServiceTests
{
    private Mock<IEmailSender> _emailSender;
    private SecurityNotificationOptions _options;
    private FakeTimeProvider _timeProvider;
    private InMemorySecurityNotificationSuppressionStore _suppressionStore;
    private SecurityNotificationService _service;

    [SetUp]
    public void SetUp()
    {
        _emailSender = new Mock<IEmailSender>();
        _options = new SecurityNotificationOptions
        {
            Enabled = true,
            EnabledTypes = { SecurityNotificationType.SignIn }
        };
        _timeProvider = new FakeTimeProvider(new DateTimeOffset(2026, 5, 9, 12, 0, 0, TimeSpan.Zero));
        _suppressionStore = new InMemorySecurityNotificationSuppressionStore();
        _service = new SecurityNotificationService(_emailSender.Object, Options.Create(_options), _suppressionStore, _timeProvider);
    }

    [Test]
    public async Task NotifyAsyncWhenDisabledDoesNotSendEmail()
    {
        _options.Enabled = false;
        var notification = new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = "user@example.com",
            OccurredAt = DateTimeOffset.UtcNow
        };

        var result = await _service.NotifyAsync(notification);

        Assert.That(result.Succeeded, Is.True);
        _emailSender.Verify(x => x.SendAsync(It.IsAny<EmailMessage>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task NotifyAsyncWhenTypeDisabledDoesNotSendEmail()
    {
        _options.EnabledTypes.Clear();
        var notification = new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = "user@example.com",
            OccurredAt = DateTimeOffset.UtcNow
        };

        var result = await _service.NotifyAsync(notification);

        Assert.That(result.Succeeded, Is.True);
        _emailSender.Verify(x => x.SendAsync(It.IsAny<EmailMessage>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void ConstructorShouldValidateRequiredDependencies()
    {
        Assert.Throws<ArgumentNullException>(() => _ = new SecurityNotificationService(null!, Options.Create(_options)));
        Assert.Throws<ArgumentNullException>(() => _ = new SecurityNotificationService(_emailSender.Object, null!));
        Assert.DoesNotThrow(() => _ = new SecurityNotificationService(_emailSender.Object, Options.Create(_options), logger: Mock.Of<ILogger<SecurityNotificationService>>()));
    }

    [Test]
    public void NotifyAsyncShouldThrowWhenNotificationIsNull()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(() => _service.NotifyAsync(null!));
    }

    [Test]
    public async Task NotifyAsyncReturnsFailureWhenTemplateIsMissing()
    {
        var type = (SecurityNotificationType)999;
        _options.EnabledTypes.Add(type);
        var notification = new SecurityNotification
        {
            Type = type,
            RecipientEmail = "user@example.com",
            OccurredAt = DateTimeOffset.UtcNow
        };

        var result = await _service.NotifyAsync(notification);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Does.Contain("No template found"));
        }
    }

    [Test]
    public async Task NotifyAsyncWhenEnabledSendsEmailWithRenderedTemplate()
    {
        var now = new DateTimeOffset(2026, 5, 9, 12, 0, 0, TimeSpan.Zero);
        var notification = new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = "user@example.com",
            OccurredAt = now,
            IpAddress = "127.0.0.1",
            UserAgent = "Mozilla/5.0"
        };

        var result = await _service.NotifyAsync(notification);

        Assert.That(result.Succeeded, Is.True);
        _emailSender.Verify(x => x.SendAsync(It.Is<EmailMessage>(m =>
            m.To == "user@example.com" &&
            m.Subject.Contains("New sign-in") &&
            m.TextBody != null && m.TextBody.Contains("127.0.0.1") &&
            m.TextBody.Contains(now.ToString("f", System.Globalization.CultureInfo.InvariantCulture))
        ), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task NotifyAsyncUsesSystemClockWhenTimeProviderIsNull()
    {
        var service = new SecurityNotificationService(_emailSender.Object, Options.Create(_options), _suppressionStore);
        var notification = new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = "clock@example.com",
            OccurredAt = DateTimeOffset.UtcNow
        };

        var result = await service.NotifyAsync(notification);

        Assert.That(result.Succeeded, Is.True);
    }

    [Test]
    public async Task NotifyAsyncWithTemplateOverrideUsesOverride()
    {
        _options.TemplateOverrides[SecurityNotificationType.SignIn] = new SecurityNotificationTemplate
        {
            Subject = "Custom Subject",
            Body = "Custom Body for {RecipientEmail}"
        };
        var notification = new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = "user@example.com",
            OccurredAt = DateTimeOffset.UtcNow
        };

        var result = await _service.NotifyAsync(notification);

        Assert.That(result.Succeeded, Is.True);
        _emailSender.Verify(x => x.SendAsync(It.Is<EmailMessage>(m =>
            m.Subject == "Custom Subject" &&
            m.TextBody == "Custom Body for user@example.com"
        ), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task NotifyAsyncLeavesUnknownPlaceholdersUnchanged()
    {
        _options.TemplateOverrides[SecurityNotificationType.SignIn] = new SecurityNotificationTemplate
        {
            Subject = "Subject",
            Body = "Unknown: {MissingValue}"
        };
        var notification = new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = "user@example.com",
            OccurredAt = DateTimeOffset.UtcNow
        };

        var result = await _service.NotifyAsync(notification);

        Assert.That(result.Succeeded, Is.True);
        _emailSender.Verify(x => x.SendAsync(It.Is<EmailMessage>(m => m.TextBody == "Unknown: {MissingValue}"), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task NotifyAsyncRendersSessionIdPlaceholder()
    {
        var sessionId = Guid.NewGuid();
        _options.TemplateOverrides[SecurityNotificationType.SignIn] = new SecurityNotificationTemplate
        {
            Subject = "Subject",
            Body = "Session: {SessionId}"
        };
        var notification = new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = "user@example.com",
            OccurredAt = DateTimeOffset.UtcNow,
            SessionId = sessionId
        };

        var result = await _service.NotifyAsync(notification);

        Assert.That(result.Succeeded, Is.True);
        _emailSender.Verify(x => x.SendAsync(It.Is<EmailMessage>(m => m.TextBody == $"Session: {sessionId}"), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public void NotifyAsyncRejectsRecipientEmailWithLineBreaks()
    {
        var notification = new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = "user@example.com\r\nBcc: attacker@example.com",
            OccurredAt = DateTimeOffset.UtcNow
        };

        Assert.ThrowsAsync<ArgumentException>(() => _service.NotifyAsync(notification));

        _emailSender.Verify(x => x.SendAsync(It.IsAny<EmailMessage>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task NotifyAsyncTrimsRecipientEmailBeforeSending()
    {
        var notification = new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = " user@example.com ",
            OccurredAt = DateTimeOffset.UtcNow
        };

        var result = await _service.NotifyAsync(notification);

        Assert.That(result.Succeeded, Is.True);
        _emailSender.Verify(x => x.SendAsync(It.Is<EmailMessage>(m => m.To == "user@example.com"), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task NotifyAsyncWithRedactedIpAndUserAgentRedactsContent()
    {
        _options.IncludeIpAddress = false;
        _options.IncludeUserAgent = false;
        var notification = new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = "user@example.com",
            OccurredAt = DateTimeOffset.UtcNow,
            IpAddress = "127.0.0.1",
            UserAgent = "Mozilla/5.0"
        };

        // Update default template to include UA for testing
        _options.TemplateOverrides[SecurityNotificationType.SignIn] = new SecurityNotificationTemplate
        {
            Subject = "Test",
            Body = "IP: {IpAddress}, UA: {UserAgent}"
        };

        var result = await _service.NotifyAsync(notification);

        Assert.That(result.Succeeded, Is.True);
        _emailSender.Verify(x => x.SendAsync(It.Is<EmailMessage>(m =>
            m.TextBody != null && m.TextBody.Contains("IP: [redacted]") &&
            m.TextBody.Contains("UA: [redacted]")
        ), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task NotifyAsyncWithMetadataReplacesPlaceholders()
    {
        _options.Cooldowns.Clear();
        var notification = new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = "user@example.com",
            OccurredAt = DateTimeOffset.UtcNow,
            Metadata = new Dictionary<string, string> { ["CustomKey"] = "CustomValue" }
        };

        _options.TemplateOverrides[SecurityNotificationType.SignIn] = new SecurityNotificationTemplate
        {
            Subject = "Test",
            Body = "Metadata: {CustomKey}"
        };

        var result = await _service.NotifyAsync(notification);

        Assert.That(result.Succeeded, Is.True);
        _emailSender.Verify(x => x.SendAsync(It.Is<EmailMessage>(m =>
            m.TextBody != null && m.TextBody.Contains("Metadata: CustomValue")
        ), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task NotifyAsyncIgnoresBlankMetadataKeys()
    {
        _options.Cooldowns.Clear();
        var notification = new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = "user@example.com",
            OccurredAt = DateTimeOffset.UtcNow,
            Metadata = new Dictionary<string, string> { [" "] = "ignored" }
        };
        _options.TemplateOverrides[SecurityNotificationType.SignIn] = new SecurityNotificationTemplate
        {
            Subject = "Test",
            Body = "Blank: { }"
        };

        var result = await _service.NotifyAsync(notification);

        Assert.That(result.Succeeded, Is.True);
        _emailSender.Verify(x => x.SendAsync(It.Is<EmailMessage>(m => m.TextBody == "Blank: { }"), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task NotifyAsyncDoesNotAllowMetadataToOverrideBuiltInPlaceholders()
    {
        _options.Cooldowns.Clear();
        var notification = new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = "user@example.com",
            OccurredAt = DateTimeOffset.UtcNow,
            Metadata = new Dictionary<string, string> { ["Type"] = "Injected" }
        };
        _options.TemplateOverrides[SecurityNotificationType.SignIn] = new SecurityNotificationTemplate
        {
            Subject = "Test",
            Body = "Type: {Type}"
        };

        var result = await _service.NotifyAsync(notification);

        Assert.That(result.Succeeded, Is.True);
        _emailSender.Verify(x => x.SendAsync(It.Is<EmailMessage>(m => m.TextBody == "Type: SignIn"), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task NotifyAsyncDoesNotResolvePlaceholdersIntroducedByValues()
    {
        _options.Cooldowns.Clear();
        var notification = new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = "user@example.com",
            OccurredAt = DateTimeOffset.UtcNow,
            IpAddress = "{CustomKey}",
            Metadata = new Dictionary<string, string> { ["CustomKey"] = "injected" }
        };

        _options.TemplateOverrides[SecurityNotificationType.SignIn] = new SecurityNotificationTemplate
        {
            Subject = "Test",
            Body = "IP: {IpAddress}, Metadata: {CustomKey}"
        };

        var result = await _service.NotifyAsync(notification);

        Assert.That(result.Succeeded, Is.True);
        _emailSender.Verify(x => x.SendAsync(It.Is<EmailMessage>(m =>
            m.TextBody == "IP: {CustomKey}, Metadata: injected"
        ), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task NotifyAsyncReplacesPlaceholdersCaseInsensitively()
    {
        _options.Cooldowns.Clear();
        var notification = new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = "user@example.com",
            OccurredAt = DateTimeOffset.UtcNow,
            IpAddress = "127.0.0.1"
        };

        _options.TemplateOverrides[SecurityNotificationType.SignIn] = new SecurityNotificationTemplate
        {
            Subject = "Test",
            Body = "Email: {recipientemail}, IP: {ipaddress}"
        };

        var result = await _service.NotifyAsync(notification);

        Assert.That(result.Succeeded, Is.True);
        _emailSender.Verify(x => x.SendAsync(It.Is<EmailMessage>(m =>
            m.TextBody == "Email: user@example.com, IP: 127.0.0.1"
        ), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task NotifyAsyncSanitizesNewLinesInSubjectAndBodyValues()
    {
        _options.Cooldowns.Clear();
        var notification = new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = "user@example.com",
            OccurredAt = DateTimeOffset.UtcNow,
            Metadata = new Dictionary<string, string> { ["Reason"] = "line1\r\nBcc: injected<script>" }
        };

        _options.TemplateOverrides[SecurityNotificationType.SignIn] = new SecurityNotificationTemplate
        {
            Subject = "Alert {Reason}",
            Body = "Reason: {Reason}"
        };

        var result = await _service.NotifyAsync(notification);

        Assert.That(result.Succeeded, Is.True);
        _emailSender.Verify(x => x.SendAsync(It.Is<EmailMessage>(m =>
            m.Subject == "Alert line1 Bcc: injected<script>" &&
            m.TextBody == "Reason: line1 Bcc: injected<script>"), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task NotifyAsyncDoesNotAllowMetadataToOverrideProtectedPlaceholders()
    {
        _options.Cooldowns.Clear();
        var notification = new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = "user@example.com",
            OccurredAt = DateTimeOffset.UtcNow,
            Metadata = new Dictionary<string, string> { ["RecipientEmail"] = "attacker@example.com" }
        };

        _options.TemplateOverrides[SecurityNotificationType.SignIn] = new SecurityNotificationTemplate
        {
            Subject = "Test",
            Body = "Recipient: {RecipientEmail}"
        };

        var result = await _service.NotifyAsync(notification);

        Assert.That(result.Succeeded, Is.True);
        _emailSender.Verify(x => x.SendAsync(It.Is<EmailMessage>(m =>
            m.TextBody == "Recipient: user@example.com"), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task NotifyAsyncTreatsNullMetadataValueAsEmpty()
    {
        _options.Cooldowns.Clear();
        var notification = new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = "user@example.com",
            OccurredAt = DateTimeOffset.UtcNow,
            // ReSharper disable once NullableWarningSuppressionIsUsed
            Metadata = new Dictionary<string, string> { ["Reason"] = null! }
        };

        _options.TemplateOverrides[SecurityNotificationType.SignIn] = new SecurityNotificationTemplate
        {
            Subject = "Test",
            Body = "Reason: {Reason}"
        };

        var result = await _service.NotifyAsync(notification);

        Assert.That(result.Succeeded, Is.True);
        _emailSender.Verify(x => x.SendAsync(It.Is<EmailMessage>(m =>
            m.TextBody == "Reason: "), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task NotifyAsyncWhenSenderFailsReturnsFailure()
    {
        _options.Cooldowns.Clear();
        _emailSender.Setup(x => x.SendAsync(It.IsAny<EmailMessage>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("SMTP failure"));

        var notification = new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = "user@example.com",
            OccurredAt = DateTimeOffset.UtcNow
        };

        var result = await _service.NotifyAsync(notification);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo("SMTP failure"));
        }
    }

    [Test]
    public void DefaultTemplatesShouldCoverEveryNotificationType()
    {
        foreach (var type in Enum.GetValues<SecurityNotificationType>())
        {
            Assert.That(SecurityNotificationOptions.DefaultTemplates, Does.ContainKey(type));
        }
    }

    [Test]
    public async Task NotifyAsyncSuppressesRepeatedNotificationWithinCooldown()
    {
        var notification = new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = "user@example.com",
            OccurredAt = _timeProvider.GetUtcNow()
        };

        var first = await _service.NotifyAsync(notification);
        var second = await _service.NotifyAsync(notification);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(first.Suppressed, Is.False);
            Assert.That(second.Suppressed, Is.True);
        }
        _emailSender.Verify(x => x.SendAsync(It.IsAny<EmailMessage>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task NotifyAsyncUsesCentralEmailNormalizationForSuppression()
    {
        await _service.NotifyAsync(new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = " User@Example.COM ",
            OccurredAt = _timeProvider.GetUtcNow()
        });

        var result = await _service.NotifyAsync(new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = "user@example.com",
            OccurredAt = _timeProvider.GetUtcNow()
        });

        Assert.That(result.Suppressed, Is.True);
        _emailSender.Verify(x => x.SendAsync(It.IsAny<EmailMessage>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task NotifyAsyncAllowsNotificationAfterCooldown()
    {
        var notification = new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = "user@example.com",
            OccurredAt = _timeProvider.GetUtcNow()
        };

        await _service.NotifyAsync(notification);
        _timeProvider.Advance(TimeSpan.FromMinutes(15));
        var result = await _service.NotifyAsync(notification);

        Assert.That(result.Suppressed, Is.False);
        _emailSender.Verify(x => x.SendAsync(It.IsAny<EmailMessage>(), It.IsAny<CancellationToken>()), Times.Exactly(2));
    }

    [Test]
    public async Task NotifyAsyncUsesLongerSuspiciousAttemptCooldown()
    {
        _options.EnabledTypes.Clear();
        _options.EnabledTypes.Add(SecurityNotificationType.SuspiciousAuthenticationAttempt);
        var notification = new SecurityNotification
        {
            Type = SecurityNotificationType.SuspiciousAuthenticationAttempt,
            RecipientEmail = "user@example.com",
            OccurredAt = _timeProvider.GetUtcNow()
        };

        await _service.NotifyAsync(notification);
        _timeProvider.Advance(TimeSpan.FromMinutes(30));
        var suppressed = await _service.NotifyAsync(notification);
        _timeProvider.Advance(TimeSpan.FromMinutes(30));
        var sent = await _service.NotifyAsync(notification);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(suppressed.Suppressed, Is.True);
            Assert.That(sent.Suppressed, Is.False);
        }
        _emailSender.Verify(x => x.SendAsync(It.IsAny<EmailMessage>(), It.IsAny<CancellationToken>()), Times.Exactly(2));
    }

    [Test]
    public async Task NotifyAsyncCanDisableCooldownForType()
    {
        _options.Cooldowns[SecurityNotificationType.SignIn] = TimeSpan.Zero;
        var notification = new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = "user@example.com",
            OccurredAt = _timeProvider.GetUtcNow()
        };

        await _service.NotifyAsync(notification);
        await _service.NotifyAsync(notification);

        _emailSender.Verify(x => x.SendAsync(It.IsAny<EmailMessage>(), It.IsAny<CancellationToken>()), Times.Exactly(2));
    }

    [Test]
    public async Task NotifyAsyncSendsWhenCooldownHasNoSuppressionStore()
    {
        var service = new SecurityNotificationService(_emailSender.Object, Options.Create(_options), null, _timeProvider);
        var notification = new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = "user@example.com",
            OccurredAt = _timeProvider.GetUtcNow()
        };

        var result = await service.NotifyAsync(notification);

        Assert.That(result.Suppressed, Is.False);
        _emailSender.Verify(x => x.SendAsync(It.IsAny<EmailMessage>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task NotifyAsyncDoesNotSuppressDifferentRecipients()
    {
        await _service.NotifyAsync(new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = "first@example.com",
            OccurredAt = _timeProvider.GetUtcNow()
        });

        var result = await _service.NotifyAsync(new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = "second@example.com",
            OccurredAt = _timeProvider.GetUtcNow()
        });

        Assert.That(result.Suppressed, Is.False);
        _emailSender.Verify(x => x.SendAsync(It.IsAny<EmailMessage>(), It.IsAny<CancellationToken>()), Times.Exactly(2));
    }

    [Test]
    public async Task NotifyAsyncDoesNotSuppressDifferentTypesForSameRecipient()
    {
        _options.EnabledTypes.Add(SecurityNotificationType.TotpDisabled);

        await _service.NotifyAsync(new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = "user@example.com",
            OccurredAt = _timeProvider.GetUtcNow()
        });

        var result = await _service.NotifyAsync(new SecurityNotification
        {
            Type = SecurityNotificationType.TotpDisabled,
            RecipientEmail = "user@example.com",
            OccurredAt = _timeProvider.GetUtcNow()
        });

        Assert.That(result.Suppressed, Is.False);
        _emailSender.Verify(x => x.SendAsync(It.IsAny<EmailMessage>(), It.IsAny<CancellationToken>()), Times.Exactly(2));
    }

    [Test]
    public void SecurityNotificationFromContextCopiesContextValues()
    {
        var sessionId = Guid.NewGuid();
        var metadata = new Dictionary<string, string> { ["reason"] = "test" };
        var notification = SecurityNotification.FromContext(
            SecurityNotificationType.SessionRevoked,
            "user@example.com",
            _timeProvider.GetUtcNow(),
            new AuthenticationContext(IpAddress: "203.0.113.10", UserAgent: "NUnit"),
            sessionId,
            metadata);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(notification.IpAddress, Is.EqualTo("203.0.113.10"));
            Assert.That(notification.UserAgent, Is.EqualTo("NUnit"));
            Assert.That(notification.SessionId, Is.EqualTo(sessionId));
            Assert.That(notification.Metadata, Is.SameAs(metadata));
        }
    }

    [Test]
    public void SecurityNotificationFromContextAllowsNullContext()
    {
        var notification = SecurityNotification.FromContext(
            SecurityNotificationType.SignIn,
            "user@example.com",
            _timeProvider.GetUtcNow());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(notification.IpAddress, Is.Null);
            Assert.That(notification.UserAgent, Is.Null);
            Assert.That(notification.SessionId, Is.Null);
            Assert.That(notification.Metadata, Is.Null);
        }
    }

    [Test]
    public void SuppressionStoreShouldValidateNotification()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _suppressionStore.ShouldSend(null!, TimeSpan.FromMinutes(1), _timeProvider.GetUtcNow()));
    }

    [Test]
    public void SuppressionStoreShouldSendWhenCooldownIsZeroOrNegative()
    {
        var notification = new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = "user@example.com",
            OccurredAt = _timeProvider.GetUtcNow()
        };

        using (Assert.EnterMultipleScope())
        {
            Assert.That(_suppressionStore.ShouldSend(notification, TimeSpan.Zero, _timeProvider.GetUtcNow()), Is.True);
            Assert.That(_suppressionStore.ShouldSend(notification, TimeSpan.FromTicks(-1), _timeProvider.GetUtcNow()), Is.True);
        }
    }

    [Test]
    public void SuppressionStoreShouldCleanupExpiredEntries()
    {
        var now = _timeProvider.GetUtcNow();
        var expired = new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = "expired@example.com",
            OccurredAt = now
        };
        var active = new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = "active@example.com",
            OccurredAt = now
        };

        using (Assert.EnterMultipleScope())
        {
            Assert.That(_suppressionStore.ShouldSend(expired, TimeSpan.FromMinutes(1), now), Is.True);
            Assert.That(_suppressionStore.ShouldSend(active, TimeSpan.FromHours(1), now), Is.True);
        }

        var later = now.AddMinutes(2);
        for (var i = 0; i < 253; i++)
        {
            var filler = new SecurityNotification
            {
                Type = SecurityNotificationType.SignIn,
                RecipientEmail = $"cleanup-{i}@example.com",
                OccurredAt = later
            };
            Assert.That(_suppressionStore.ShouldSend(filler, TimeSpan.FromHours(1), later), Is.True);
        }

        using (Assert.EnterMultipleScope())
        {
            Assert.That(_suppressionStore.ShouldSend(active, TimeSpan.FromHours(1), later), Is.False);
            Assert.That(_suppressionStore.ShouldSend(expired, TimeSpan.FromMinutes(1), later), Is.True);
        }
    }

    [Test]
    public void SuppressionStoreShouldHandleConcurrentFirstSendForSameNotification()
    {
        var store = new InMemorySecurityNotificationSuppressionStore();
        var notification = new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = "race@example.com",
            OccurredAt = _timeProvider.GetUtcNow()
        };
        var start = new ManualResetEventSlim();
        var results = new bool[32];

        var tasks = Enumerable.Range(0, results.Length).Select(index => Task.Run(() =>
        {
            start.Wait();
            results[index] = store.ShouldSend(notification, TimeSpan.FromMinutes(1), _timeProvider.GetUtcNow());
        })).ToArray();
        start.Set();
        Task.WaitAll(tasks);

        Assert.That(results.Count(result => result), Is.EqualTo(1));
    }

    [Test]
    public void SuppressionStoreShouldHandleConcurrentSendAfterCooldown()
    {
        var store = new InMemorySecurityNotificationSuppressionStore();
        var notification = new SecurityNotification
        {
            Type = SecurityNotificationType.SignIn,
            RecipientEmail = "expired-race@example.com",
            OccurredAt = _timeProvider.GetUtcNow()
        };
        Assert.That(store.ShouldSend(notification, TimeSpan.FromTicks(1), _timeProvider.GetUtcNow()), Is.True);

        var later = _timeProvider.GetUtcNow().AddSeconds(1);
        var start = new ManualResetEventSlim();
        var results = new bool[64];
        var tasks = Enumerable.Range(0, results.Length).Select(index => Task.Run(() =>
        {
            start.Wait();
            results[index] = store.ShouldSend(notification, TimeSpan.FromMinutes(1), later);
        })).ToArray();

        start.Set();
        Task.WaitAll(tasks);

        Assert.That(results.Count(result => result), Is.EqualTo(1));
    }

}
