using Ashlar.Operational;

namespace Ashlar.Tests.Operational;

internal sealed class AshlarCleanupOptionsTests
{
    [Test]
    public void ValidateAcceptsDefaults()
    {
        var options = new AshlarCleanupOptions();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(AshlarCleanupOptions.Validate(options), Is.True);
            Assert.That(options.RemoveSentSensitiveEmailsAfter, Is.EqualTo(TimeSpan.FromHours(1)));
            Assert.That(options.RemoveFailedSensitiveEmailsAfter, Is.EqualTo(TimeSpan.FromHours(1)));
            Assert.That(options.RemoveSentEmailsAfter, Is.EqualTo(TimeSpan.FromDays(7)));
            Assert.That(options.RemoveFailedEmailsAfter, Is.EqualTo(TimeSpan.FromDays(30)));
            Assert.That(options.RemoveDiscardedEmailsAfter, Is.EqualTo(TimeSpan.FromDays(30)));
            Assert.That(options.RemoveExpiredRememberedMfaDevicesAfter, Is.EqualTo(TimeSpan.FromDays(30)));
            Assert.That(options.RemoveRevokedRememberedMfaDevicesAfter, Is.EqualTo(TimeSpan.FromDays(30)));
            Assert.That(options.RemoveDiscardedSensitiveEmailsAfter, Is.EqualTo(TimeSpan.FromHours(1)));
            Assert.That(options.RemoveSentSecurityEventWebhooksAfter, Is.EqualTo(TimeSpan.FromDays(7)));
            Assert.That(options.RemoveFailedSecurityEventWebhooksAfter, Is.EqualTo(TimeSpan.FromDays(30)));
            Assert.That(options.RemoveDiscardedSecurityEventWebhooksAfter, Is.EqualTo(TimeSpan.FromDays(30)));
        }
    }

    [Test]
    public void ValidateRejectsInvalidBatchSize()
    {
        Assert.That(AshlarCleanupOptions.Validate(new AshlarCleanupOptions { BatchSize = 0 }), Is.False);
    }

    [Test]
    public void ValidateRejectsInvalidMaxBatchesPerRun()
    {
        Assert.That(AshlarCleanupOptions.Validate(new AshlarCleanupOptions { MaxBatchesPerRun = 0 }), Is.False);
    }

    [Test]
    public void ValidateRejectsInvalidCleanupInterval()
    {
        Assert.That(AshlarCleanupOptions.Validate(new AshlarCleanupOptions { CleanupInterval = TimeSpan.Zero }), Is.False);
    }

    [Test]
    public void ValidateRejectsNegativeRetention()
    {
        Assert.That(AshlarCleanupOptions.Validate(new AshlarCleanupOptions { RemoveExpiredSessionsAfter = TimeSpan.FromTicks(-1) }), Is.False);
    }

    [Test]
    public void ValidateRejectsNegativeAuthorizationGrantRetention()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(AshlarCleanupOptions.Validate(new AshlarCleanupOptions { RemoveExpiredAuthorizationGrantsAfter = TimeSpan.FromTicks(-1) }), Is.False);
            Assert.That(AshlarCleanupOptions.Validate(new AshlarCleanupOptions { RemoveRevokedAuthorizationGrantsAfter = TimeSpan.FromTicks(-1) }), Is.False);
        }
    }

    [Test]
    public void ValidateRejectsNegativeSensitiveEmailRetention()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(AshlarCleanupOptions.Validate(new AshlarCleanupOptions { RemoveSentSensitiveEmailsAfter = TimeSpan.FromTicks(-1) }), Is.False);
            Assert.That(AshlarCleanupOptions.Validate(new AshlarCleanupOptions { RemoveFailedSensitiveEmailsAfter = TimeSpan.FromTicks(-1) }), Is.False);
            Assert.That(AshlarCleanupOptions.Validate(new AshlarCleanupOptions { RemoveDiscardedSensitiveEmailsAfter = TimeSpan.FromTicks(-1) }), Is.False);
            Assert.That(AshlarCleanupOptions.Validate(new AshlarCleanupOptions { RemoveDiscardedEmailsAfter = TimeSpan.FromTicks(-1) }), Is.False);
        }
    }

    [Test]
    public void ValidateRejectsNegativeSecurityEventWebhookRetention()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(AshlarCleanupOptions.Validate(new AshlarCleanupOptions { RemoveSentSecurityEventWebhooksAfter = TimeSpan.FromTicks(-1) }), Is.False);
            Assert.That(AshlarCleanupOptions.Validate(new AshlarCleanupOptions { RemoveFailedSecurityEventWebhooksAfter = TimeSpan.FromTicks(-1) }), Is.False);
            Assert.That(AshlarCleanupOptions.Validate(new AshlarCleanupOptions { RemoveDiscardedSecurityEventWebhooksAfter = TimeSpan.FromTicks(-1) }), Is.False);
        }
    }

    [Test]
    public void ValidateRejectsNegativeRememberedMfaDeviceRetention()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(AshlarCleanupOptions.Validate(new AshlarCleanupOptions { RemoveExpiredRememberedMfaDevicesAfter = TimeSpan.FromTicks(-1) }), Is.False);
            Assert.That(AshlarCleanupOptions.Validate(new AshlarCleanupOptions { RemoveRevokedRememberedMfaDevicesAfter = TimeSpan.FromTicks(-1) }), Is.False);
        }
    }

    [Test]
    public void ValidateThrowsForNullOptions()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => AshlarCleanupOptions.Validate(null!));
    }

    [Test]
    public async Task SensitiveEmailCleanupFailsClosedForUnknownMarkers()
    {
        var predicates = new Dictionary<string, string>();

        await AshlarCleanupPlan.RunAsync(
            new AshlarCleanupOptions { MaxBatchesPerRun = 1 },
            DateTimeOffset.UtcNow,
            predicates,
            static (result, definition, _, _) =>
            {
                result[definition.Category] = definition.Predicate;
                return Task.FromResult(0);
            },
            static definition => new AshlarCleanupDeleteDefinition(
                definition.Category,
                definition.TableName,
                AshlarCleanupPlan.RenderPredicate(definition.PredicateTemplate, "@cutoff", "TRUE", "FALSE"),
                definition.OrderColumn),
            CancellationToken.None);

        foreach (var category in new[] { "sent_sensitive_emails", "failed_sensitive_emails", "discarded_sensitive_emails" })
        {
            Assert.That(predicates[category], Does.Contain("(sensitivity IS NULL OR sensitivity <> 'Normal')"));
        }
    }
}
