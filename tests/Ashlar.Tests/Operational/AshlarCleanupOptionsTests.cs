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
        }
    }

    [Test]
    public void ValidateThrowsForNullOptions()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => AshlarCleanupOptions.Validate(null!));
    }
}
