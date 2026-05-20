using Ashlar.Operational;

namespace Ashlar.Tests.Operational;

internal sealed class AshlarCleanupOptionsTests
{
    [Test]
    public void ValidateAcceptsDefaults()
    {
        Assert.That(AshlarCleanupOptions.Validate(new AshlarCleanupOptions()), Is.True);
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
    public void ValidateThrowsForNullOptions()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => AshlarCleanupOptions.Validate(null!));
    }
}


