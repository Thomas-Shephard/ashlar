using Ashlar.Operational;
using Ashlar.Operational.Diagnostics;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Tests.Operational.Diagnostics;

internal sealed class AshlarCleanupDiagnosticsRunnerTests
{
    private static readonly DateTimeOffset CheckedAt = new(2026, 5, 20, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public void CheckReturnsHealthyResultWhenOptionsAreValid()
    {
        var runner = new AshlarCleanupDiagnosticsRunner("TestProvider");
        var options = new AshlarCleanupOptions
        {
            CleanupInterval = TimeSpan.FromMinutes(30),
            BatchSize = 100,
            MaxBatchesPerRun = 3
        };

        var result = runner.Check(new FakeTimeProvider(CheckedAt), options, configured: true);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Healthy));
            Assert.That(result.ProviderName, Is.EqualTo("TestProvider"));
            Assert.That(result.Reason, Is.Null);
            Assert.That(result.CheckedAt, Is.EqualTo(CheckedAt));
            Assert.That(result.Configured, Is.True);
            Assert.That(result.OptionsValid, Is.True);
            Assert.That(result.CleanupInterval, Is.EqualTo(TimeSpan.FromMinutes(30)));
            Assert.That(result.BatchSize, Is.EqualTo(100));
            Assert.That(result.MaxBatchesPerRun, Is.EqualTo(3));
            Assert.That(result.DisabledCategoryCount, Is.EqualTo(1));
            Assert.That(result.EnabledCategoryCount, Is.EqualTo(24));
        }
    }

    [Test]
    public void CheckReturnsUnhealthyResultWhenOptionsAreInvalid()
    {
        var runner = new AshlarCleanupDiagnosticsRunner("TestProvider");
        var options = new AshlarCleanupOptions { BatchSize = 0 };

        var result = runner.Check(new FakeTimeProvider(CheckedAt), options, configured: true);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Unhealthy));
            Assert.That(result.Reason, Is.EqualTo("Ashlar cleanup options are invalid."));
            Assert.That(result.Configured, Is.True);
            Assert.That(result.OptionsValid, Is.False);
            Assert.That(result.BatchSize, Is.Zero);
            Assert.That(result.EnabledCategoryCount, Is.EqualTo(24));
            Assert.That(result.DisabledCategoryCount, Is.EqualTo(1));
        }
    }

    [Test]
    public void CheckCountsDisabledAndEnabledCategories()
    {
        var runner = new AshlarCleanupDiagnosticsRunner("TestProvider");
        var options = new AshlarCleanupOptions
        {
            RemoveAuditEventsAfter = TimeSpan.FromDays(1),
            RemoveSentEmailsAfter = null,
            RemoveFailedEmailsAfter = null
        };

        var result = runner.Check(new FakeTimeProvider(CheckedAt), options, configured: true);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.EnabledCategoryCount, Is.EqualTo(23));
            Assert.That(result.DisabledCategoryCount, Is.EqualTo(2));
        }
    }

    [Test]
    public void CheckReturnsNotSupportedWhenCleanupIsNotConfigured()
    {
        var runner = new AshlarCleanupDiagnosticsRunner("TestProvider");

        var result = runner.Check(new FakeTimeProvider(CheckedAt), null, configured: false);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.NotSupported));
            Assert.That(result.Reason, Is.EqualTo("Ashlar cleanup services are not configured."));
            Assert.That(result.CheckedAt, Is.EqualTo(CheckedAt));
            Assert.That(result.Configured, Is.False);
            Assert.That(result.OptionsValid, Is.False);
            Assert.That(result.CleanupInterval, Is.Null);
            Assert.That(result.BatchSize, Is.Null);
            Assert.That(result.MaxBatchesPerRun, Is.Null);
            Assert.That(result.EnabledCategoryCount, Is.Null);
            Assert.That(result.DisabledCategoryCount, Is.Null);
        }
    }

    [Test]
    public void CheckRejectsNullTimeProvider()
    {
        var runner = new AshlarCleanupDiagnosticsRunner("TestProvider");

        Assert.Throws<ArgumentNullException>(() => runner.Check(null!, new AshlarCleanupOptions(), configured: true));
    }
}
