using Ashlar.Operational.Diagnostics;

namespace Ashlar.Tests.Operational.Diagnostics;

internal sealed class DiagnosticResultTests
{
    [Test]
    public void AshlarSchemaDiagnosticResultCanBeConstructedWithExpectedValues()
    {
        var checkedAt = new DateTimeOffset(2026, 5, 20, 12, 0, 0, TimeSpan.Zero);

        var result = new AshlarSchemaDiagnosticResult(
            AshlarDiagnosticStatus.Healthy,
            "Postgres",
            "schema is current",
            checkedAt,
            AshlarSchemaStatus.Current,
            4,
            4,
            0,
            "004_passkeys",
            "004_passkeys",
            "16",
            "16.3");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Healthy));
            Assert.That(result.ProviderName, Is.EqualTo("Postgres"));
            Assert.That(result.Reason, Is.EqualTo("schema is current"));
            Assert.That(result.CheckedAt, Is.EqualTo(checkedAt));
            Assert.That(result.SchemaStatus, Is.EqualTo(AshlarSchemaStatus.Current));
            Assert.That(result.AppliedMigrationCount, Is.EqualTo(4));
            Assert.That(result.ExpectedMigrationCount, Is.EqualTo(4));
            Assert.That(result.MissingMigrationCount, Is.Zero);
            Assert.That(result.LatestAppliedMigrationName, Is.EqualTo("004_passkeys"));
            Assert.That(result.LatestExpectedMigrationName, Is.EqualTo("004_passkeys"));
            Assert.That(result.MinimumProviderVersion, Is.EqualTo("16"));
            Assert.That(result.ProviderVersion, Is.EqualTo("16.3"));
        }
    }

    [Test]
    public void EmailOutboxDiagnosticResultCanBeConstructedWithExpectedValues()
    {
        var checkedAt = new DateTimeOffset(2026, 5, 20, 12, 0, 0, TimeSpan.Zero);
        var oldestPendingAt = checkedAt.AddMinutes(-10);
        var oldestFailedAt = checkedAt.AddHours(-1);

        var result = new EmailOutboxDiagnosticResult(
            AshlarDiagnosticStatus.Degraded,
            "Sqlite",
            "old failed mail exists",
            checkedAt,
            10,
            3,
            2,
            1,
            5,
            oldestPendingAt,
            oldestFailedAt,
            8,
            TimeSpan.FromSeconds(15),
            25);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Degraded));
            Assert.That(result.ProviderName, Is.EqualTo("Sqlite"));
            Assert.That(result.Reason, Is.EqualTo("old failed mail exists"));
            Assert.That(result.CheckedAt, Is.EqualTo(checkedAt));
            Assert.That(result.PendingCount, Is.EqualTo(10));
            Assert.That(result.ScheduledCount, Is.EqualTo(3));
            Assert.That(result.LockedCount, Is.EqualTo(2));
            Assert.That(result.ExpiredLockCount, Is.EqualTo(1));
            Assert.That(result.FailedCount, Is.EqualTo(5));
            Assert.That(result.OldestPendingAt, Is.EqualTo(oldestPendingAt));
            Assert.That(result.OldestFailedAt, Is.EqualTo(oldestFailedAt));
            Assert.That(result.MaxAttempts, Is.EqualTo(8));
            Assert.That(result.PollingInterval, Is.EqualTo(TimeSpan.FromSeconds(15)));
            Assert.That(result.BatchSize, Is.EqualTo(25));
        }
    }

    [Test]
    public void AshlarCleanupDiagnosticResultCanBeConstructedWithExpectedValues()
    {
        var checkedAt = new DateTimeOffset(2026, 5, 20, 12, 0, 0, TimeSpan.Zero);

        var result = new AshlarCleanupDiagnosticResult(
            AshlarDiagnosticStatus.Healthy,
            "Postgres",
            null,
            checkedAt,
            true,
            true,
            TimeSpan.FromMinutes(30),
            100,
            3,
            1,
            9);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Healthy));
            Assert.That(result.ProviderName, Is.EqualTo("Postgres"));
            Assert.That(result.Reason, Is.Null);
            Assert.That(result.CheckedAt, Is.EqualTo(checkedAt));
            Assert.That(result.Configured, Is.True);
            Assert.That(result.OptionsValid, Is.True);
            Assert.That(result.CleanupInterval, Is.EqualTo(TimeSpan.FromMinutes(30)));
            Assert.That(result.BatchSize, Is.EqualTo(100));
            Assert.That(result.MaxBatchesPerRun, Is.EqualTo(3));
            Assert.That(result.DisabledCategoryCount, Is.EqualTo(1));
            Assert.That(result.EnabledCategoryCount, Is.EqualTo(9));
        }
    }

    [Test]
    public void AuthenticationRateLimiterDiagnosticResultCanBeConstructedWithExpectedValues()
    {
        var checkedAt = new DateTimeOffset(2026, 5, 20, 12, 0, 0, TimeSpan.Zero);

        var result = new AuthenticationRateLimiterDiagnosticResult(
            AshlarDiagnosticStatus.Unhealthy,
            "Postgres",
            "cleanup is disabled",
            checkedAt,
            true,
            true,
            true,
            42,
            100,
            4,
            false,
            TimeSpan.FromMinutes(5),
            500);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Unhealthy));
            Assert.That(result.ProviderName, Is.EqualTo("Postgres"));
            Assert.That(result.Reason, Is.EqualTo("cleanup is disabled"));
            Assert.That(result.CheckedAt, Is.EqualTo(checkedAt));
            Assert.That(result.Configured, Is.True);
            Assert.That(result.Distributed, Is.True);
            Assert.That(result.Persistent, Is.True);
            Assert.That(result.ExpiredRowCount, Is.EqualTo(42));
            Assert.That(result.ActiveKeyCount, Is.EqualTo(100));
            Assert.That(result.BlockedKeyCount, Is.EqualTo(4));
            Assert.That(result.CleanupConfigured, Is.False);
            Assert.That(result.CleanupInterval, Is.EqualTo(TimeSpan.FromMinutes(5)));
            Assert.That(result.MaxCleanupRows, Is.EqualTo(500));
        }
    }
}
