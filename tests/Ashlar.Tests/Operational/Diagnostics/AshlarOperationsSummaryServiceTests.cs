using System.Reflection;
using System.Text.Json;
using Ashlar.Operational.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Tests.Operational.Diagnostics;

internal sealed class AshlarOperationsSummaryServiceTests
{
    private static readonly DateTimeOffset CheckedAt = new(2026, 5, 20, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task AllHealthyComponentsProduceHealthyOverallStatus()
    {
        var summary = await CreateService().GetSummaryAsync();

        Assert.That(summary.Status, Is.EqualTo(AshlarDiagnosticStatus.Healthy));
    }

    [Test]
    public async Task OneDegradedComponentProducesDegradedOverallStatus()
    {
        var summary = await CreateService(schemaStatus: AshlarDiagnosticStatus.Degraded).GetSummaryAsync();

        Assert.That(summary.Status, Is.EqualTo(AshlarDiagnosticStatus.Degraded));
    }

    [Test]
    public async Task OneUnknownComponentProducesDegradedOverallStatus()
    {
        var summary = await CreateService(schemaStatus: AshlarDiagnosticStatus.Unknown).GetSummaryAsync();

        Assert.That(summary.Status, Is.EqualTo(AshlarDiagnosticStatus.Degraded));
    }

    [Test]
    public async Task OneUnhealthyComponentProducesUnhealthyOverallStatus()
    {
        var summary = await CreateService(schemaStatus: AshlarDiagnosticStatus.Unhealthy).GetSummaryAsync();

        Assert.That(summary.Status, Is.EqualTo(AshlarDiagnosticStatus.Unhealthy));
    }

    [Test]
    public async Task NotSupportedOnlyComponentsDoNotMakeOverallUnhealthy()
    {
        var summary = await CreateService(
            schemaStatus: AshlarDiagnosticStatus.NotSupported,
            cleanupStatus: AshlarDiagnosticStatus.NotSupported,
            rateLimiterStatus: AshlarDiagnosticStatus.NotSupported,
            emailStatus: AshlarDiagnosticStatus.NotSupported,
            webhookStatus: AshlarDiagnosticStatus.NotSupported).GetSummaryAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(summary.Status, Is.EqualTo(AshlarDiagnosticStatus.Healthy));
            Assert.That(summary.Issues, Is.Empty);
        }
    }

    [Test]
    public async Task SafeProjectionDoesNotExposeRawSensitiveDiagnosticFields()
    {
        var summary = await CreateService().GetSummaryAsync();
        var issues = (ICollection<AshlarOperationsIssue>)summary.Issues;

        using (Assert.EnterMultipleScope())
        {
            Assert.That(summary.Schema, Is.EqualTo(new AshlarSchemaOperationsSummary(
                AshlarDiagnosticStatus.Healthy, CheckedAt, AshlarSchemaStatus.Current, 4, 4, 0)));
            Assert.That(summary.Cleanup, Is.EqualTo(new AshlarCleanupOperationsSummary(
                AshlarDiagnosticStatus.Healthy, CheckedAt, true, true, TimeSpan.FromMinutes(30), 100, 3, 9, 1)));
            Assert.That(summary.AuthenticationRateLimiter, Is.EqualTo(new AshlarAuthenticationRateLimiterOperationsSummary(
                AshlarDiagnosticStatus.Healthy, CheckedAt, true, false, false, null, 11, 2, false, TimeSpan.FromMinutes(5), 500)));
            Assert.That(summary.EmailOutbox, Is.EqualTo(new AshlarOutboxOperationsSummary(
                AshlarDiagnosticStatus.Healthy, CheckedAt, 7, 2, 1, 0, 1,
                CheckedAt.AddMinutes(-10), CheckedAt.AddHours(-1), 8, TimeSpan.FromSeconds(15), 25)));
            Assert.That(summary.SecurityEventWebhookOutbox, Is.EqualTo(new AshlarOutboxOperationsSummary(
                AshlarDiagnosticStatus.Healthy, CheckedAt, 17, 12, 11, 10, 9,
                CheckedAt.AddMinutes(-20), CheckedAt.AddHours(-2), 18, TimeSpan.FromSeconds(25), 35)));
            Assert.That(issues.IsReadOnly, Is.True);
            Assert.Throws<NotSupportedException>(() =>
                issues.Add(new AshlarOperationsIssue("schema", AshlarDiagnosticStatus.Unhealthy)));
        }

        AssertPublicProperties<AshlarOperationsSummary>(
            "Status", "CheckedAt", "Schema", "Cleanup", "AuthenticationRateLimiter",
            "EmailOutbox", "SecurityEventWebhookOutbox", "Issues");
        AssertPublicProperties<AshlarOperationsIssue>("Component", "Status");
        AssertPublicProperties<AshlarOperationsComponentSummary>("Status", "CheckedAt");
        AssertPublicProperties<AshlarSchemaOperationsSummary>(
            "Status", "CheckedAt", "SchemaStatus", "AppliedMigrationCount",
            "ExpectedMigrationCount", "MissingMigrationCount");
        AssertPublicProperties<AshlarCleanupOperationsSummary>(
            "Status", "CheckedAt", "Configured", "OptionsValid", "CleanupInterval",
            "BatchSize", "MaxBatchesPerRun", "EnabledCategoryCount", "DisabledCategoryCount");
        AssertPublicProperties<AshlarAuthenticationRateLimiterOperationsSummary>(
            "Status", "CheckedAt", "Configured", "Distributed", "Persistent",
            "ExpiredRowCount", "ActiveKeyCount", "BlockedKeyCount", "CleanupConfigured",
            "CleanupInterval", "MaxCleanupRows");
        AssertPublicProperties<AshlarOutboxOperationsSummary>(
            "Status", "CheckedAt", "PendingCount", "ScheduledCount", "LockedCount",
            "ExpiredLockCount", "FailedCount", "OldestPendingAt", "OldestFailedAt",
            "MaxAttempts", "PollingInterval", "BatchSize");

        Assert.That(
            JsonSerializer.SerializeToElement(summary).EnumerateObject().Select(property => property.Name),
            Is.EquivalentTo(typeof(AshlarOperationsSummary)
                .GetProperties(BindingFlags.Instance | BindingFlags.Public)
                .Select(property => property.Name)));
    }

    [Test]
    public async Task DiagnosticProviderNamesAndReasonsAreNotProjected()
    {
        var summary = await CreateService(
            schemaStatus: AshlarDiagnosticStatus.Degraded,
            schemaReason: "https://internal.example/?token=secret provider exception").GetSummaryAsync();

        Assert.That(summary.Issues.Single(), Is.EqualTo(new AshlarOperationsIssue("schema", AshlarDiagnosticStatus.Degraded)));
    }

    [Test]
    public void IndividualDiagnosticResultsExposeOnlyAggregateHealthAndConfigurationFields()
    {
        AssertPublicProperties<AshlarSchemaDiagnosticResult>(
            "Status", "ProviderName", "Reason", "CheckedAt", "SchemaStatus", "AppliedMigrationCount",
            "ExpectedMigrationCount", "MissingMigrationCount", "LatestAppliedMigrationName",
            "LatestExpectedMigrationName", "MinimumProviderVersion", "ProviderVersion");
        AssertPublicProperties<AshlarCleanupDiagnosticResult>(
            "Status", "ProviderName", "Reason", "CheckedAt", "Configured", "OptionsValid",
            "CleanupInterval", "BatchSize", "MaxBatchesPerRun", "DisabledCategoryCount", "EnabledCategoryCount");
        AssertPublicProperties<AuthenticationRateLimiterDiagnosticResult>(
            "Status", "ProviderName", "Reason", "CheckedAt", "Configured", "Distributed", "Persistent",
            "ExpiredRowCount", "ActiveKeyCount", "BlockedKeyCount", "CleanupConfigured", "CleanupInterval", "MaxCleanupRows");
        AssertPublicProperties<EmailOutboxDiagnosticResult>(
            "Status", "ProviderName", "Reason", "CheckedAt", "PendingCount", "ScheduledCount", "LockedCount",
            "ExpiredLockCount", "FailedCount", "SensitivePendingCount", "SensitiveScheduledCount",
            "SensitiveLockedCount", "SensitiveFailedCount", "OldestPendingAt", "OldestFailedAt",
            "MaxAttempts", "PollingInterval", "BatchSize");
        AssertPublicProperties<SecurityEventWebhookOutboxDiagnosticResult>(
            "Status", "ProviderName", "Reason", "CheckedAt", "PendingCount", "ScheduledCount", "LockedCount",
            "ExpiredLockCount", "FailedCount", "OldestPendingAt", "OldestFailedAt",
            "MaxAttempts", "PollingInterval", "BatchSize");
    }

    [Test]
    public async Task ComponentFailureBecomesSafeUnknownResultAndOtherComponentsAreReported()
    {
        var service = CreateService(schemaDiagnostics: new ThrowingSchemaDiagnostics());

        var summary = await service.GetSummaryAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(summary.Status, Is.EqualTo(AshlarDiagnosticStatus.Degraded));
            Assert.That(summary.Schema.Status, Is.EqualTo(AshlarDiagnosticStatus.Unknown));
            Assert.That(summary.Cleanup.Status, Is.EqualTo(AshlarDiagnosticStatus.Healthy));
            Assert.That(summary.EmailOutbox.Status, Is.EqualTo(AshlarDiagnosticStatus.Healthy));
            Assert.That(summary.Issues.Single().Component, Is.EqualTo("schema"));
        }
    }

    [Test]
    public async Task CleanupFailureBecomesSafeUnknownResult()
    {
        var service = CreateService(cleanupDiagnostics: new ThrowingCleanupDiagnostics());

        var summary = await service.GetSummaryAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(summary.Cleanup.Status, Is.EqualTo(AshlarDiagnosticStatus.Unknown));
        }
    }

    [Test]
    public async Task RateLimiterFailureBecomesSafeUnknownResult()
    {
        var service = CreateService(rateLimiterDiagnostics: new ThrowingRateLimiterDiagnostics());

        var summary = await service.GetSummaryAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(summary.AuthenticationRateLimiter.Status, Is.EqualTo(AshlarDiagnosticStatus.Unknown));
        }
    }

    [Test]
    public async Task EmailOutboxFailureBecomesSafeUnknownResult()
    {
        var service = CreateService(emailOutboxDiagnostics: new ThrowingEmailOutboxDiagnostics());

        var summary = await service.GetSummaryAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(summary.EmailOutbox.Status, Is.EqualTo(AshlarDiagnosticStatus.Unknown));
        }
    }

    [Test]
    public async Task WebhookOutboxFailureBecomesSafeUnknownResultAndLogsFailure()
    {
        var logger = new RecordingLogger();
        var service = CreateService(webhookOutboxDiagnostics: new ThrowingSecurityEventWebhookOutboxDiagnostics(), logger: logger);

        var summary = await service.GetSummaryAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(summary.SecurityEventWebhookOutbox.Status, Is.EqualTo(AshlarDiagnosticStatus.Unknown));
            Assert.That(logger.WarningCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task CancellationIsNotSwallowed()
    {
        using var cancellationTokenSource = new CancellationTokenSource();
        var service = CreateService(schemaDiagnostics: new CanceledSchemaDiagnostics(cancellationTokenSource));

        try
        {
            await service.GetSummaryAsync(cancellationTokenSource.Token);
            Assert.Fail("Expected cancellation to propagate.");
        }
        catch (OperationCanceledException)
        {
            Assert.Pass();
        }
    }

    [Test]
    public void PreCanceledCallStopsWhenDiagnosticsIgnoreCancellation()
    {
        using var cancellationTokenSource = new CancellationTokenSource();
        cancellationTokenSource.Cancel();

        Assert.ThrowsAsync<OperationCanceledException>(
            () => CreateService().GetSummaryAsync(cancellationTokenSource.Token));
    }

    [Test]
    public void CancellationAfterFinalDiagnosticIsNotIgnored()
    {
        using var cancellationTokenSource = new CancellationTokenSource();
        var service = CreateService(
            webhookOutboxDiagnostics: new CancelingSecurityEventWebhookOutboxDiagnostics(cancellationTokenSource));

        Assert.ThrowsAsync<OperationCanceledException>(
            () => service.GetSummaryAsync(cancellationTokenSource.Token));
    }

    [Test]
    public async Task InnerDiagnosticCancellationBecomesSafeUnknownWhenCallerDidNotCancel()
    {
        var service = CreateService(schemaDiagnostics: new IndependentlyCanceledSchemaDiagnostics());

        var summary = await service.GetSummaryAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(summary.Schema.Status, Is.EqualTo(AshlarDiagnosticStatus.Unknown));
        }
    }

    [Test]
    public async Task MissingDiagnosticsBecomeNotSupportedComponents()
    {
        var service = new AshlarOperationsSummaryService(
            [],
            [],
            [],
            [],
            [],
            new FakeTimeProvider(CheckedAt));

        var summary = await service.GetSummaryAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(summary.Status, Is.EqualTo(AshlarDiagnosticStatus.Healthy));
            Assert.That(summary.Schema.Status, Is.EqualTo(AshlarDiagnosticStatus.NotSupported));
            Assert.That(summary.Cleanup.Status, Is.EqualTo(AshlarDiagnosticStatus.NotSupported));
            Assert.That(summary.AuthenticationRateLimiter.Status, Is.EqualTo(AshlarDiagnosticStatus.NotSupported));
            Assert.That(summary.EmailOutbox.Status, Is.EqualTo(AshlarDiagnosticStatus.NotSupported));
            Assert.That(summary.SecurityEventWebhookOutbox.Status, Is.EqualTo(AshlarDiagnosticStatus.NotSupported));
            Assert.That(summary.Issues, Is.Empty);
        }
    }

    [Test]
    public void ConstructorRejectsNullArguments()
    {
        var schema = new SchemaDiagnostics(SchemaResult(AshlarDiagnosticStatus.Healthy));
        var cleanup = new CleanupDiagnostics(CleanupResult(AshlarDiagnosticStatus.Healthy));
        var rateLimiter = new RateLimiterDiagnostics(RateLimiterResult(AshlarDiagnosticStatus.Healthy));
        var emailOutbox = new EmailOutboxDiagnostics(EmailOutboxResult(AshlarDiagnosticStatus.Healthy));
        var webhookOutbox = new SecurityEventWebhookOutboxDiagnostics(WebhookOutboxResult(AshlarDiagnosticStatus.Healthy));
        var timeProvider = new FakeTimeProvider(CheckedAt);

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new AshlarOperationsSummaryService(null!, [cleanup], [rateLimiter], [emailOutbox], [webhookOutbox], timeProvider));
            Assert.Throws<ArgumentNullException>(() => _ = new AshlarOperationsSummaryService([schema], null!, [rateLimiter], [emailOutbox], [webhookOutbox], timeProvider));
            Assert.Throws<ArgumentNullException>(() => _ = new AshlarOperationsSummaryService([schema], [cleanup], null!, [emailOutbox], [webhookOutbox], timeProvider));
            Assert.Throws<ArgumentNullException>(() => _ = new AshlarOperationsSummaryService([schema], [cleanup], [rateLimiter], null!, [webhookOutbox], timeProvider));
            Assert.Throws<ArgumentNullException>(() => _ = new AshlarOperationsSummaryService([schema], [cleanup], [rateLimiter], [emailOutbox], null!, timeProvider));
            Assert.Throws<ArgumentNullException>(() => _ = new AshlarOperationsSummaryService([schema], [cleanup], [rateLimiter], [emailOutbox], [webhookOutbox], null!));
        }
    }

    private static AshlarOperationsSummaryService CreateService(
        AshlarDiagnosticStatus schemaStatus = AshlarDiagnosticStatus.Healthy,
        AshlarDiagnosticStatus cleanupStatus = AshlarDiagnosticStatus.Healthy,
        AshlarDiagnosticStatus rateLimiterStatus = AshlarDiagnosticStatus.Healthy,
        AshlarDiagnosticStatus emailStatus = AshlarDiagnosticStatus.Healthy,
        AshlarDiagnosticStatus webhookStatus = AshlarDiagnosticStatus.Healthy,
        string? schemaReason = null,
        IAshlarSchemaDiagnostics? schemaDiagnostics = null,
        IAshlarCleanupDiagnostics? cleanupDiagnostics = null,
        IAuthenticationRateLimiterDiagnostics? rateLimiterDiagnostics = null,
        IEmailOutboxDiagnostics? emailOutboxDiagnostics = null,
        ISecurityEventWebhookOutboxDiagnostics? webhookOutboxDiagnostics = null,
        ILogger<AshlarOperationsSummaryService>? logger = null)
    {
        var timeProvider = new FakeTimeProvider(CheckedAt);
        return new AshlarOperationsSummaryService(
            [schemaDiagnostics ?? new SchemaDiagnostics(SchemaResult(schemaStatus, schemaReason))],
            [cleanupDiagnostics ?? new CleanupDiagnostics(CleanupResult(cleanupStatus))],
            [rateLimiterDiagnostics ?? new RateLimiterDiagnostics(RateLimiterResult(rateLimiterStatus))],
            [emailOutboxDiagnostics ?? new EmailOutboxDiagnostics(EmailOutboxResult(emailStatus))],
            [webhookOutboxDiagnostics ?? new SecurityEventWebhookOutboxDiagnostics(WebhookOutboxResult(webhookStatus))],
            timeProvider,
            logger);
    }

    private static void AssertPublicProperties<T>(params string[] expected)
    {
        Assert.That(
            typeof(T).GetProperties(BindingFlags.Instance | BindingFlags.Public).Select(property => property.Name),
            Is.EquivalentTo(expected),
            $"Unexpected public field on low-sensitivity {typeof(T).Name} projection.");
    }

    private static AshlarSchemaDiagnosticResult SchemaResult(AshlarDiagnosticStatus status, string? reason = null)
    {
        return new AshlarSchemaDiagnosticResult(
            status,
            "SQLite",
            reason,
            CheckedAt,
            status == AshlarDiagnosticStatus.Healthy ? AshlarSchemaStatus.Current : AshlarSchemaStatus.Unknown,
            4,
            4,
            0,
            "004_passkeys",
            "004_passkeys",
            "3.45",
            "3.45");
    }

    private static AshlarCleanupDiagnosticResult CleanupResult(AshlarDiagnosticStatus status)
    {
        return new AshlarCleanupDiagnosticResult(
            status,
            "SQLite",
            status == AshlarDiagnosticStatus.Healthy ? null : "Cleanup needs attention.",
            CheckedAt,
            true,
            true,
            TimeSpan.FromMinutes(30),
            100,
            3,
            1,
            9);
    }

    private static AuthenticationRateLimiterDiagnosticResult RateLimiterResult(AshlarDiagnosticStatus status)
    {
        return new AuthenticationRateLimiterDiagnosticResult(
            status,
            "In-memory",
            status == AshlarDiagnosticStatus.Healthy ? null : "Rate limiter needs attention.",
            CheckedAt,
            true,
            false,
            false,
            null,
            11,
            2,
            false,
            TimeSpan.FromMinutes(5),
            500);
    }

    private static EmailOutboxDiagnosticResult EmailOutboxResult(AshlarDiagnosticStatus status)
    {
        return new EmailOutboxDiagnosticResult(
            status,
            "SQLite",
            status == AshlarDiagnosticStatus.Healthy ? null : "Email outbox needs attention.",
            CheckedAt,
            7,
            2,
            1,
            0,
            1,
            3,
            1,
            0,
            1,
            CheckedAt.AddMinutes(-10),
            CheckedAt.AddHours(-1),
            8,
            TimeSpan.FromSeconds(15),
            25);
    }

    private static SecurityEventWebhookOutboxDiagnosticResult WebhookOutboxResult(AshlarDiagnosticStatus status)
    {
        return new SecurityEventWebhookOutboxDiagnosticResult(
            status,
            "SQLite",
            status == AshlarDiagnosticStatus.Healthy ? null : "Webhook outbox needs attention.",
            CheckedAt,
            17,
            12,
            11,
            10,
            9,
            CheckedAt.AddMinutes(-20),
            CheckedAt.AddHours(-2),
            18,
            TimeSpan.FromSeconds(25),
            35);
    }

    private sealed class SchemaDiagnostics(AshlarSchemaDiagnosticResult result) : IAshlarSchemaDiagnostics
    {
        public Task<AshlarSchemaDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(result);
        }
    }

    private sealed class CleanupDiagnostics(AshlarCleanupDiagnosticResult result) : IAshlarCleanupDiagnostics
    {
        public Task<AshlarCleanupDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(result);
        }
    }

    private sealed class RateLimiterDiagnostics(AuthenticationRateLimiterDiagnosticResult result) : IAuthenticationRateLimiterDiagnostics
    {
        public Task<AuthenticationRateLimiterDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(result);
        }
    }

    private sealed class EmailOutboxDiagnostics(EmailOutboxDiagnosticResult result) : IEmailOutboxDiagnostics
    {
        public Task<EmailOutboxDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(result);
        }
    }

    private sealed class SecurityEventWebhookOutboxDiagnostics(SecurityEventWebhookOutboxDiagnosticResult result) : ISecurityEventWebhookOutboxDiagnostics
    {
        public Task<SecurityEventWebhookOutboxDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(result);
        }
    }

    private sealed class ThrowingSchemaDiagnostics : IAshlarSchemaDiagnostics
    {
        public Task<AshlarSchemaDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
        {
            throw new InvalidOperationException("contains raw provider failure details");
        }
    }

    private sealed class ThrowingCleanupDiagnostics : IAshlarCleanupDiagnostics
    {
        public Task<AshlarCleanupDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
        {
            throw new InvalidOperationException("contains raw provider failure details");
        }
    }

    private sealed class ThrowingRateLimiterDiagnostics : IAuthenticationRateLimiterDiagnostics
    {
        public Task<AuthenticationRateLimiterDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
        {
            throw new InvalidOperationException("contains raw provider failure details");
        }
    }

    private sealed class ThrowingEmailOutboxDiagnostics : IEmailOutboxDiagnostics
    {
        public Task<EmailOutboxDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
        {
            throw new InvalidOperationException("contains raw provider failure details");
        }
    }

    private sealed class ThrowingSecurityEventWebhookOutboxDiagnostics : ISecurityEventWebhookOutboxDiagnostics
    {
        public Task<SecurityEventWebhookOutboxDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
        {
            throw new InvalidOperationException("contains raw provider failure details");
        }
    }

    private sealed class CancelingSecurityEventWebhookOutboxDiagnostics(CancellationTokenSource cancellationTokenSource)
        : ISecurityEventWebhookOutboxDiagnostics
    {
        public Task<SecurityEventWebhookOutboxDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
        {
            cancellationTokenSource.Cancel();
            return Task.FromResult(WebhookOutboxResult(AshlarDiagnosticStatus.Healthy));
        }
    }

    private sealed class IndependentlyCanceledSchemaDiagnostics : IAshlarSchemaDiagnostics
    {
        public Task<AshlarSchemaDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
        {
            using var cancellationTokenSource = new CancellationTokenSource();
            cancellationTokenSource.Cancel();
            return Task.FromCanceled<AshlarSchemaDiagnosticResult>(cancellationTokenSource.Token);
        }
    }

    private sealed class CanceledSchemaDiagnostics(CancellationTokenSource cancellationTokenSource) : IAshlarSchemaDiagnostics
    {
        public Task<AshlarSchemaDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
        {
            cancellationTokenSource.Cancel();
            return Task.FromCanceled<AshlarSchemaDiagnosticResult>(cancellationToken);
        }
    }

    private sealed class RecordingLogger : ILogger<AshlarOperationsSummaryService>
    {
        public int WarningCount { get; private set; }

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull
        {
            return null;
        }

        public bool IsEnabled(LogLevel logLevel)
        {
            return true;
        }

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (logLevel == LogLevel.Warning)
            {
                WarningCount++;
            }
        }
    }
}
