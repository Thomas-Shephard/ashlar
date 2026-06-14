using System.Reflection;
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

        using (Assert.EnterMultipleScope())
        {
            Assert.That(summary.Schema.AppliedMigrationCount, Is.EqualTo(4));
            Assert.That(summary.Schema.MissingMigrationCount, Is.Zero);
            Assert.That(summary.Cleanup.CleanupInterval, Is.EqualTo(TimeSpan.FromMinutes(30)));
            Assert.That(summary.EmailOutbox.PendingCount, Is.EqualTo(7));
            Assert.That(summary.EmailOutbox.FailedCount, Is.EqualTo(1));
            Assert.That(summary.EmailOutbox.PollingInterval, Is.EqualTo(TimeSpan.FromSeconds(15)));
            Assert.That(summary.SecurityEventWebhookOutbox.PendingCount, Is.EqualTo(7));
            Assert.That(summary.SecurityEventWebhookOutbox.PollingInterval, Is.EqualTo(TimeSpan.FromSeconds(15)));
            Assert.That(summary.AuthenticationRateLimiter.ActiveKeyCount, Is.EqualTo(11));
            Assert.That(summary.AuthenticationRateLimiter.CleanupInterval, Is.EqualTo(TimeSpan.FromMinutes(5)));
            Assert.That(summary.AuthenticationRateLimiter.MaxCleanupRows, Is.EqualTo(500));
        }

        var publicPropertyNames = typeof(AshlarOperationsSummary).Assembly
            .GetTypes()
            .Where(type => type.Namespace == "Ashlar.Operational.Diagnostics" && type.Name.Contains("Operations", StringComparison.Ordinal))
            .SelectMany(type => type.GetProperties(BindingFlags.Instance | BindingFlags.Public))
            .Select(property => property.Name)
            .ToArray();

        Assert.That(publicPropertyNames, Has.None.Matches<string>(name =>
            name.Contains("Secret", StringComparison.OrdinalIgnoreCase)
            || name.Contains("Token", StringComparison.OrdinalIgnoreCase)
            || name.Contains("Url", StringComparison.OrdinalIgnoreCase)
            || name.Equals("Uri", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith("Uri", StringComparison.OrdinalIgnoreCase)
            || name.Contains("Body", StringComparison.OrdinalIgnoreCase)
            || name.Contains("Header", StringComparison.OrdinalIgnoreCase)
            || name.Contains("LockOwner", StringComparison.OrdinalIgnoreCase)
            || name.Contains("RedisKey", StringComparison.OrdinalIgnoreCase)
            || name.Contains("ConnectionString", StringComparison.OrdinalIgnoreCase)
            || name.Contains("Sql", StringComparison.OrdinalIgnoreCase)
            || name.Contains("Metadata", StringComparison.OrdinalIgnoreCase)
            || name.Equals("Id", StringComparison.OrdinalIgnoreCase)));
    }

    [Test]
    public async Task ComponentReasonsAreProjectedAsSafeStrings()
    {
        var summary = await CreateService(schemaStatus: AshlarDiagnosticStatus.Degraded, schemaReason: "Schema has pending migrations.").GetSummaryAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(summary.Schema.Reason, Is.EqualTo("Schema has pending migrations."));
            Assert.That(summary.Issues.Single().Reason, Is.EqualTo("Schema has pending migrations."));
        }
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
            Assert.That(summary.Schema.Reason, Is.EqualTo("Diagnostic check failed."));
            Assert.That(summary.Schema.ProviderName, Is.Null);
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
            Assert.That(summary.Cleanup.Reason, Is.EqualTo("Diagnostic check failed."));
            Assert.That(summary.Cleanup.ProviderName, Is.Null);
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
            Assert.That(summary.AuthenticationRateLimiter.Reason, Is.EqualTo("Diagnostic check failed."));
            Assert.That(summary.AuthenticationRateLimiter.ProviderName, Is.Null);
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
            Assert.That(summary.EmailOutbox.Reason, Is.EqualTo("Diagnostic check failed."));
            Assert.That(summary.EmailOutbox.ProviderName, Is.Null);
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
            Assert.That(summary.SecurityEventWebhookOutbox.Reason, Is.EqualTo("Diagnostic check failed."));
            Assert.That(summary.SecurityEventWebhookOutbox.ProviderName, Is.Null);
            Assert.That(logger.WarningCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task CancellationIsNotSwallowed()
    {
        using var cancellationTokenSource = new CancellationTokenSource();
        cancellationTokenSource.Cancel();
        var service = CreateService(schemaDiagnostics: new CanceledSchemaDiagnostics());

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
    public async Task InnerDiagnosticCancellationBecomesSafeUnknownWhenCallerDidNotCancel()
    {
        var service = CreateService(schemaDiagnostics: new IndependentlyCanceledSchemaDiagnostics());

        var summary = await service.GetSummaryAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(summary.Schema.Status, Is.EqualTo(AshlarDiagnosticStatus.Unknown));
            Assert.That(summary.Schema.Reason, Is.EqualTo("Diagnostic check failed."));
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

    private static AshlarSchemaDiagnosticResult SchemaResult(AshlarDiagnosticStatus status, string? reason = null)
    {
        return new AshlarSchemaDiagnosticResult(
            status,
            "Sqlite",
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
            "Sqlite",
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
            "InMemory",
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
            "Sqlite",
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
            "Sqlite",
            status == AshlarDiagnosticStatus.Healthy ? null : "Webhook outbox needs attention.",
            CheckedAt,
            7,
            2,
            1,
            0,
            1,
            CheckedAt.AddMinutes(-10),
            CheckedAt.AddHours(-1),
            8,
            TimeSpan.FromSeconds(15),
            25);
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

    private sealed class CanceledSchemaDiagnostics : IAshlarSchemaDiagnostics
    {
        public Task<AshlarSchemaDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromCanceled<AshlarSchemaDiagnosticResult>(cancellationToken);
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
