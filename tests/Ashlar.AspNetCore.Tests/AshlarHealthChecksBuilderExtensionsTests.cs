using Ashlar.AspNetCore.Diagnostics;
using Ashlar.Operational.Diagnostics;
using Ashlar.Testing.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace Ashlar.AspNetCore.Tests;

internal sealed class AshlarHealthChecksBuilderExtensionsTests
{
    private static readonly DateTimeOffset Now = new(2026, 5, 22, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task AddAshlarSchemaShouldRegisterHealthCheck()
    {
        using var provider = BuildProvider(services =>
        {
            services.AddSingleton<IAshlarSchemaDiagnostics>(_ => new SchemaDiagnostics(SchemaResult()));
            services.AddHealthChecks().AddAshlarSchema();
        });

        var report = await CheckAsync(provider);

        Assert.That(report.Entries.Keys, Contains.Item(AshlarHealthCheckNames.Schema));
    }

    [Test]
    public async Task AddAshlarEmailOutboxShouldRegisterHealthCheck()
    {
        using var provider = BuildProvider(services =>
        {
            services.AddSingleton<IEmailOutboxDiagnostics>(_ => new EmailOutboxDiagnostics(EmailOutboxResult()));
            services.AddHealthChecks().AddAshlarEmailOutbox();
        });

        var report = await CheckAsync(provider);

        Assert.That(report.Entries.Keys, Contains.Item(AshlarHealthCheckNames.EmailOutbox));
    }

    [Test]
    public async Task AddAshlarSecurityEventWebhookOutboxShouldRegisterHealthCheck()
    {
        using var provider = BuildProvider(services =>
        {
            services.AddSingleton<ISecurityEventWebhookOutboxDiagnostics>(_ => new SecurityEventWebhookOutboxDiagnostics(SecurityEventWebhookOutboxResult()));
            services.AddHealthChecks().AddAshlarSecurityEventWebhookOutbox();
        });

        var report = await CheckAsync(provider);

        Assert.That(report.Entries.Keys, Contains.Item(AshlarHealthCheckNames.SecurityEventWebhookOutbox));
    }

    [Test]
    public async Task AddAshlarCleanupShouldRegisterHealthCheck()
    {
        using var provider = BuildProvider(services =>
        {
            services.AddSingleton<IAshlarCleanupDiagnostics>(_ => new CleanupDiagnostics(CleanupResult()));
            services.AddHealthChecks().AddAshlarCleanup();
        });

        var report = await CheckAsync(provider);

        Assert.That(report.Entries.Keys, Contains.Item(AshlarHealthCheckNames.Cleanup));
    }

    [Test]
    public async Task AddAshlarRateLimiterShouldRegisterHealthCheck()
    {
        using var provider = BuildProvider(services =>
        {
            services.AddSingleton<IAuthenticationRateLimiterDiagnostics>(_ => new RateLimiterDiagnostics(RateLimiterResult()));
            services.AddHealthChecks().AddAshlarRateLimiter();
        });

        var report = await CheckAsync(provider);

        Assert.That(report.Entries.Keys, Contains.Item(AshlarHealthCheckNames.RateLimiter));
    }

    [Test]
    public async Task HealthyDiagnosticsShouldMapToHealthyResults()
    {
        using var provider = BuildProvider(services =>
        {
            services.AddSingleton<IAshlarSchemaDiagnostics>(_ => new SchemaDiagnostics(SchemaResult()));
            services.AddSingleton<IEmailOutboxDiagnostics>(_ => new EmailOutboxDiagnostics(EmailOutboxResult()));
            services.AddSingleton<ISecurityEventWebhookOutboxDiagnostics>(_ => new SecurityEventWebhookOutboxDiagnostics(SecurityEventWebhookOutboxResult()));
            services.AddSingleton<IAshlarCleanupDiagnostics>(_ => new CleanupDiagnostics(CleanupResult()));
            services.AddSingleton<IAuthenticationRateLimiterDiagnostics>(_ => new RateLimiterDiagnostics(RateLimiterResult()));
            services.AddHealthChecks()
                .AddAshlarSchema()
                .AddAshlarEmailOutbox()
                .AddAshlarSecurityEventWebhookOutbox()
                .AddAshlarCleanup()
                .AddAshlarRateLimiter();
        });

        var report = await CheckAsync(provider);

        Assert.That(report.Entries.Values.Select(entry => entry.Status), Is.All.EqualTo(HealthStatus.Healthy));
    }

    [Test]
    public async Task UnknownDiagnosticsShouldMapAppropriately()
    {
        using var provider = BuildProvider(services =>
        {
            services.AddSingleton<IAshlarSchemaDiagnostics>(_ => new SchemaDiagnostics(SchemaResult(AshlarDiagnosticStatus.Unknown, AshlarSchemaStatus.Unknown)));
            services.AddSingleton<IEmailOutboxDiagnostics>(_ => new EmailOutboxDiagnostics(EmailOutboxResult(AshlarDiagnosticStatus.Unknown)));
            services.AddSingleton<ISecurityEventWebhookOutboxDiagnostics>(_ => new SecurityEventWebhookOutboxDiagnostics(SecurityEventWebhookOutboxResult(AshlarDiagnosticStatus.Unknown)));
            services.AddSingleton<IAshlarCleanupDiagnostics>(_ => new CleanupDiagnostics(CleanupResult(AshlarDiagnosticStatus.Unknown)));
            services.AddSingleton<IAuthenticationRateLimiterDiagnostics>(_ => new RateLimiterDiagnostics(RateLimiterResult(AshlarDiagnosticStatus.Unknown)));
            services.AddHealthChecks()
                .AddAshlarSchema()
                .AddAshlarEmailOutbox()
                .AddAshlarSecurityEventWebhookOutbox()
                .AddAshlarCleanup()
                .AddAshlarRateLimiter();
        });

        var report = await CheckAsync(provider);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(report.Entries[AshlarHealthCheckNames.Schema].Status, Is.EqualTo(HealthStatus.Degraded));
            Assert.That(report.Entries[AshlarHealthCheckNames.EmailOutbox].Status, Is.EqualTo(HealthStatus.Unhealthy));
            Assert.That(report.Entries[AshlarHealthCheckNames.SecurityEventWebhookOutbox].Status, Is.EqualTo(HealthStatus.Unhealthy));
            Assert.That(report.Entries[AshlarHealthCheckNames.Cleanup].Status, Is.EqualTo(HealthStatus.Unhealthy));
            Assert.That(report.Entries[AshlarHealthCheckNames.RateLimiter].Status, Is.EqualTo(HealthStatus.Unhealthy));
        }
    }

    [Test]
    public async Task DegradedAndUnhealthyDiagnosticsShouldMapDirectly()
    {
        using var provider = BuildProvider(services =>
        {
            services.AddSingleton<IEmailOutboxDiagnostics>(_ => new EmailOutboxDiagnostics(EmailOutboxResult(AshlarDiagnosticStatus.Degraded)));
            services.AddSingleton<ISecurityEventWebhookOutboxDiagnostics>(_ => new SecurityEventWebhookOutboxDiagnostics(SecurityEventWebhookOutboxResult(AshlarDiagnosticStatus.Degraded)));
            services.AddSingleton<IAuthenticationRateLimiterDiagnostics>(_ => new RateLimiterDiagnostics(RateLimiterResult(AshlarDiagnosticStatus.Unhealthy)));
            services.AddSingleton<IAshlarSchemaDiagnostics>(_ => new SchemaDiagnostics(SchemaResult(AshlarDiagnosticStatus.Degraded, AshlarSchemaStatus.Unknown)));
            services.AddSingleton<IAshlarCleanupDiagnostics>(_ => new CleanupDiagnostics(CleanupResult(AshlarDiagnosticStatus.Degraded)));
            services.AddHealthChecks()
                .AddAshlarEmailOutbox()
                .AddAshlarSecurityEventWebhookOutbox()
                .AddAshlarRateLimiter()
                .AddAshlarSchema()
                .AddAshlarCleanup();
        });

        var report = await CheckAsync(provider);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(report.Entries[AshlarHealthCheckNames.EmailOutbox].Status, Is.EqualTo(HealthStatus.Degraded));
            Assert.That(report.Entries[AshlarHealthCheckNames.SecurityEventWebhookOutbox].Status, Is.EqualTo(HealthStatus.Degraded));
            Assert.That(report.Entries[AshlarHealthCheckNames.RateLimiter].Status, Is.EqualTo(HealthStatus.Unhealthy));
            Assert.That(report.Entries[AshlarHealthCheckNames.Schema].Status, Is.EqualTo(HealthStatus.Degraded));
            Assert.That(report.Entries[AshlarHealthCheckNames.Cleanup].Status, Is.EqualTo(HealthStatus.Degraded));
        }
    }

    [Test]
    public async Task NotSupportedDiagnosticsShouldUseDefaultDegradedStatus()
    {
        using var provider = BuildProvider(services =>
        {
            services.AddSingleton<IAshlarSchemaDiagnostics>(_ => new SchemaDiagnostics(SchemaResult(AshlarDiagnosticStatus.NotSupported, AshlarSchemaStatus.Unknown)));
            services.AddSingleton<IEmailOutboxDiagnostics>(_ => new EmailOutboxDiagnostics(EmailOutboxResult(AshlarDiagnosticStatus.NotSupported)));
            services.AddSingleton<ISecurityEventWebhookOutboxDiagnostics>(_ => new SecurityEventWebhookOutboxDiagnostics(SecurityEventWebhookOutboxResult(AshlarDiagnosticStatus.NotSupported)));
            services.AddSingleton<IAshlarCleanupDiagnostics>(_ => new CleanupDiagnostics(CleanupResult(AshlarDiagnosticStatus.NotSupported, configured: false, optionsValid: false)));
            services.AddSingleton<IAuthenticationRateLimiterDiagnostics>(_ => new RateLimiterDiagnostics(RateLimiterResult(AshlarDiagnosticStatus.NotSupported)));
            services.AddHealthChecks().AddAshlarHealthChecks();
        });

        var report = await CheckAsync(provider);

        Assert.That(report.Entries.Values.Select(entry => entry.Status), Is.All.EqualTo(HealthStatus.Degraded));
    }

    [Test]
    public async Task NotSupportedDiagnosticsShouldUseConfiguredOverride()
    {
        using var provider = BuildProvider(services =>
        {
            services.AddSingleton<IAshlarSchemaDiagnostics>(_ => new SchemaDiagnostics(SchemaResult(AshlarDiagnosticStatus.NotSupported, AshlarSchemaStatus.Unknown)));
            services.AddSingleton<IEmailOutboxDiagnostics>(_ => new EmailOutboxDiagnostics(EmailOutboxResult(AshlarDiagnosticStatus.NotSupported)));
            services.AddSingleton<ISecurityEventWebhookOutboxDiagnostics>(_ => new SecurityEventWebhookOutboxDiagnostics(SecurityEventWebhookOutboxResult(AshlarDiagnosticStatus.NotSupported)));
            services.AddSingleton<IAshlarCleanupDiagnostics>(_ => new CleanupDiagnostics(CleanupResult(AshlarDiagnosticStatus.NotSupported, configured: false, optionsValid: false)));
            services.AddSingleton<IAuthenticationRateLimiterDiagnostics>(_ => new RateLimiterDiagnostics(RateLimiterResult(AshlarDiagnosticStatus.NotSupported)));
            services.AddHealthChecks()
                .AddAshlarSchema(options => options.NotSupportedStatus = HealthStatus.Healthy)
                .AddAshlarEmailOutbox(options => options.NotSupportedStatus = HealthStatus.Healthy)
                .AddAshlarSecurityEventWebhookOutbox(options => options.NotSupportedStatus = HealthStatus.Healthy)
                .AddAshlarCleanup(options => options.NotSupportedStatus = HealthStatus.Healthy)
                .AddAshlarRateLimiter(options => options.NotSupportedStatus = HealthStatus.Healthy);
        });

        var report = await CheckAsync(provider);

        Assert.That(report.Entries.Values.Select(entry => entry.Status), Is.All.EqualTo(HealthStatus.Healthy));
    }

    [TestCase(AshlarSchemaStatus.NotInitialized)]
    [TestCase(AshlarSchemaStatus.PendingMigrations)]
    public async Task SchemaNotInitializedOrPendingShouldMapToUnhealthy(AshlarSchemaStatus schemaStatus)
    {
        using var provider = BuildProvider(services =>
        {
            services.AddSingleton<IAshlarSchemaDiagnostics>(_ => new SchemaDiagnostics(SchemaResult(AshlarDiagnosticStatus.Unhealthy, schemaStatus)));
            services.AddHealthChecks().AddAshlarSchema();
        });

        var report = await CheckAsync(provider);

        Assert.That(report.Entries[AshlarHealthCheckNames.Schema].Status, Is.EqualTo(HealthStatus.Unhealthy));
    }

    [Test]
    public async Task SchemaHealthyDiagnosticWithUnknownSchemaStatusShouldDegrade()
    {
        using var provider = BuildProvider(services =>
        {
            services.AddSingleton<IAshlarSchemaDiagnostics>(_ => new SchemaDiagnostics(SchemaResult(AshlarDiagnosticStatus.Healthy, AshlarSchemaStatus.Unknown)));
            services.AddHealthChecks().AddAshlarSchema();
        });

        var report = await CheckAsync(provider);

        Assert.That(report.Entries[AshlarHealthCheckNames.Schema].Status, Is.EqualTo(HealthStatus.Degraded));
    }

    [Test]
    public async Task EmailOutboxThresholdBreachesShouldDegradeHealth()
    {
        using var provider = BuildProvider(services =>
        {
            services.AddSingleton<IEmailOutboxDiagnostics>(_ => new EmailOutboxDiagnostics(EmailOutboxResult(
                pendingCount: 10,
                expiredLockCount: 2,
                failedCount: 3,
                oldestPendingAt: Now.AddMinutes(-10))));
            services.AddHealthChecks().AddAshlarEmailOutbox(options =>
            {
                options.PendingCountThreshold = 5;
                options.ExpiredLockCountThreshold = 1;
                options.FailedCountThreshold = 2;
                options.OldestPendingAgeThreshold = TimeSpan.FromMinutes(5);
            });
        });

        var report = await CheckAsync(provider);

        Assert.That(report.Entries[AshlarHealthCheckNames.EmailOutbox].Status, Is.EqualTo(HealthStatus.Degraded));
    }

    [Test]
    public async Task EmailOutboxThresholdsShouldOnlyBreachWhenValuesExceedConfiguredLimits()
    {
        using var provider = BuildProvider(services =>
        {
            services.AddSingleton<IEmailOutboxDiagnostics>(_ => new EmailOutboxDiagnostics(EmailOutboxResult(
                pendingCount: 5,
                expiredLockCount: 1,
                failedCount: 2,
                oldestPendingAt: Now.AddMinutes(-5))));
            services.AddHealthChecks().AddAshlarEmailOutbox(options =>
            {
                options.PendingCountThreshold = 5;
                options.ExpiredLockCountThreshold = 1;
                options.FailedCountThreshold = 2;
                options.OldestPendingAgeThreshold = TimeSpan.FromMinutes(5);
            });
        });

        var report = await CheckAsync(provider);

        Assert.That(report.Entries[AshlarHealthCheckNames.EmailOutbox].Status, Is.EqualTo(HealthStatus.Healthy));
    }

    [Test]
    public async Task SecurityEventWebhookOutboxThresholdBreachesShouldDegradeHealth()
    {
        using var provider = BuildProvider(services =>
        {
            services.AddSingleton<ISecurityEventWebhookOutboxDiagnostics>(_ => new SecurityEventWebhookOutboxDiagnostics(SecurityEventWebhookOutboxResult(
                pendingCount: 10,
                expiredLockCount: 2,
                failedCount: 3,
                oldestPendingAt: Now.AddMinutes(-10))));
            services.AddHealthChecks().AddAshlarSecurityEventWebhookOutbox(options =>
            {
                options.PendingCountThreshold = 5;
                options.ExpiredLockCountThreshold = 1;
                options.FailedCountThreshold = 2;
                options.OldestPendingAgeThreshold = TimeSpan.FromMinutes(5);
            });
        });

        var report = await CheckAsync(provider);

        Assert.That(report.Entries[AshlarHealthCheckNames.SecurityEventWebhookOutbox].Status, Is.EqualTo(HealthStatus.Degraded));
    }

    [Test]
    public async Task SecurityEventWebhookOutboxThresholdsShouldOnlyBreachWhenValuesExceedConfiguredLimits()
    {
        using var provider = BuildProvider(services =>
        {
            services.AddSingleton<ISecurityEventWebhookOutboxDiagnostics>(_ => new SecurityEventWebhookOutboxDiagnostics(SecurityEventWebhookOutboxResult(
                pendingCount: 5,
                expiredLockCount: 1,
                failedCount: 2,
                oldestPendingAt: Now.AddMinutes(-5))));
            services.AddHealthChecks().AddAshlarSecurityEventWebhookOutbox(options =>
            {
                options.PendingCountThreshold = 5;
                options.ExpiredLockCountThreshold = 1;
                options.FailedCountThreshold = 2;
                options.OldestPendingAgeThreshold = TimeSpan.FromMinutes(5);
            });
        });

        var report = await CheckAsync(provider);

        Assert.That(report.Entries[AshlarHealthCheckNames.SecurityEventWebhookOutbox].Status, Is.EqualTo(HealthStatus.Healthy));
    }

    [Test]
    public void SecurityEventWebhookOutboxThresholdOptionsShouldRejectInvalidThresholds()
    {
        using var provider = BuildProvider(services =>
        {
            services.AddHealthChecks().AddAshlarSecurityEventWebhookOutbox(options =>
            {
                options.PendingCountThreshold = -1;
                options.ExpiredLockCountThreshold = -1;
                options.FailedCountThreshold = -1;
                options.OldestPendingAgeThreshold = TimeSpan.Zero;
            });
        });

        Assert.Throws<OptionsValidationException>(() => _ = provider.GetRequiredService<IOptions<AshlarSecurityEventWebhookOutboxHealthCheckOptions>>().Value);
    }

    [Test]
    public void SecurityEventWebhookOutboxThresholdOptionsShouldValidateOnStart()
    {
        using var provider = BuildProvider(services =>
        {
            services.AddHealthChecks().AddAshlarSecurityEventWebhookOutbox(options =>
            {
                options.PendingCountThreshold = -1;
            });
        });

        var exception = Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IStartupValidator>().Validate());
        Assert.That(exception?.OptionsType, Is.EqualTo(typeof(AshlarSecurityEventWebhookOutboxHealthCheckOptions)));
    }

    [Test]
    public void SecurityEventWebhookOutboxThresholdOptionsShouldAcceptZeroCountThresholdsAndPositiveAgeThreshold()
    {
        using var provider = BuildProvider(services =>
        {
            services.AddHealthChecks().AddAshlarSecurityEventWebhookOutbox(options =>
            {
                options.PendingCountThreshold = 0;
                options.ExpiredLockCountThreshold = 0;
                options.FailedCountThreshold = 0;
                options.OldestPendingAgeThreshold = TimeSpan.FromTicks(1);
            });
        });

        var options = provider.GetRequiredService<IOptions<AshlarSecurityEventWebhookOutboxHealthCheckOptions>>().Value;

        using (Assert.EnterMultipleScope())
        {
            Assert.That(options.PendingCountThreshold, Is.Zero);
            Assert.That(options.ExpiredLockCountThreshold, Is.Zero);
            Assert.That(options.FailedCountThreshold, Is.Zero);
            Assert.That(options.OldestPendingAgeThreshold, Is.EqualTo(TimeSpan.FromTicks(1)));
        }
    }

    [Test]
    public void EmailOutboxThresholdOptionsShouldRejectInvalidThresholds()
    {
        using var provider = BuildProvider(services =>
        {
            services.AddHealthChecks().AddAshlarEmailOutbox(options =>
            {
                options.PendingCountThreshold = -1;
                options.ExpiredLockCountThreshold = -1;
                options.FailedCountThreshold = -1;
                options.OldestPendingAgeThreshold = TimeSpan.Zero;
            });
        });

        Assert.Throws<OptionsValidationException>(() => _ = provider.GetRequiredService<IOptions<AshlarEmailOutboxHealthCheckOptions>>().Value);
    }

    [Test]
    public void EmailOutboxThresholdOptionsShouldValidateOnStart()
    {
        using var provider = BuildProvider(services =>
        {
            services.AddHealthChecks().AddAshlarEmailOutbox(options =>
            {
                options.PendingCountThreshold = -1;
            });
        });

        var exception = Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IStartupValidator>().Validate());
        Assert.That(exception?.OptionsType, Is.EqualTo(typeof(AshlarEmailOutboxHealthCheckOptions)));
    }

    [Test]
    public void EmailOutboxThresholdOptionsShouldAcceptZeroCountThresholdsAndPositiveAgeThreshold()
    {
        using var provider = BuildProvider(services =>
        {
            services.AddHealthChecks().AddAshlarEmailOutbox(options =>
            {
                options.PendingCountThreshold = 0;
                options.ExpiredLockCountThreshold = 0;
                options.FailedCountThreshold = 0;
                options.OldestPendingAgeThreshold = TimeSpan.FromTicks(1);
            });
        });

        var options = provider.GetRequiredService<IOptions<AshlarEmailOutboxHealthCheckOptions>>().Value;

        using (Assert.EnterMultipleScope())
        {
            Assert.That(options.PendingCountThreshold, Is.Zero);
            Assert.That(options.ExpiredLockCountThreshold, Is.Zero);
            Assert.That(options.FailedCountThreshold, Is.Zero);
            Assert.That(options.OldestPendingAgeThreshold, Is.EqualTo(TimeSpan.FromTicks(1)));
        }
    }

    [Test]
    public async Task EmailOutboxFallbackStatusesShouldMapToUnhealthy()
    {
        using var provider = BuildProvider(services =>
        {
            services.AddSingleton<IEmailOutboxDiagnostics>(_ => new EmailOutboxDiagnostics(EmailOutboxResult((AshlarDiagnosticStatus)99)));
            services.AddHealthChecks().AddAshlarEmailOutbox();
        });

        var report = await CheckAsync(provider);

        Assert.That(report.Entries[AshlarHealthCheckNames.EmailOutbox].Status, Is.EqualTo(HealthStatus.Unhealthy));
    }

    [Test]
    public async Task SecurityEventWebhookOutboxFallbackStatusesShouldMapToUnhealthy()
    {
        using var provider = BuildProvider(services =>
        {
            services.AddSingleton<ISecurityEventWebhookOutboxDiagnostics>(_ => new SecurityEventWebhookOutboxDiagnostics(SecurityEventWebhookOutboxResult((AshlarDiagnosticStatus)99)));
            services.AddHealthChecks().AddAshlarSecurityEventWebhookOutbox();
        });

        var report = await CheckAsync(provider);

        Assert.That(report.Entries[AshlarHealthCheckNames.SecurityEventWebhookOutbox].Status, Is.EqualTo(HealthStatus.Unhealthy));
    }

    [Test]
    public async Task RemainingStatusBranchesShouldMapPredictably()
    {
        using var provider = BuildProvider(services =>
        {
            services.AddSingleton<IEmailOutboxDiagnostics>(_ => new EmailOutboxDiagnostics(EmailOutboxResult(AshlarDiagnosticStatus.Unhealthy)));
            services.AddSingleton<ISecurityEventWebhookOutboxDiagnostics>(_ => new SecurityEventWebhookOutboxDiagnostics(SecurityEventWebhookOutboxResult(AshlarDiagnosticStatus.Unhealthy)));
            services.AddSingleton<IAshlarSchemaDiagnostics>(_ => new SchemaDiagnostics(SchemaResult(AshlarDiagnosticStatus.Unhealthy, AshlarSchemaStatus.Current)));
            services.AddSingleton<IAshlarCleanupDiagnostics>(_ => new CleanupDiagnostics(CleanupResult(AshlarDiagnosticStatus.Unhealthy)));
            services.AddSingleton<IAuthenticationRateLimiterDiagnostics>(_ => new RateLimiterDiagnostics(RateLimiterResult(AshlarDiagnosticStatus.Degraded)));
            services.AddHealthChecks()
                .AddAshlarEmailOutbox()
                .AddAshlarSecurityEventWebhookOutbox()
                .AddAshlarSchema()
                .AddAshlarCleanup()
                .AddAshlarRateLimiter();
        });

        var report = await CheckAsync(provider);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(report.Entries[AshlarHealthCheckNames.Schema].Status, Is.EqualTo(HealthStatus.Unhealthy));
            Assert.That(report.Entries[AshlarHealthCheckNames.EmailOutbox].Status, Is.EqualTo(HealthStatus.Unhealthy));
            Assert.That(report.Entries[AshlarHealthCheckNames.SecurityEventWebhookOutbox].Status, Is.EqualTo(HealthStatus.Unhealthy));
            Assert.That(report.Entries[AshlarHealthCheckNames.Cleanup].Status, Is.EqualTo(HealthStatus.Unhealthy));
            Assert.That(report.Entries[AshlarHealthCheckNames.RateLimiter].Status, Is.EqualTo(HealthStatus.Degraded));
        }
    }

    [Test]
    public async Task UnknownEnumValuesShouldUseFallbackMappings()
    {
        using var provider = BuildProvider(services =>
        {
            services.AddSingleton<IAshlarSchemaDiagnostics>(_ => new SchemaDiagnostics(SchemaResult((AshlarDiagnosticStatus)99, AshlarSchemaStatus.Current)));
            services.AddSingleton<IAshlarCleanupDiagnostics>(_ => new CleanupDiagnostics(CleanupResult((AshlarDiagnosticStatus)99)));
            services.AddSingleton<IAuthenticationRateLimiterDiagnostics>(_ => new RateLimiterDiagnostics(RateLimiterResult((AshlarDiagnosticStatus)99)));
            services.AddHealthChecks()
                .AddAshlarSchema()
                .AddAshlarCleanup()
                .AddAshlarRateLimiter();
        });

        var report = await CheckAsync(provider);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(report.Entries[AshlarHealthCheckNames.Schema].Status, Is.EqualTo(HealthStatus.Degraded));
            Assert.That(report.Entries[AshlarHealthCheckNames.Cleanup].Status, Is.EqualTo(HealthStatus.Degraded));
            Assert.That(report.Entries[AshlarHealthCheckNames.RateLimiter].Status, Is.EqualTo(HealthStatus.Unhealthy));
        }
    }

    [Test]
    public async Task CleanupFallbackGuardsShouldRespectConfigurationAndOptionsValidity()
    {
        using var notConfiguredProvider = BuildProvider(services =>
        {
            services.AddSingleton<IAshlarCleanupDiagnostics>(_ => new CleanupDiagnostics(CleanupResult((AshlarDiagnosticStatus)99, configured: false, optionsValid: true)));
            services.AddHealthChecks().AddAshlarCleanup();
        });
        using var invalidOptionsProvider = BuildProvider(services =>
        {
            services.AddSingleton<IAshlarCleanupDiagnostics>(_ => new CleanupDiagnostics(CleanupResult((AshlarDiagnosticStatus)99, configured: true, optionsValid: false)));
            services.AddHealthChecks().AddAshlarCleanup();
        });

        var notConfiguredReport = await CheckAsync(notConfiguredProvider);
        var invalidOptionsReport = await CheckAsync(invalidOptionsProvider);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(notConfiguredReport.Entries[AshlarHealthCheckNames.Cleanup].Status, Is.EqualTo(HealthStatus.Degraded));
            Assert.That(invalidOptionsReport.Entries[AshlarHealthCheckNames.Cleanup].Status, Is.EqualTo(HealthStatus.Unhealthy));
        }
    }

    [Test]
    public async Task NonDistributedRateLimiterShouldRemainHealthy()
    {
        using var provider = BuildProvider(services =>
        {
            services.AddSingleton<IAuthenticationRateLimiterDiagnostics>(_ => new RateLimiterDiagnostics(RateLimiterResult(distributed: false, persistent: true)));
            services.AddHealthChecks().AddAshlarRateLimiter();
        });

        var report = await CheckAsync(provider);

        Assert.That(report.Entries[AshlarHealthCheckNames.RateLimiter].Status, Is.EqualTo(HealthStatus.Healthy));
    }

    [Test]
    public async Task HealthCheckDataShouldContainOnlyExpectedSafeScalarValues()
    {
        using var provider = BuildProvider(services =>
        {
            services.AddSingleton<IAshlarSchemaDiagnostics>(_ => new SchemaDiagnostics(SchemaResult()));
            services.AddHealthChecks().AddAshlarSchema();
        });

        var report = await CheckAsync(provider);
        var data = report.Entries[AshlarHealthCheckNames.Schema].Data;

        using (Assert.EnterMultipleScope())
        {
            Assert.That(data.Keys, Does.Contain("diagnostic_status"));
            Assert.That(data.Keys, Does.Contain("provider_name"));
            Assert.That(data.Keys, Does.Contain("checked_at"));
            Assert.That(data.Keys, Does.Contain("schema_status"));
            Assert.That(data.Keys, Does.Contain("applied_migration_count"));
            Assert.That(data.Keys, Does.Contain("expected_migration_count"));
            Assert.That(data.Keys, Does.Contain("missing_migration_count"));
            Assert.That(data.Keys, Does.Not.Contain("latest_applied_migration_name"));
            Assert.That(data.Keys, Does.Not.Contain("latest_expected_migration_name"));
            Assert.That(data.Keys, Does.Not.Contain("minimum_provider_version"));
            Assert.That(data.Keys, Does.Not.Contain("provider_version"));
            Assert.That(data.Keys, Does.Not.Contain("connection_string"));
            Assert.That(data.Keys, Does.Not.Contain("raw_sql"));
            Assert.That(data.Keys, Does.Not.Contain("lock_owner"));
            Assert.That(data.Keys, Does.Not.Contain("row_id"));
            Assert.That(data.Keys, Does.Not.Contain("token"));
            Assert.That(data.Keys, Does.Not.Contain("url"));
            Assert.That(data.Keys, Does.Not.Contain("secret"));
        }

        Assert.That(data.Values, Is.All.Matches<object>(value => value is string or int or long or bool or double or DateTimeOffset));
    }

    [Test]
    public async Task SecurityEventWebhookOutboxHealthCheckDataShouldContainOnlySafeDiagnosticFields()
    {
        using var provider = BuildProvider(services =>
        {
            services.AddSingleton<ISecurityEventWebhookOutboxDiagnostics>(_ => new SecurityEventWebhookOutboxDiagnostics(SecurityEventWebhookOutboxResult(
                pendingCount: 3,
                scheduledCount: 2,
                lockedCount: 1,
                expiredLockCount: 4,
                failedCount: 5,
                oldestPendingAt: Now.AddMinutes(-2),
                oldestFailedAt: Now.AddHours(-1))));
            services.AddHealthChecks().AddAshlarSecurityEventWebhookOutbox();
        });

        var report = await CheckAsync(provider);
        var data = report.Entries[AshlarHealthCheckNames.SecurityEventWebhookOutbox].Data;

        using (Assert.EnterMultipleScope())
        {
            Assert.That(data.Keys, Does.Contain("diagnostic_status"));
            Assert.That(data.Keys, Does.Contain("provider_name"));
            Assert.That(data.Keys, Does.Contain("pending_count"));
            Assert.That(data.Keys, Does.Contain("scheduled_count"));
            Assert.That(data.Keys, Does.Contain("locked_count"));
            Assert.That(data.Keys, Does.Contain("expired_lock_count"));
            Assert.That(data.Keys, Does.Contain("failed_count"));
            Assert.That(data.Keys, Does.Contain("oldest_pending_age_seconds"));
            Assert.That(data.Keys, Does.Not.Contain("endpoint_secret"));
            Assert.That(data.Keys, Does.Not.Contain("request_body"));
            Assert.That(data.Keys, Does.Not.Contain("headers"));
            Assert.That(data.Keys, Does.Not.Contain("lock_owner"));
            Assert.That(data.Keys, Does.Not.Contain("last_error"));
            Assert.That(data.Keys, Does.Not.Contain("event_payload"));
        }

        Assert.That(data.Values, Is.All.Matches<object>(value => value is string or int or long or bool or double or DateTimeOffset));
    }

    [Test]
    public async Task HealthCheckDataShouldSkipNullOptionalValues()
    {
        using var provider = BuildProvider(services =>
        {
            services.AddSingleton<IEmailOutboxDiagnostics>(_ => new EmailOutboxDiagnostics(new EmailOutboxDiagnosticResult(
                AshlarDiagnosticStatus.NotSupported,
                "Test",
                null,
                Now,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null)));
            services.AddSingleton<ISecurityEventWebhookOutboxDiagnostics>(_ => new SecurityEventWebhookOutboxDiagnostics(new SecurityEventWebhookOutboxDiagnosticResult(
                AshlarDiagnosticStatus.NotSupported,
                "Test",
                null,
                Now,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null)));
            services.AddSingleton<IAshlarCleanupDiagnostics>(_ => new CleanupDiagnostics(new AshlarCleanupDiagnosticResult(
                AshlarDiagnosticStatus.NotSupported,
                "Test",
                null,
                Now,
                false,
                false,
                null,
                null,
                null,
                null,
                null)));
            services.AddSingleton<IAuthenticationRateLimiterDiagnostics>(_ => new RateLimiterDiagnostics(new AuthenticationRateLimiterDiagnosticResult(
                AshlarDiagnosticStatus.NotSupported,
                "Test",
                null,
                Now,
                false,
                false,
                false,
                null,
                null,
                null,
                null,
                null,
                null)));
            services.AddHealthChecks()
                .AddAshlarEmailOutbox()
                .AddAshlarSecurityEventWebhookOutbox()
                .AddAshlarCleanup()
                .AddAshlarRateLimiter();
        });

        var report = await CheckAsync(provider);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(report.Entries[AshlarHealthCheckNames.EmailOutbox].Data.Keys, Does.Not.Contain("oldest_pending_age_seconds"));
            Assert.That(report.Entries[AshlarHealthCheckNames.EmailOutbox].Data.Keys, Does.Not.Contain("polling_interval_seconds"));
            Assert.That(report.Entries[AshlarHealthCheckNames.SecurityEventWebhookOutbox].Data.Keys, Does.Not.Contain("oldest_pending_age_seconds"));
            Assert.That(report.Entries[AshlarHealthCheckNames.SecurityEventWebhookOutbox].Data.Keys, Does.Not.Contain("polling_interval_seconds"));
            Assert.That(report.Entries[AshlarHealthCheckNames.Cleanup].Data.Keys, Does.Not.Contain("cleanup_interval_seconds"));
            Assert.That(report.Entries[AshlarHealthCheckNames.RateLimiter].Data.Keys, Does.Not.Contain("cleanup_interval_seconds"));
        }
    }

    [Test]
    public void HealthCheckConstructorsShouldValidateRequiredDependencies()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => new AshlarSchemaHealthCheck(null!, Options.Create(new AshlarSchemaHealthCheckOptions())));
            Assert.Throws<ArgumentNullException>(() => new AshlarSchemaHealthCheck([new SchemaDiagnostics(SchemaResult())], null!));
            Assert.Throws<ArgumentNullException>(() => new AshlarSchemaHealthCheck([new SchemaDiagnostics(SchemaResult())], Options.Create<AshlarSchemaHealthCheckOptions>(null!)));
            Assert.Throws<ArgumentNullException>(() => new AshlarEmailOutboxHealthCheck(null!, Options.Create(new AshlarEmailOutboxHealthCheckOptions())));
            Assert.Throws<ArgumentNullException>(() => new AshlarEmailOutboxHealthCheck([new EmailOutboxDiagnostics(EmailOutboxResult())], null!));
            Assert.Throws<ArgumentNullException>(() => new AshlarEmailOutboxHealthCheck([new EmailOutboxDiagnostics(EmailOutboxResult())], Options.Create<AshlarEmailOutboxHealthCheckOptions>(null!)));
            Assert.Throws<ArgumentNullException>(() => new AshlarSecurityEventWebhookOutboxHealthCheck(null!, Options.Create(new AshlarSecurityEventWebhookOutboxHealthCheckOptions())));
            Assert.Throws<ArgumentNullException>(() => new AshlarSecurityEventWebhookOutboxHealthCheck([new SecurityEventWebhookOutboxDiagnostics(SecurityEventWebhookOutboxResult())], null!));
            Assert.Throws<ArgumentNullException>(() => new AshlarSecurityEventWebhookOutboxHealthCheck([new SecurityEventWebhookOutboxDiagnostics(SecurityEventWebhookOutboxResult())], Options.Create<AshlarSecurityEventWebhookOutboxHealthCheckOptions>(null!)));
            Assert.Throws<ArgumentNullException>(() => new AshlarCleanupHealthCheck(null!, Options.Create(new AshlarCleanupHealthCheckOptions())));
            Assert.Throws<ArgumentNullException>(() => new AshlarCleanupHealthCheck([new CleanupDiagnostics(CleanupResult())], null!));
            Assert.Throws<ArgumentNullException>(() => new AshlarCleanupHealthCheck([new CleanupDiagnostics(CleanupResult())], Options.Create<AshlarCleanupHealthCheckOptions>(null!)));
            Assert.Throws<ArgumentNullException>(() => new AshlarRateLimiterHealthCheck(null!, Options.Create(new AshlarRateLimiterHealthCheckOptions())));
            Assert.Throws<ArgumentNullException>(() => new AshlarRateLimiterHealthCheck([new RateLimiterDiagnostics(RateLimiterResult())], null!));
            Assert.Throws<ArgumentNullException>(() => new AshlarRateLimiterHealthCheck([new RateLimiterDiagnostics(RateLimiterResult())], Options.Create<AshlarRateLimiterHealthCheckOptions>(null!)));
        }
    }

    [Test]
    public async Task AddAshlarHealthChecksShouldReportMissingOptionalDiagnosticsAsDegraded()
    {
        using var provider = BuildProvider(services =>
        {
            services.AddSingleton<IAshlarSchemaDiagnostics>(_ => new SchemaDiagnostics(SchemaResult()));
            services.AddHealthChecks().AddAshlarHealthChecks();
        });

        var report = await CheckAsync(provider);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(report.Entries.Keys, Contains.Item(AshlarHealthCheckNames.Schema));
            Assert.That(report.Entries[AshlarHealthCheckNames.Schema].Status, Is.EqualTo(HealthStatus.Healthy));
            Assert.That(report.Entries[AshlarHealthCheckNames.EmailOutbox].Status, Is.EqualTo(HealthStatus.Degraded));
            Assert.That(report.Entries[AshlarHealthCheckNames.SecurityEventWebhookOutbox].Status, Is.EqualTo(HealthStatus.Degraded));
            Assert.That(report.Entries[AshlarHealthCheckNames.Cleanup].Status, Is.EqualTo(HealthStatus.Degraded));
            Assert.That(report.Entries[AshlarHealthCheckNames.RateLimiter].Status, Is.EqualTo(HealthStatus.Degraded));
        }
    }

    [Test]
    public async Task AddAshlarHealthChecksShouldAllowAllDiagnosticsToBeMissing()
    {
        using var provider = BuildProvider(services => services.AddHealthChecks().AddAshlarHealthChecks());

        var report = await CheckAsync(provider);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(report.Entries.Keys, Is.EquivalentTo(new[]
            {
                AshlarHealthCheckNames.Schema,
                AshlarHealthCheckNames.EmailOutbox,
                AshlarHealthCheckNames.SecurityEventWebhookOutbox,
                AshlarHealthCheckNames.Cleanup,
                AshlarHealthCheckNames.RateLimiter
            }));
            Assert.That(report.Entries.Values.Select(entry => entry.Status), Is.All.EqualTo(HealthStatus.Degraded));
        }
    }

    [Test]
    public void AddAshlarHealthChecksBuildsWithStrictValidationFromDiagnosticsAbstractions()
    {
        using var provider = ServiceProviderValidation.BuildValidatedServiceProvider(services =>
        {
            services.AddLogging();
            services.AddSingleton<IAshlarSchemaDiagnostics>(_ => new SchemaDiagnostics(SchemaResult()));
            services.AddSingleton<IEmailOutboxDiagnostics>(_ => new EmailOutboxDiagnostics(EmailOutboxResult()));
            services.AddSingleton<ISecurityEventWebhookOutboxDiagnostics>(_ => new SecurityEventWebhookOutboxDiagnostics(SecurityEventWebhookOutboxResult()));
            services.AddSingleton<IAshlarCleanupDiagnostics>(_ => new CleanupDiagnostics(CleanupResult()));
            services.AddSingleton<IAuthenticationRateLimiterDiagnostics>(_ => new RateLimiterDiagnostics(RateLimiterResult()));
            services.AddHealthChecks().AddAshlarHealthChecks();
        }, typeof(HealthCheckService));

        Assert.That(provider.GetRequiredService<HealthCheckService>(), Is.Not.Null);
    }

    [Test]
    public async Task AddAshlarHealthChecksShouldNotDependOnDiagnosticsRegistrationOrder()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddHealthChecks().AddAshlarHealthChecks();
        services.AddSingleton<IAshlarSchemaDiagnostics>(_ => new SchemaDiagnostics(SchemaResult()));

        using var provider = services.BuildServiceProvider();

        var report = await CheckAsync(provider);

        Assert.That(report.Entries[AshlarHealthCheckNames.Schema].Status, Is.EqualTo(HealthStatus.Healthy));
    }

    [Test]
    public async Task MissingDiagnosticsShouldUseConfiguredNotSupportedStatus()
    {
        using var provider = BuildProvider(services =>
        {
            services.AddHealthChecks().AddAshlarHealthChecks(
                configureSchema: options => options.NotSupportedStatus = HealthStatus.Healthy,
                configureEmailOutbox: options => options.NotSupportedStatus = HealthStatus.Healthy,
                configureSecurityEventWebhookOutbox: options => options.NotSupportedStatus = HealthStatus.Healthy,
                configureCleanup: options => options.NotSupportedStatus = HealthStatus.Healthy,
                configureRateLimiter: options => options.NotSupportedStatus = HealthStatus.Healthy);
        });

        var report = await CheckAsync(provider);

        Assert.That(report.Entries.Values.Select(entry => entry.Status), Is.All.EqualTo(HealthStatus.Healthy));
    }

    [Test]
    public async Task RegistrationExtensionsShouldAcceptTags()
    {
        using var provider = BuildProvider(services =>
        {
            services.AddSingleton<IAshlarSchemaDiagnostics>(_ => new SchemaDiagnostics(SchemaResult()));
            services.AddSingleton<IEmailOutboxDiagnostics>(_ => new EmailOutboxDiagnostics(EmailOutboxResult()));
            services.AddSingleton<ISecurityEventWebhookOutboxDiagnostics>(_ => new SecurityEventWebhookOutboxDiagnostics(SecurityEventWebhookOutboxResult()));
            services.AddSingleton<IAshlarCleanupDiagnostics>(_ => new CleanupDiagnostics(CleanupResult()));
            services.AddSingleton<IAuthenticationRateLimiterDiagnostics>(_ => new RateLimiterDiagnostics(RateLimiterResult()));
            services.AddHealthChecks()
                .AddAshlarSchema(tags: ["ashlar"])
                .AddAshlarEmailOutbox(tags: ["ashlar"])
                .AddAshlarSecurityEventWebhookOutbox(tags: ["ashlar"])
                .AddAshlarCleanup(tags: ["ashlar"])
                .AddAshlarRateLimiter(tags: ["ashlar"]);
        });

        var report = await CheckAsync(provider);

        Assert.That(report.Entries, Has.Count.EqualTo(5));
    }

    [Test]
    public void RegistrationExtensionsShouldValidateArguments()
    {
        var services = new ServiceCollection();
        var builder = services.AddHealthChecks();

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => AshlarHealthChecksBuilderExtensions.AddAshlarHealthChecks(null!));
            Assert.Throws<ArgumentNullException>(() => AshlarHealthChecksBuilderExtensions.AddAshlarSchema(null!));
            Assert.Throws<ArgumentException>(() => builder.AddAshlarSchema(name: ""));
            Assert.Throws<ArgumentNullException>(() => AshlarHealthChecksBuilderExtensions.AddAshlarEmailOutbox(null!));
            Assert.Throws<ArgumentException>(() => builder.AddAshlarEmailOutbox(name: ""));
            Assert.Throws<ArgumentNullException>(() => AshlarHealthChecksBuilderExtensions.AddAshlarSecurityEventWebhookOutbox(null!));
            Assert.Throws<ArgumentException>(() => builder.AddAshlarSecurityEventWebhookOutbox(name: ""));
            Assert.Throws<ArgumentNullException>(() => AshlarHealthChecksBuilderExtensions.AddAshlarCleanup(null!));
            Assert.Throws<ArgumentException>(() => builder.AddAshlarCleanup(name: ""));
            Assert.Throws<ArgumentNullException>(() => AshlarHealthChecksBuilderExtensions.AddAshlarRateLimiter(null!));
            Assert.Throws<ArgumentException>(() => builder.AddAshlarRateLimiter(name: ""));
        }
    }

    private static ServiceProvider BuildProvider(Action<IServiceCollection> configure)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        configure(services);
        return services.BuildServiceProvider();
    }

    private static Task<HealthReport> CheckAsync(IServiceProvider provider)
    {
        return provider.GetRequiredService<HealthCheckService>().CheckHealthAsync();
    }

    private static AshlarSchemaDiagnosticResult SchemaResult(
        AshlarDiagnosticStatus status = AshlarDiagnosticStatus.Healthy,
        AshlarSchemaStatus schemaStatus = AshlarSchemaStatus.Current)
    {
        return new AshlarSchemaDiagnosticResult(
            status,
            "Test",
            null,
            Now,
            schemaStatus,
            1,
            1,
            0,
            "0001_Initialize",
            "0001_Initialize",
            "1.0",
            "1.0");
    }

    private static EmailOutboxDiagnosticResult EmailOutboxResult(
        AshlarDiagnosticStatus status = AshlarDiagnosticStatus.Healthy,
        long pendingCount = 0,
        long expiredLockCount = 0,
        long failedCount = 0,
        DateTimeOffset? oldestPendingAt = null)
    {
        return new EmailOutboxDiagnosticResult(
            status,
            "Test",
            null,
            Now,
            pendingCount,
            0,
            0,
            expiredLockCount,
            failedCount,
            0,
            0,
            0,
            0,
            oldestPendingAt,
            null,
            3,
            TimeSpan.FromSeconds(30),
            10);
    }

    private static SecurityEventWebhookOutboxDiagnosticResult SecurityEventWebhookOutboxResult(
        AshlarDiagnosticStatus status = AshlarDiagnosticStatus.Healthy,
        long pendingCount = 0,
        long scheduledCount = 0,
        long lockedCount = 0,
        long expiredLockCount = 0,
        long failedCount = 0,
        DateTimeOffset? oldestPendingAt = null,
        DateTimeOffset? oldestFailedAt = null)
    {
        return new SecurityEventWebhookOutboxDiagnosticResult(
            status,
            "Test",
            null,
            Now,
            pendingCount,
            scheduledCount,
            lockedCount,
            expiredLockCount,
            failedCount,
            oldestPendingAt,
            oldestFailedAt,
            3,
            TimeSpan.FromSeconds(30),
            10);
    }

    private static AshlarCleanupDiagnosticResult CleanupResult(
        AshlarDiagnosticStatus status = AshlarDiagnosticStatus.Healthy,
        bool configured = true,
        bool optionsValid = true)
    {
        return new AshlarCleanupDiagnosticResult(
            status,
            "Test",
            null,
            Now,
            configured,
            optionsValid,
            TimeSpan.FromMinutes(5),
            100,
            10,
            0,
            4);
    }

    private static AuthenticationRateLimiterDiagnosticResult RateLimiterResult(
        AshlarDiagnosticStatus status = AshlarDiagnosticStatus.Healthy,
        bool distributed = true,
        bool persistent = true)
    {
        return new AuthenticationRateLimiterDiagnosticResult(
            status,
            "Test",
            null,
            Now,
            true,
            distributed,
            persistent,
            0,
            1,
            0,
            true,
            TimeSpan.FromMinutes(5),
            100);
    }

    private sealed class SchemaDiagnostics(AshlarSchemaDiagnosticResult result) : IAshlarSchemaDiagnostics
    {
        public Task<AshlarSchemaDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
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
}
