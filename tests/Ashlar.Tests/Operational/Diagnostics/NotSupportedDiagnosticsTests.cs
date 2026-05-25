using Ashlar.Operational.Diagnostics;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Tests.Operational.Diagnostics;

internal sealed class NotSupportedDiagnosticsTests
{
    private static readonly DateTimeOffset CheckedAt = new(2026, 5, 20, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task NotSupportedAshlarSchemaDiagnosticsReturnsNotSupportedResult()
    {
        var diagnostics = new NotSupportedAshlarSchemaDiagnostics("None", new FakeTimeProvider(CheckedAt));

        var result = await diagnostics.CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.NotSupported));
            Assert.That(result.ProviderName, Is.EqualTo("None"));
            Assert.That(result.CheckedAt, Is.EqualTo(CheckedAt));
            Assert.That(result.SchemaStatus, Is.EqualTo(AshlarSchemaStatus.Unknown));
            Assert.That(result.Reason, Is.Null);
        }
    }

    [Test]
    public async Task NotSupportedEmailOutboxDiagnosticsReturnsNotSupportedResult()
    {
        var diagnostics = new NotSupportedEmailOutboxDiagnostics("None", new FakeTimeProvider(CheckedAt));

        var result = await diagnostics.CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.NotSupported));
            Assert.That(result.ProviderName, Is.EqualTo("None"));
            Assert.That(result.CheckedAt, Is.EqualTo(CheckedAt));
            Assert.That(result.PendingCount, Is.Null);
            Assert.That(result.Reason, Is.Null);
        }
    }

    [Test]
    public async Task NotSupportedSecurityEventWebhookOutboxDiagnosticsReturnsNotSupportedResult()
    {
        var diagnostics = new NotSupportedSecurityEventWebhookOutboxDiagnostics("None", new FakeTimeProvider(CheckedAt));

        var result = await diagnostics.CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.NotSupported));
            Assert.That(result.ProviderName, Is.EqualTo("None"));
            Assert.That(result.CheckedAt, Is.EqualTo(CheckedAt));
            Assert.That(result.PendingCount, Is.Null);
            Assert.That(result.Reason, Is.Null);
        }
    }

    [Test]
    public async Task NotSupportedAshlarCleanupDiagnosticsReturnsNotSupportedResult()
    {
        var diagnostics = new NotSupportedAshlarCleanupDiagnostics("None", new FakeTimeProvider(CheckedAt));

        var result = await diagnostics.CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.NotSupported));
            Assert.That(result.ProviderName, Is.EqualTo("None"));
            Assert.That(result.CheckedAt, Is.EqualTo(CheckedAt));
            Assert.That(result.Configured, Is.False);
            Assert.That(result.OptionsValid, Is.False);
            Assert.That(result.Reason, Is.Null);
        }
    }

    [Test]
    public async Task NotSupportedAuthenticationRateLimiterDiagnosticsReturnsNotSupportedResult()
    {
        var diagnostics = new NotSupportedAuthenticationRateLimiterDiagnostics("None", new FakeTimeProvider(CheckedAt));

        var result = await diagnostics.CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.NotSupported));
            Assert.That(result.ProviderName, Is.EqualTo("None"));
            Assert.That(result.CheckedAt, Is.EqualTo(CheckedAt));
            Assert.That(result.Configured, Is.False);
            Assert.That(result.Distributed, Is.False);
            Assert.That(result.Persistent, Is.False);
            Assert.That(result.Reason, Is.Null);
        }
    }
}
