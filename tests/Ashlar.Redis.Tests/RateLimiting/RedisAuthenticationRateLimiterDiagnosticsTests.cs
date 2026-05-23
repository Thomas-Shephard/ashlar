using Ashlar.Operational.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Redis.Tests.RateLimiting;

internal sealed class RedisAuthenticationRateLimiterDiagnosticsTests : RedisTestBase
{
    private static readonly DateTimeOffset CheckedAt = new(2026, 5, 22, 15, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task CheckAsyncReturnsHealthyCapabilityData()
    {
        var services = new ServiceCollection();
        services.AddAshlarRedisRateLimiting(GetConnection(), options =>
        {
            options.KeyPrefix = $"ashlar:test:{Guid.NewGuid():N}";
            options.Persistent = true;
        });
        services.AddSingleton<TimeProvider>(new FakeTimeProvider(CheckedAt));
        await using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAuthenticationRateLimiterDiagnostics>().CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Healthy));
            Assert.That(result.ProviderName, Is.EqualTo("Redis"));
            Assert.That(result.CheckedAt, Is.EqualTo(CheckedAt));
            Assert.That(result.Configured, Is.True);
            Assert.That(result.Distributed, Is.True);
            Assert.That(result.Persistent, Is.True);
            Assert.That(result.CleanupConfigured, Is.False);
            Assert.That(result.ActiveKeyCount, Is.Null);
            Assert.That(result.ExpiredRowCount, Is.Null);
            Assert.That(result.BlockedKeyCount, Is.Null);
        }
    }
}
