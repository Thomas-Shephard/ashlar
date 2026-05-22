using Ashlar.Identity.RateLimiting;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Operational.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Tests.Operational.Diagnostics;

internal sealed class InMemoryAuthenticationRateLimiterDiagnosticsTests
{
    private static readonly DateTimeOffset CheckedAt = new(2026, 5, 21, 10, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task CheckAsyncReturnsExpectedProviderAndCapabilityFields()
    {
        var timeProvider = new FakeTimeProvider(CheckedAt);
        var limiter = new InMemoryAuthenticationRateLimiter(timeProvider);
        var diagnostics = new InMemoryAuthenticationRateLimiterDiagnostics(limiter, timeProvider);

        var result = await diagnostics.CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Healthy));
            Assert.That(result.ProviderName, Is.EqualTo("InMemory"));
            Assert.That(result.Reason, Is.Null);
            Assert.That(result.CheckedAt, Is.EqualTo(CheckedAt));
            Assert.That(result.Configured, Is.True);
            Assert.That(result.Distributed, Is.False);
            Assert.That(result.Persistent, Is.False);
            Assert.That(result.ExpiredRowCount, Is.Null);
            Assert.That(result.BlockedKeyCount, Is.Null);
            Assert.That(result.CleanupConfigured, Is.False);
            Assert.That(result.CleanupInterval, Is.Null);
            Assert.That(result.MaxCleanupRows, Is.Null);
        }
    }

    [Test]
    public async Task CheckAsyncReturnsSafeActiveCount()
    {
        var timeProvider = new FakeTimeProvider(CheckedAt);
        var limiter = new InMemoryAuthenticationRateLimiter(timeProvider);
        var diagnostics = new InMemoryAuthenticationRateLimiterDiagnostics(limiter, timeProvider);
        var rule = new RateLimitRule { PermitLimit = 5, Window = TimeSpan.FromMinutes(5) };

        await limiter.CheckAsync(new RateLimitAttempt { Key = "user-1" }, rule);
        await limiter.CheckAsync(new RateLimitAttempt { Key = "user-2" }, rule);

        var result = await diagnostics.CheckAsync();

        Assert.That(result.ActiveKeyCount, Is.EqualTo(2));
    }

    [Test]
    public async Task AddAshlarIdentityRegistersInMemoryRateLimiterDiagnostics()
    {
        var timeProvider = new FakeTimeProvider(CheckedAt);
        var services = new ServiceCollection();
        services.AddAshlarIdentity();
        services.AddSingleton<TimeProvider>(timeProvider);
        await using var provider = services.BuildServiceProvider();

        var diagnostics = provider.GetRequiredService<IAuthenticationRateLimiterDiagnostics>();
        var result = await diagnostics.CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(diagnostics, Is.TypeOf<InMemoryAuthenticationRateLimiterDiagnostics>());
            Assert.That(result.ProviderName, Is.EqualTo("InMemory"));
            Assert.That(result.CheckedAt, Is.EqualTo(CheckedAt));
        }
    }

    [Test]
    public async Task AddAshlarIdentityRegistersNotSupportedDiagnosticsForCustomRateLimiter()
    {
        var timeProvider = new FakeTimeProvider(CheckedAt);
        var services = new ServiceCollection();
        services.AddSingleton<IAuthenticationRateLimiter, CustomAuthenticationRateLimiter>();
        services.AddAshlarIdentity();
        services.AddSingleton<TimeProvider>(timeProvider);
        await using var provider = services.BuildServiceProvider();

        var diagnostics = provider.GetRequiredService<IAuthenticationRateLimiterDiagnostics>();
        var result = await diagnostics.CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(diagnostics, Is.TypeOf<NotSupportedAuthenticationRateLimiterDiagnostics>());
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.NotSupported));
            Assert.That(result.ProviderName, Is.EqualTo(nameof(CustomAuthenticationRateLimiter)));
            Assert.That(result.CheckedAt, Is.EqualTo(CheckedAt));
            Assert.That(result.Configured, Is.False);
        }
    }

    [Test]
    public void ConstructorRejectsNullArguments()
    {
        var timeProvider = new FakeTimeProvider(CheckedAt);
        var limiter = new InMemoryAuthenticationRateLimiter(timeProvider);

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new InMemoryAuthenticationRateLimiterDiagnostics(null!, timeProvider));
            Assert.Throws<ArgumentNullException>(() => _ = new InMemoryAuthenticationRateLimiterDiagnostics(limiter, null!));
        }
    }

    private sealed class CustomAuthenticationRateLimiter : IAuthenticationRateLimiter
    {
        public Task<RateLimitDecision> CheckAsync(RateLimitAttempt attempt, RateLimitRule rule, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new RateLimitDecision
            {
                Status = RateLimitStatus.Allowed,
                Remaining = 0,
                WindowResetAt = DateTimeOffset.UnixEpoch
            });
        }
    }
}
