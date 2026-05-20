using Ashlar.Identity.RateLimiting;
using Ashlar.Identity.RateLimiting.Models;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Tests.Identity.RateLimiting;

internal sealed class InMemoryAuthenticationRateLimiterTests
{
    [Test]
    public async Task CheckAsyncFirstAttemptIsAllowed()
    {
        var timeProvider = new FakeTimeProvider();
        var limiter = new InMemoryAuthenticationRateLimiter(timeProvider);
        var attempt = new RateLimitAttempt { Key = "test@example.com" };
        var rule = new RateLimitRule { PermitLimit = 5, Window = TimeSpan.FromMinutes(5) };

        var decision = await limiter.CheckAsync(attempt, rule);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(decision.IsAllowed, Is.True);
            Assert.That(decision.Status, Is.EqualTo(RateLimitStatus.Allowed));
            Assert.That(decision.Remaining, Is.EqualTo(4));
            Assert.That(decision.RetryAfter, Is.Null);
            Assert.That(decision.WindowResetAt, Is.EqualTo(timeProvider.GetUtcNow() + rule.Window));
        }
    }

    [Test]
    public async Task CheckAsyncAttemptsUpToLimitAreAllowed()
    {
        var timeProvider = new FakeTimeProvider();
        var limiter = new InMemoryAuthenticationRateLimiter(timeProvider);
        var attempt = new RateLimitAttempt { Key = "test@example.com" };
        var rule = new RateLimitRule { PermitLimit = 3, Window = TimeSpan.FromMinutes(5) };

        var decision1 = await limiter.CheckAsync(attempt, rule);
        Assert.That(decision1.IsAllowed, Is.True);

        var decision2 = await limiter.CheckAsync(attempt, rule);
        Assert.That(decision2.IsAllowed, Is.True);

        var decision3 = await limiter.CheckAsync(attempt, rule);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(decision3.IsAllowed, Is.True);
            Assert.That(decision3.Remaining, Is.Zero);
        }
    }

    [Test]
    public async Task CheckAsyncAttemptOverLimitIsBlocked()
    {
        var timeProvider = new FakeTimeProvider();
        var limiter = new InMemoryAuthenticationRateLimiter(timeProvider);
        var attempt = new RateLimitAttempt { Key = "test@example.com" };
        var rule = new RateLimitRule { PermitLimit = 2, Window = TimeSpan.FromMinutes(5) };

        await limiter.CheckAsync(attempt, rule);
        await limiter.CheckAsync(attempt, rule);

        var decision = await limiter.CheckAsync(attempt, rule);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(decision.IsAllowed, Is.False);
            Assert.That(decision.Status, Is.EqualTo(RateLimitStatus.Blocked));
            Assert.That(decision.Remaining, Is.Zero);
            Assert.That(decision.RetryAfter, Is.EqualTo(timeProvider.GetUtcNow() + rule.Window));
        }
    }

    [Test]
    public async Task CheckAsyncAttemptsAllowedAgainAfterWindowExpires()
    {
        var timeProvider = new FakeTimeProvider();
        var limiter = new InMemoryAuthenticationRateLimiter(timeProvider);
        var attempt = new RateLimitAttempt { Key = "test@example.com" };
        var rule = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(5) };

        await limiter.CheckAsync(attempt, rule);
        var blockedDecision = await limiter.CheckAsync(attempt, rule);
        Assert.That(blockedDecision.IsAllowed, Is.False);

        timeProvider.Advance(TimeSpan.FromMinutes(5));
        var allowedDecision = await limiter.CheckAsync(attempt, rule);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(allowedDecision.IsAllowed, Is.True);
            Assert.That(allowedDecision.Remaining, Is.Zero);
        }
    }

    [Test]
    public async Task CheckAsyncBlockDurationExtendsBlockingIfConfigured()
    {
        var timeProvider = new FakeTimeProvider();
        var limiter = new InMemoryAuthenticationRateLimiter(timeProvider);
        var attempt = new RateLimitAttempt { Key = "test@example.com" };
        var rule = new RateLimitRule
        {
            PermitLimit = 1,
            Window = TimeSpan.FromMinutes(5),
            BlockDuration = TimeSpan.FromMinutes(15)
        };

        var start = timeProvider.GetUtcNow();
        await limiter.CheckAsync(attempt, rule);

        var blockedDecision = await limiter.CheckAsync(attempt, rule);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(blockedDecision.IsAllowed, Is.False);
            Assert.That(blockedDecision.RetryAfter, Is.EqualTo(start + TimeSpan.FromMinutes(15)));
        }

        timeProvider.Advance(TimeSpan.FromMinutes(6));
        var stillBlockedDecision = await limiter.CheckAsync(attempt, rule);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(stillBlockedDecision.IsAllowed, Is.False);
            Assert.That(stillBlockedDecision.RetryAfter, Is.EqualTo(start + TimeSpan.FromMinutes(15)));
        }

        timeProvider.Advance(TimeSpan.FromMinutes(10));
        var allowedDecision = await limiter.CheckAsync(attempt, rule);
        Assert.That(allowedDecision.IsAllowed, Is.True);
    }

    [Test]
    public async Task CheckAsyncDifferentKeysAreIsolated()
    {
        var timeProvider = new FakeTimeProvider();
        var limiter = new InMemoryAuthenticationRateLimiter(timeProvider);
        var attempt1 = new RateLimitAttempt { Key = "user1" };
        var attempt2 = new RateLimitAttempt { Key = "user2", Purpose = "Login" };
        var attempt3 = new RateLimitAttempt { Key = "user2", Purpose = "Reset" };

        var rule = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(5) };

        await limiter.CheckAsync(attempt1, rule);
        await limiter.CheckAsync(attempt2, rule);

        var user1Blocked = await limiter.CheckAsync(attempt1, rule);
        var user2LoginBlocked = await limiter.CheckAsync(attempt2, rule);
        var user2ResetAllowed = await limiter.CheckAsync(attempt3, rule);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(user1Blocked.IsAllowed, Is.False);
            Assert.That(user2LoginBlocked.IsAllowed, Is.False);
            Assert.That(user2ResetAllowed.IsAllowed, Is.True);
        }
    }

    [Test]
    public async Task CheckAsyncIsSafeUnderConcurrentCalls()
    {
        var timeProvider = new FakeTimeProvider();
        var limiter = new InMemoryAuthenticationRateLimiter(timeProvider);
        var attempt = new RateLimitAttempt { Key = "concurrent" };
        var rule = new RateLimitRule { PermitLimit = 50, Window = TimeSpan.FromMinutes(5) };

        var tasks = Enumerable.Range(0, 100)
            .Select(_ => Task.Run(() => limiter.CheckAsync(attempt, rule)))
            .ToArray();

        var results = await Task.WhenAll(tasks);

        var allowedCount = results.Count(r => r.IsAllowed);
        var blockedCount = results.Count(r => !r.IsAllowed);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(allowedCount, Is.EqualTo(50));
            Assert.That(blockedCount, Is.EqualTo(50));
        }
    }

    [Test]
    public void CheckAsyncThrowsIfPermitLimitIsInvalid()
    {
        var timeProvider = new FakeTimeProvider();
        var limiter = new InMemoryAuthenticationRateLimiter(timeProvider);
        var attempt = new RateLimitAttempt { Key = "test" };
        var rule = new RateLimitRule { PermitLimit = 0, Window = TimeSpan.FromMinutes(5) };

        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => limiter.CheckAsync(attempt, rule));
        Assert.That(ex?.ParamName, Is.EqualTo("rule"));
    }

    [Test]
    public void CheckAsyncThrowsIfWindowIsInvalid()
    {
        var timeProvider = new FakeTimeProvider();
        var limiter = new InMemoryAuthenticationRateLimiter(timeProvider);
        var attempt = new RateLimitAttempt { Key = "test" };
        var rule = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.Zero };

        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => limiter.CheckAsync(attempt, rule));
        Assert.That(ex?.ParamName, Is.EqualTo("rule"));
    }

    [Test]
    public void CheckAsyncThrowsIfBlockDurationIsInvalid()
    {
        var timeProvider = new FakeTimeProvider();
        var limiter = new InMemoryAuthenticationRateLimiter(timeProvider);
        var attempt = new RateLimitAttempt { Key = "test" };
        var rule = new RateLimitRule
        {
            PermitLimit = 1,
            Window = TimeSpan.FromMinutes(5),
            BlockDuration = TimeSpan.FromSeconds(-1)
        };

        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => limiter.CheckAsync(attempt, rule));
        Assert.That(ex?.ParamName, Is.EqualTo("rule"));
    }

    [Test]
    public async Task CheckAsyncShortBlockDurationDoesNotBypassWindow()
    {
        var timeProvider = new FakeTimeProvider();
        var limiter = new InMemoryAuthenticationRateLimiter(timeProvider);
        var attempt = new RateLimitAttempt { Key = "block-reset" };
        var rule = new RateLimitRule
        {
            PermitLimit = 1,
            Window = TimeSpan.FromMinutes(5),
            BlockDuration = TimeSpan.FromMinutes(1)
        };

        var start = timeProvider.GetUtcNow();
        await limiter.CheckAsync(attempt, rule); // Allowed
        await limiter.CheckAsync(attempt, rule); // Blocked, but should be blocked until Window ends (5 min) because BlockDuration is shorter

        timeProvider.Advance(TimeSpan.FromMinutes(1.1));
        var decision = await limiter.CheckAsync(attempt, rule);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(decision.IsAllowed, Is.False, "A shorter BlockDuration should not allow bypassing the Window limit.");
            Assert.That(decision.RetryAfter, Is.EqualTo(start + TimeSpan.FromMinutes(5)));
        }
    }

    [Test]
    public async Task StateCountReturnsCacheSize()
    {
        var timeProvider = new FakeTimeProvider();
        var limiter = new InMemoryAuthenticationRateLimiter(timeProvider);
        var rule = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(5) };

        Assert.That(limiter.StateCount, Is.Zero);
        await limiter.CheckAsync(new RateLimitAttempt { Key = "user" }, rule);
        Assert.That(limiter.StateCount, Is.EqualTo(1));
    }

    [Test]
    public void DisposeDisposesInternalCache()
    {
        var timeProvider = new FakeTimeProvider();
        var limiter = new InMemoryAuthenticationRateLimiter(timeProvider);
        Assert.DoesNotThrow(limiter.Dispose);
    }
}
