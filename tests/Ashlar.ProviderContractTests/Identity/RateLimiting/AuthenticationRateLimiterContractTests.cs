using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.ProviderContractTests.Identity.RateLimiting;

/// <summary>Tests rate-limit windows, permit boundaries, key isolation, validation, persistence, and rollback.</summary>
public abstract class AuthenticationRateLimiterContractTests : ProviderContractFixture
{
    /// <summary>Current provider time used to verify rate-limit windows.</summary>
    protected abstract DateTimeOffset Now { get; }

    /// <summary>Advances the provider clock used for expiry decisions.</summary>
    /// <param name="duration">Amount by which to advance provider time.</param>
    protected abstract void AdvanceTime(TimeSpan duration);

    /// <summary>Allowed precision difference between provider and fixture timestamps.</summary>
    protected virtual TimeSpan TimestampTolerance => TimeSpan.Zero;

    /// <summary>Window used by the default rate-limit scenarios.</summary>
    protected virtual TimeSpan RateLimitWindow => TimeSpan.FromMinutes(5);

    /// <summary>Whether the provider can verify rate-limit rollback.</summary>
    protected virtual bool SupportsRateLimiterTransactionRollback => false;

    /// <summary>Verifies that a new bucket permits its first attempt.</summary>
    [Test]
    public async Task CheckAsyncFirstAttemptUnderRuleIsAllowed()
    {
        await using var scope = CreateAsyncScope();
        var limiter = GetAuthenticationRateLimiter(scope.ServiceProvider);
        var rule = new RateLimitRule { PermitLimit = 5, Window = RateLimitWindow };

        var decision = await limiter.CheckAsync(new RateLimitAttempt { Key = UniqueKey() }, rule);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(decision.IsAllowed, Is.True);
            Assert.That(decision.Status, Is.EqualTo(RateLimitStatus.Allowed));
            Assert.That(decision.Remaining, Is.EqualTo(4));
            Assert.That(decision.RetryAfter, Is.Null);
            Assert.That(decision.WindowResetAt, Is.InRange(
                Now + rule.Window - TimestampTolerance,
                Now + rule.Window + TimestampTolerance));
        }
    }

    /// <summary>Verifies that every permit in the configured window remains usable.</summary>
    [Test]
    public async Task CheckAsyncAttemptsUpToPermitLimitAreAllowed()
    {
        await using var scope = CreateAsyncScope();
        var limiter = GetAuthenticationRateLimiter(scope.ServiceProvider);
        var attempt = new RateLimitAttempt { Key = UniqueKey() };
        var rule = new RateLimitRule { PermitLimit = 3, Window = RateLimitWindow };

        var first = await limiter.CheckAsync(attempt, rule);
        var second = await limiter.CheckAsync(attempt, rule);
        var third = await limiter.CheckAsync(attempt, rule);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(first.IsAllowed, Is.True);
            Assert.That(second.IsAllowed, Is.True);
            Assert.That(third.IsAllowed, Is.True);
            Assert.That(third.Remaining, Is.Zero);
        }
    }

    /// <summary>Verifies that the first attempt beyond the permit limit is denied.</summary>
    [Test]
    public async Task CheckAsyncAttemptOverPermitLimitIsBlocked()
    {
        await using var scope = CreateAsyncScope();
        var limiter = GetAuthenticationRateLimiter(scope.ServiceProvider);
        var attempt = new RateLimitAttempt { Key = UniqueKey() };
        var rule = new RateLimitRule { PermitLimit = 2, Window = RateLimitWindow };

        await limiter.CheckAsync(attempt, rule);
        await limiter.CheckAsync(attempt, rule);
        var decision = await limiter.CheckAsync(attempt, rule);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(decision.IsAllowed, Is.False);
            Assert.That(decision.Status, Is.EqualTo(RateLimitStatus.Blocked));
            Assert.That(decision.Remaining, Is.Zero);
            Assert.That(decision.RetryAfter, Is.InRange(
                Now + rule.Window - TimestampTolerance,
                Now + rule.Window + TimestampTolerance));
        }
    }

    /// <summary>Verifies that denial reports the configured remaining block duration.</summary>
    [Test]
    public async Task CheckAsyncBlockDurationIsReflectedWhenConfigured()
    {
        await using var scope = CreateAsyncScope();
        var limiter = GetAuthenticationRateLimiter(scope.ServiceProvider);
        var attempt = new RateLimitAttempt { Key = UniqueKey() };
        var rule = new RateLimitRule
        {
            PermitLimit = 1,
            Window = RateLimitWindow,
            BlockDuration = TimeSpan.FromMinutes(15)
        };

        var start = Now;
        await limiter.CheckAsync(attempt, rule);
        var decision = await limiter.CheckAsync(attempt, rule);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(decision.IsAllowed, Is.False);
            Assert.That(decision.RetryAfter, Is.InRange(
                start + rule.BlockDuration - TimestampTolerance,
                Now + rule.BlockDuration + TimestampTolerance));
        }
    }

    /// <summary>Verifies that permits become available after the rate-limit window expires.</summary>
    [Test]
    public async Task CheckAsyncAllowsAttemptsAfterWindowResets()
    {
        await using var scope = CreateAsyncScope();
        var limiter = GetAuthenticationRateLimiter(scope.ServiceProvider);
        var attempt = new RateLimitAttempt { Key = UniqueKey() };
        var rule = new RateLimitRule { PermitLimit = 1, Window = RateLimitWindow };

        await limiter.CheckAsync(attempt, rule);
        Assert.That((await limiter.CheckAsync(attempt, rule)).IsAllowed, Is.False);

        AdvanceTime(rule.Window);
        var decision = await limiter.CheckAsync(attempt, rule);

        Assert.That(decision.IsAllowed, Is.True);
    }

    /// <summary>Verifies that consuming one key's permits cannot block another key.</summary>
    [Test]
    public async Task CheckAsyncDifferentKeysAreIsolated()
    {
        await using var scope = CreateAsyncScope();
        var limiter = GetAuthenticationRateLimiter(scope.ServiceProvider);
        var rule = new RateLimitRule { PermitLimit = 1, Window = RateLimitWindow };
        var first = UniqueKey();
        var second = UniqueKey();

        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "login", Key = first }, rule);
        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "login", Key = second }, rule);

        using (Assert.EnterMultipleScope())
        {
            Assert.That((await limiter.CheckAsync(new RateLimitAttempt { Purpose = "login", Key = first }, rule)).IsAllowed, Is.False);
            Assert.That((await limiter.CheckAsync(new RateLimitAttempt { Purpose = "login", Key = second }, rule)).IsAllowed, Is.False);
            Assert.That((await limiter.CheckAsync(new RateLimitAttempt { Purpose = "login", Key = UniqueKey() }, rule)).IsAllowed, Is.True);
        }
    }

    /// <summary>Verifies that consuming one purpose's permits cannot block another purpose.</summary>
    [Test]
    public async Task CheckAsyncDifferentPurposesAreIsolated()
    {
        await using var scope = CreateAsyncScope();
        var limiter = GetAuthenticationRateLimiter(scope.ServiceProvider);
        var rule = new RateLimitRule { PermitLimit = 1, Window = RateLimitWindow };
        var key = UniqueKey();

        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "login", Key = key }, rule);
        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "reset", Key = key }, rule);

        using (Assert.EnterMultipleScope())
        {
            Assert.That((await limiter.CheckAsync(new RateLimitAttempt { Purpose = "login", Key = key }, rule)).IsAllowed, Is.False);
            Assert.That((await limiter.CheckAsync(new RateLimitAttempt { Purpose = "reset", Key = key }, rule)).IsAllowed, Is.False);
            Assert.That((await limiter.CheckAsync(new RateLimitAttempt { Purpose = "invite", Key = key }, rule)).IsAllowed, Is.True);
        }
    }

    /// <summary>Verifies that recreating a DI scope cannot reset an active rate limit.</summary>
    [Test]
    public async Task CheckAsyncStatePersistsAcrossServiceProviderScopes()
    {
        var key = UniqueKey();
        var rule = new RateLimitRule { PermitLimit = 1, Window = RateLimitWindow };
        await using (var scope = CreateAsyncScope())
        {
            await GetAuthenticationRateLimiter(scope.ServiceProvider).CheckAsync(new RateLimitAttempt { Key = key }, rule);
        }

        await using var secondScope = CreateAsyncScope();
        var decision = await GetAuthenticationRateLimiter(secondScope.ServiceProvider).CheckAsync(new RateLimitAttempt { Key = key }, rule);

        Assert.That(decision.IsAllowed, Is.False);
    }

    /// <summary>Verifies that checks reject nonpositive permit, window, and block settings.</summary>
    [Test]
    public async Task CheckAsyncRejectsInvalidRulesConsistently()
    {
        await using var scope = CreateAsyncScope();
        var limiter = GetAuthenticationRateLimiter(scope.ServiceProvider);
        var attempt = new RateLimitAttempt { Key = UniqueKey() };

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await limiter.CheckAsync(attempt, new RateLimitRule { PermitLimit = 0, Window = RateLimitWindow }));
            Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await limiter.CheckAsync(attempt, new RateLimitRule { PermitLimit = 1, Window = TimeSpan.Zero }));
            Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await limiter.CheckAsync(attempt, new RateLimitRule { PermitLimit = 1, Window = RateLimitWindow, BlockDuration = TimeSpan.Zero }));
        }
    }

    /// <summary>Verifies that checks reject <see langword="null" />, empty, and whitespace keys.</summary>
    [Test]
    public async Task CheckAsyncRejectsInvalidKeysConsistently()
    {
        await using var scope = CreateAsyncScope();
        var limiter = GetAuthenticationRateLimiter(scope.ServiceProvider);
        var rule = new RateLimitRule { PermitLimit = 1, Window = RateLimitWindow };

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentNullException>(async () => await limiter.CheckAsync(new RateLimitAttempt { Key = null! }, rule));
            Assert.ThrowsAsync<ArgumentException>(async () => await limiter.CheckAsync(new RateLimitAttempt { Key = string.Empty }, rule));
            Assert.ThrowsAsync<ArgumentException>(async () => await limiter.CheckAsync(new RateLimitAttempt { Key = " " }, rule));
        }
    }

    /// <summary>Verifies that a rolled-back check does not consume a permit.</summary>
    /// <exception cref="System.InvalidOperationException">The fixture did not register a transaction provider.</exception>
    [Test]
    public async Task CheckAsyncRollsBackWhenProviderImplementationParticipatesInAshlarTransactions()
    {
        if (!SupportsRateLimiterTransactionRollback)
        {
            Assert.Ignore("This provider rate limiter does not participate in IAshlarTransactionProvider transactions.");
        }

        await using var scope = CreateAsyncScope();
        var transactionProvider = GetTransactionProvider(scope.ServiceProvider) ?? throw new InvalidOperationException("Transaction provider is not registered.");
        var limiter = GetAuthenticationRateLimiter(scope.ServiceProvider);
        var rule = new RateLimitRule { PermitLimit = 1, Window = RateLimitWindow };
        var key = UniqueKey();

        await using (var transaction = await transactionProvider.BeginTransactionAsync())
        {
            await limiter.CheckAsync(new RateLimitAttempt { Key = key }, rule);
            await transaction.RollbackAsync();
        }

        var decision = await limiter.CheckAsync(new RateLimitAttempt { Key = key }, rule);

        Assert.That(decision.IsAllowed, Is.True);
    }

    private static string UniqueKey() => $"contract-{Guid.NewGuid():N}";
}
