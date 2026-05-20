using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.ProviderContractTests.Identity.RateLimiting;

internal abstract class AuthenticationRateLimiterContractTests : ProviderContractFixture
{
    protected abstract DateTimeOffset Now { get; }

    protected abstract void AdvanceTime(TimeSpan duration);

    protected virtual bool SupportsRateLimiterTransactionRollback => false;

    [Test]
    public async Task CheckAsyncFirstAttemptUnderRuleIsAllowed()
    {
        await using var scope = CreateAsyncScope();
        var limiter = GetAuthenticationRateLimiter(scope.ServiceProvider);
        var rule = new RateLimitRule { PermitLimit = 5, Window = TimeSpan.FromMinutes(5) };

        var decision = await limiter.CheckAsync(new RateLimitAttempt { Key = UniqueKey() }, rule);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(decision.IsAllowed, Is.True);
            Assert.That(decision.Status, Is.EqualTo(RateLimitStatus.Allowed));
            Assert.That(decision.Remaining, Is.EqualTo(4));
            Assert.That(decision.RetryAfter, Is.Null);
            Assert.That(decision.WindowResetAt, Is.EqualTo(Now + rule.Window));
        }
    }

    [Test]
    public async Task CheckAsyncAttemptsUpToPermitLimitAreAllowed()
    {
        await using var scope = CreateAsyncScope();
        var limiter = GetAuthenticationRateLimiter(scope.ServiceProvider);
        var attempt = new RateLimitAttempt { Key = UniqueKey() };
        var rule = new RateLimitRule { PermitLimit = 3, Window = TimeSpan.FromMinutes(5) };

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

    [Test]
    public async Task CheckAsyncAttemptOverPermitLimitIsBlocked()
    {
        await using var scope = CreateAsyncScope();
        var limiter = GetAuthenticationRateLimiter(scope.ServiceProvider);
        var attempt = new RateLimitAttempt { Key = UniqueKey() };
        var rule = new RateLimitRule { PermitLimit = 2, Window = TimeSpan.FromMinutes(5) };

        await limiter.CheckAsync(attempt, rule);
        await limiter.CheckAsync(attempt, rule);
        var decision = await limiter.CheckAsync(attempt, rule);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(decision.IsAllowed, Is.False);
            Assert.That(decision.Status, Is.EqualTo(RateLimitStatus.Blocked));
            Assert.That(decision.Remaining, Is.Zero);
            Assert.That(decision.RetryAfter, Is.EqualTo(Now + rule.Window));
        }
    }

    [Test]
    public async Task CheckAsyncBlockDurationIsReflectedWhenConfigured()
    {
        await using var scope = CreateAsyncScope();
        var limiter = GetAuthenticationRateLimiter(scope.ServiceProvider);
        var attempt = new RateLimitAttempt { Key = UniqueKey() };
        var rule = new RateLimitRule
        {
            PermitLimit = 1,
            Window = TimeSpan.FromMinutes(5),
            BlockDuration = TimeSpan.FromMinutes(15)
        };

        var start = Now;
        await limiter.CheckAsync(attempt, rule);
        var decision = await limiter.CheckAsync(attempt, rule);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(decision.IsAllowed, Is.False);
            Assert.That(decision.RetryAfter, Is.EqualTo(start + rule.BlockDuration));
        }
    }

    [Test]
    public async Task CheckAsyncAllowsAttemptsAfterWindowResets()
    {
        await using var scope = CreateAsyncScope();
        var limiter = GetAuthenticationRateLimiter(scope.ServiceProvider);
        var attempt = new RateLimitAttempt { Key = UniqueKey() };
        var rule = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(5) };

        await limiter.CheckAsync(attempt, rule);
        Assert.That((await limiter.CheckAsync(attempt, rule)).IsAllowed, Is.False);

        AdvanceTime(rule.Window);
        var decision = await limiter.CheckAsync(attempt, rule);

        Assert.That(decision.IsAllowed, Is.True);
    }

    [Test]
    public async Task CheckAsyncDifferentKeysAreIsolated()
    {
        await using var scope = CreateAsyncScope();
        var limiter = GetAuthenticationRateLimiter(scope.ServiceProvider);
        var rule = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(5) };
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

    [Test]
    public async Task CheckAsyncDifferentPurposesAreIsolated()
    {
        await using var scope = CreateAsyncScope();
        var limiter = GetAuthenticationRateLimiter(scope.ServiceProvider);
        var rule = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(5) };
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

    [Test]
    public async Task CheckAsyncStatePersistsAcrossServiceProviderScopes()
    {
        var key = UniqueKey();
        var rule = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(5) };
        await using (var scope = CreateAsyncScope())
        {
            await GetAuthenticationRateLimiter(scope.ServiceProvider).CheckAsync(new RateLimitAttempt { Key = key }, rule);
        }

        await using var secondScope = CreateAsyncScope();
        var decision = await GetAuthenticationRateLimiter(secondScope.ServiceProvider).CheckAsync(new RateLimitAttempt { Key = key }, rule);

        Assert.That(decision.IsAllowed, Is.False);
    }

    [Test]
    public async Task CheckAsyncRejectsInvalidRulesConsistently()
    {
        await using var scope = CreateAsyncScope();
        var limiter = GetAuthenticationRateLimiter(scope.ServiceProvider);
        var attempt = new RateLimitAttempt { Key = UniqueKey() };

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await limiter.CheckAsync(attempt, new RateLimitRule { PermitLimit = 0, Window = TimeSpan.FromMinutes(5) }));
            Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await limiter.CheckAsync(attempt, new RateLimitRule { PermitLimit = 1, Window = TimeSpan.Zero }));
            Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await limiter.CheckAsync(attempt, new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(5), BlockDuration = TimeSpan.Zero }));
        }
    }

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
        var rule = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(5) };
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


