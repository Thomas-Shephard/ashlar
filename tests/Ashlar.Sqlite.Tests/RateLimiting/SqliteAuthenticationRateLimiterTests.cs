using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using System.Globalization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Sqlite.Tests.RateLimiting;

internal sealed class SqliteAuthenticationRateLimiterTests : SqliteTestBase
{
    private static readonly DateTimeOffset Start = new(2026, 5, 8, 12, 0, 0, TimeSpan.Zero);
    private FakeTimeProvider _timeProvider = null!;
    private ServiceProvider _provider = null!;

    [SetUp]
    public async Task SetUpAsync()
    {
        _timeProvider = new FakeTimeProvider(Start);
        var services = new ServiceCollection();
        services.AddAshlarSqlite(GetConnectionString());
        services.AddAshlarSqliteRateLimiting();
        services.AddSingleton<TimeProvider>(_timeProvider);
        _provider = services.BuildServiceProvider();
        await _provider.InitializeAshlarSqliteSchemaAsync();
    }

    [TearDown]
    public async Task TearDownAsync()
    {
        await _provider.DisposeAsync();
    }

    [Test]
    public async Task CheckAsyncAllowsAttemptsUnderLimit()
    {
        var limiter = GetLimiter();
        var rule = new RateLimitRule { PermitLimit = 3, Window = TimeSpan.FromMinutes(5) };

        var first = await limiter.CheckAsync(new RateLimitAttempt { Key = "under-limit" }, rule);
        var second = await limiter.CheckAsync(new RateLimitAttempt { Key = "under-limit" }, rule);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(first.IsAllowed, Is.True);
            Assert.That(first.Remaining, Is.EqualTo(2));
            Assert.That(second.IsAllowed, Is.True);
            Assert.That(second.Remaining, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task CheckAsyncRejectsAttemptAtLimit()
    {
        var limiter = GetLimiter();
        var rule = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(5) };

        await limiter.CheckAsync(new RateLimitAttempt { Key = "blocked" }, rule);
        var blocked = await limiter.CheckAsync(new RateLimitAttempt { Key = "blocked" }, rule);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(blocked.IsAllowed, Is.False);
            Assert.That(blocked.RetryAfter, Is.EqualTo(Start + rule.Window));
        }
    }

    [Test]
    public async Task CheckAsyncUsesConfiguredBlockDuration()
    {
        var limiter = GetLimiter();
        var rule = new RateLimitRule
        {
            PermitLimit = 1,
            Window = TimeSpan.FromMinutes(5),
            BlockDuration = TimeSpan.FromMinutes(15)
        };

        await limiter.CheckAsync(new RateLimitAttempt { Key = "block-duration" }, rule);
        var blocked = await limiter.CheckAsync(new RateLimitAttempt { Key = "block-duration" }, rule);

        Assert.That(blocked.RetryAfter, Is.EqualTo(Start + TimeSpan.FromMinutes(15)));
    }

    [Test]
    public async Task CheckAsyncAllowsAfterWindowReset()
    {
        var limiter = GetLimiter();
        var rule = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(5) };

        await limiter.CheckAsync(new RateLimitAttempt { Key = "reset" }, rule);
        Assert.That((await limiter.CheckAsync(new RateLimitAttempt { Key = "reset" }, rule)).IsAllowed, Is.False);

        _timeProvider.Advance(TimeSpan.FromMinutes(5));
        var allowed = await limiter.CheckAsync(new RateLimitAttempt { Key = "reset" }, rule);

        Assert.That(allowed.IsAllowed, Is.True);
    }

    [Test]
    public async Task CheckAsyncIsolatesKeysAndPurposes()
    {
        var limiter = GetLimiter();
        var rule = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(5) };

        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "login", Key = "a" }, rule);
        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "login", Key = "b" }, rule);
        await limiter.CheckAsync(new RateLimitAttempt { Purpose = "reset", Key = "a" }, rule);

        using (Assert.EnterMultipleScope())
        {
            Assert.That((await limiter.CheckAsync(new RateLimitAttempt { Purpose = "login", Key = "a" }, rule)).IsAllowed, Is.False);
            Assert.That((await limiter.CheckAsync(new RateLimitAttempt { Purpose = "login", Key = "b" }, rule)).IsAllowed, Is.False);
            Assert.That((await limiter.CheckAsync(new RateLimitAttempt { Purpose = "reset", Key = "a" }, rule)).IsAllowed, Is.False);
            Assert.That((await limiter.CheckAsync(new RateLimitAttempt { Purpose = "reset", Key = "b" }, rule)).IsAllowed, Is.True);
        }
    }

    [Test]
    public async Task CheckAsyncPersistsStateAcrossScopes()
    {
        var rule = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(5) };
        await GetLimiter().CheckAsync(new RateLimitAttempt { Key = "persisted" }, rule);

        await using var scope = _provider.CreateAsyncScope();
        var limiter = scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimiter>();
        var blocked = await limiter.CheckAsync(new RateLimitAttempt { Key = "persisted" }, rule);

        Assert.That(blocked.IsAllowed, Is.False);
    }

    [Test]
    public async Task CleanupExpiredRowsDeletesOnlyExpiredRows()
    {
        var limiter = (SqliteAuthenticationRateLimiter)GetLimiter();
        var rule = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(5) };
        await limiter.CheckAsync(new RateLimitAttempt { Key = "expired" }, rule);
        await limiter.CheckAsync(new RateLimitAttempt { Key = "active" }, rule);

        _timeProvider.Advance(TimeSpan.FromMinutes(6));
        await limiter.CheckAsync(new RateLimitAttempt { Key = "active" }, rule);
        var deleted = await limiter.CleanupExpiredRowsAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(deleted, Is.EqualTo(1));
            Assert.That(await CountRateLimitsAsync(), Is.EqualTo(1));
        }
    }

    [Test]
    public void CleanupExpiredRowsRejectsInvalidMaxRows()
    {
        var limiter = (SqliteAuthenticationRateLimiter)GetLimiter();

        Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await limiter.CleanupExpiredRowsAsync(0));
    }

    [Test]
    public void CheckAsyncRejectsInvalidRules()
    {
        var limiter = GetLimiter();
        var attempt = new RateLimitAttempt { Key = "invalid-rule" };

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await limiter.CheckAsync(attempt, new RateLimitRule { PermitLimit = 0, Window = TimeSpan.FromMinutes(5) }));
            Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await limiter.CheckAsync(attempt, new RateLimitRule { PermitLimit = 1, Window = TimeSpan.Zero }));
            Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await limiter.CheckAsync(attempt, new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(5), BlockDuration = TimeSpan.Zero }));
        }
    }

    [Test]
    public async Task CheckAsyncUsesFreshStateIfRowDisappearsAfterInsert()
    {
        var limiter = (SqliteAuthenticationRateLimiter)GetLimiter();
        var rule = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(5) };
        var deleted = false;
        limiter.AfterInsertForTesting = async (handle, purpose, key, cancellationToken) =>
        {
            if (deleted)
            {
                return;
            }

            await using var command = handle.Connection.CreateCommand();
            command.Transaction = handle.Transaction;
            command.CommandText = "DELETE FROM ashlar_rate_limits WHERE purpose = $purpose AND rate_limit_key = $key;";
            command.AddParameter("$purpose", purpose);
            command.AddParameter("$key", key);
            await command.ExecuteNonQueryAsync(cancellationToken);
            deleted = true;
        };

        try
        {
            var decision = await limiter.CheckAsync(new RateLimitAttempt { Key = "missing-after-insert" }, rule);

            using (Assert.EnterMultipleScope())
            {
                Assert.That(decision.IsAllowed, Is.True);
                Assert.That(await CountRateLimitsAsync(), Is.EqualTo(1));
            }
        }
        finally
        {
            limiter.AfterInsertForTesting = null;
        }
    }

    [Test]
    public async Task CheckAsyncParticipatesInAshlarTransactionRollback()
    {
        var rule = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(5) };
        await using var scope = _provider.CreateAsyncScope();
        var transactionProvider = scope.ServiceProvider.GetRequiredService<AshlarDurableTransactionProvider>();
        var limiter = scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimiter>();

        await using (var transaction = await transactionProvider.BeginTransactionAsync())
        {
            await limiter.CheckAsync(new RateLimitAttempt { Key = "rollback" }, rule);
            await transaction.RollbackAsync();
        }

        Assert.That(await CountRateLimitsAsync(), Is.Zero);
    }

    private IAuthenticationRateLimiter GetLimiter()
    {
        return _provider.GetRequiredService<IAuthenticationRateLimiter>();
    }

    private async Task<int> CountRateLimitsAsync()
    {
        await using var connection = await OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT count(*) FROM ashlar_rate_limits;";
        return Convert.ToInt32(await command.ExecuteScalarAsync(), CultureInfo.InvariantCulture);
    }
}
