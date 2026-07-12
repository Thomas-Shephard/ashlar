using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using StackExchange.Redis;
using Ashlar.Auditing;
using Ashlar.Identity.Abstractions.Transactions;

namespace Ashlar.Redis.Tests.RateLimiting;

internal sealed class RedisAuthenticationRateLimitAdministrationContractTests : AuthenticationRateLimitAdministrationContractTests
{
    private static readonly DateTimeOffset Start = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);
    private readonly RedisTestHost _redis = new();
    private FakeTimeProvider _timeProvider = null!;

    protected override DateTimeOffset Now => _timeProvider.GetUtcNow();

    [OneTimeTearDown]
    public async Task DisposeRedisHostAsync()
    {
        await _redis.OneTimeTearDown();
    }

    protected override async Task<IServiceProvider> CreateInitializedServiceProviderAsync()
    {
        await _redis.InitializeAsync();

        _timeProvider = new FakeTimeProvider(Start);
        var services = new ServiceCollection();
        var transactions = new TestDurableTransactionProvider();
        services.AddAshlarIdentity();
        services.AddAshlarRedisRateLimiting(_redis.Connection, options => options.KeyPrefix = $"ashlar:test:{Guid.NewGuid():N}");
        services.AddSingleton<TimeProvider>(_timeProvider);
        services.AddSingleton<IAshlarTransactionProvider>(transactions);
        services.AddSingleton<IAshlarDurableTransactionProvider>(transactions);
        services.AddSingleton<IPersistentSecurityEventSink, NoOpPersistentSecurityEventSink>();
        return services.BuildServiceProvider();
    }

    protected override void AdvanceTime(TimeSpan duration)
    {
        _timeProvider.Advance(duration);
    }

    private sealed class RedisTestHost : RedisTestBase
    {
        public IConnectionMultiplexer Connection => GetConnection();

        public async Task InitializeAsync()
        {
            await OneTimeSetUp();
        }
    }

    private sealed class TestDurableTransactionProvider : IAshlarDurableTransactionProvider
    {
        public Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IAshlarTransaction>(new TestTransaction());
    }

    private sealed class TestTransaction : IAshlarTransaction
    {
        public Task CommitAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task RollbackAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public void OnCommitted(Func<CancellationToken, Task> action) => ArgumentNullException.ThrowIfNull(action);
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class NoOpPersistentSecurityEventSink : IPersistentSecurityEventSink
    {
        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
