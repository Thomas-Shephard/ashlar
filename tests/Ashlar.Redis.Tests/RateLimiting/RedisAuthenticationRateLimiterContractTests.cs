using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using StackExchange.Redis;

namespace Ashlar.Redis.Tests.RateLimiting;

internal sealed class RedisAuthenticationRateLimiterContractTests : AuthenticationRateLimiterContractTests
{
    private static readonly DateTimeOffset Start = new(2026, 5, 8, 12, 0, 0, TimeSpan.Zero);
    private readonly RedisTestHost _redis = new();
    private FakeTimeProvider _timeProvider = null!;

    protected override DateTimeOffset Now => _timeProvider.GetUtcNow();

    protected override async Task<IServiceProvider> CreateInitializedServiceProviderAsync()
    {
        await _redis.InitializeAsync();
        await _redis.FlushAsync();

        _timeProvider = new FakeTimeProvider(Start);
        var services = new ServiceCollection();
        services.AddAshlarRedisRateLimiting(_redis.Connection, options => options.KeyPrefix = $"ashlar:test:{Guid.NewGuid():N}");
        services.AddSingleton<TimeProvider>(_timeProvider);
        return services.BuildServiceProvider();
    }

    protected override void AdvanceTime(TimeSpan duration)
    {
        _timeProvider.Advance(duration);
    }

    private sealed class RedisTestHost : RedisTestBase
    {
        public IConnectionMultiplexer Connection => GetConnection();

        internal Task FlushAsync()
        {
            return FlushDatabaseAsync();
        }

        public async Task InitializeAsync()
        {
            await OneTimeSetUp();
        }
    }
}
