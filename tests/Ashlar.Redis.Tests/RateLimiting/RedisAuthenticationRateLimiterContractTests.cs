using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using StackExchange.Redis;

namespace Ashlar.Redis.Tests.RateLimiting;

internal sealed class RedisAuthenticationRateLimiterContractTests : AuthenticationRateLimiterContractTests
{
    private static readonly DateTimeOffset Start = new(2026, 5, 8, 12, 0, 0, TimeSpan.Zero);
    private readonly RedisTestHost _redis = new();
    private FakeTimeProvider _timeProvider = null!;

    protected override DateTimeOffset Now
    {
        get
        {
            var time = (RedisResult[])_redis.Connection.GetDatabase().Execute("TIME")!;
            return DateTimeOffset.FromUnixTimeMilliseconds((long)time[0] * 1000 + (long)time[1] / 1000);
        }
    }

    protected override TimeSpan TimestampTolerance => TimeSpan.FromSeconds(5);

    protected override TimeSpan RateLimitWindow => TimeSpan.FromMilliseconds(250);

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
        Thread.Sleep(duration + TimeSpan.FromMilliseconds(250));
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
