using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Sqlite.Tests.RateLimiting;

internal sealed class SqliteAuthenticationRateLimiterContractTests : AuthenticationRateLimiterContractTests
{
    private static readonly DateTimeOffset Start = new(2026, 5, 8, 12, 0, 0, TimeSpan.Zero);
    private SqliteContractDatabase? _database;
    private FakeTimeProvider _timeProvider = null!;

    protected override DateTimeOffset Now => _timeProvider.GetUtcNow();

    protected override bool SupportsRateLimiterTransactionRollback => true;

    protected override async Task<IServiceProvider> CreateInitializedServiceProviderAsync()
    {
        _timeProvider = new FakeTimeProvider(Start);
        _database = await SqliteContractDatabase.CreateAsync(services => services.AddSingleton<TimeProvider>(_timeProvider));
        return _database.ServiceProvider;
    }

    protected override Task CleanupInitializedServiceProviderAsync()
    {
        _database?.Delete();
        _database = null;
        return Task.CompletedTask;
    }

    protected override void AdvanceTime(TimeSpan duration)
    {
        _timeProvider.Advance(duration);
    }
}








