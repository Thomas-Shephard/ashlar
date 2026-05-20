using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Postgres.Tests.Messaging;

internal sealed class PostgresEmailOutboxContractTests : EmailOutboxContractTests
{
    private static readonly DateTimeOffset Now = new(2026, 5, 8, 12, 0, 0, TimeSpan.Zero);
    private PostgresContractDatabaseLease? _database;
    private FakeTimeProvider _timeProvider = null!;

    protected override async Task<IServiceProvider> CreateInitializedServiceProviderAsync()
    {
        _timeProvider = new FakeTimeProvider(Now);
        _database = await PostgresContractDatabase.CreateInitializedServiceProviderAsync(services =>
        {
            services.AddSingleton<TimeProvider>(_timeProvider);
            services.AddSingleton<RecordingEmailTransport>();
            services.AddAshlarPostgresEmailOutboxDispatcher<RecordingEmailTransport>(options =>
            {
                options.BatchSize = 2;
                options.InitialRetryDelay = TimeSpan.FromMinutes(1);
            });
        });
        return _database.ServiceProvider;
    }

    protected override async Task CleanupInitializedServiceProviderAsync()
    {
        if (_database != null)
        {
            await _database.DropDatabaseAsync();
            _database = null;
        }
    }

    protected override Task AdvanceEmailOutboxTimeAsync(TimeSpan offset)
    {
        _timeProvider.Advance(offset);
        return Task.CompletedTask;
    }
}










