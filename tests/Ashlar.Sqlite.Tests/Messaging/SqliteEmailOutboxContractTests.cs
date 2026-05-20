using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Sqlite.Tests.Messaging;

internal sealed class SqliteEmailOutboxContractTests : EmailOutboxContractTests
{
    private static readonly DateTimeOffset Now = new(2026, 5, 8, 12, 0, 0, TimeSpan.Zero);
    private SqliteContractDatabase? _database;
    private FakeTimeProvider _timeProvider = null!;

    protected override async Task<IServiceProvider> CreateInitializedServiceProviderAsync()
    {
        _timeProvider = new FakeTimeProvider(Now);
        _database = await SqliteContractDatabase.CreateAsync(services =>
        {
            services.AddSingleton<TimeProvider>(_timeProvider);
            services.AddSingleton<RecordingEmailTransport>();
            services.AddAshlarSqliteEmailOutboxDispatcher<RecordingEmailTransport>(options =>
            {
                options.BatchSize = 2;
                options.InitialRetryDelay = TimeSpan.FromMinutes(1);
            });
        });
        return _database.ServiceProvider;
    }

    protected override Task CleanupInitializedServiceProviderAsync()
    {
        _database?.Delete();
        _database = null;
        return Task.CompletedTask;
    }

    protected override Task AdvanceEmailOutboxTimeAsync(TimeSpan offset)
    {
        _timeProvider.Advance(offset);
        return Task.CompletedTask;
    }
}
