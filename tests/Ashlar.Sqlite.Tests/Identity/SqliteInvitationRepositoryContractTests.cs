using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Sqlite.Tests.Identity;

internal sealed class SqliteInvitationRepositoryContractTests : InvitationRepositoryContractTests
{
    private SqliteContractDatabase? _database;

    protected override async Task<IServiceProvider> CreateInitializedServiceProviderAsync()
    {
        _database = await SqliteContractDatabase.CreateAsync(services =>
            services.AddSingleton<TimeProvider>(new FakeTimeProvider(RepositoryNow)));
        return _database.ServiceProvider;
    }

    protected override Task CleanupInitializedServiceProviderAsync()
    {
        _database?.Delete();
        _database = null;
        return Task.CompletedTask;
    }
}
