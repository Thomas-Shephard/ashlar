using Ashlar.ProviderContractTests.Identity;

namespace Ashlar.Sqlite.Tests.Identity;

internal sealed class SqliteIdentityRepositoryContractTests : IdentityRepositoryContractTests
{
    private SqliteContractDatabase? _database;

    protected override async Task<IServiceProvider> CreateInitializedServiceProviderAsync()
    {
        _database = await SqliteContractDatabase.CreateAsync();
        return _database.ServiceProvider;
    }

    protected override Task CleanupInitializedServiceProviderAsync()
    {
        _database?.Delete();
        _database = null;
        return Task.CompletedTask;
    }
}
