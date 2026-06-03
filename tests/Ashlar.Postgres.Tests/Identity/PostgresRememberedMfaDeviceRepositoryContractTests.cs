namespace Ashlar.Postgres.Tests.Identity;

internal sealed class PostgresRememberedMfaDeviceRepositoryContractTests : RememberedMfaDeviceRepositoryContractTests
{
    private PostgresContractDatabaseLease? _database;

    protected override async Task<IServiceProvider> CreateInitializedServiceProviderAsync()
    {
        _database = await PostgresContractDatabase.CreateInitializedServiceProviderAsync();
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
}
