using Ashlar.ProviderContractTests.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;

namespace Ashlar.Sqlite.Tests.Identity;

internal sealed class SqliteBootstrapStateRepositoryContractTests : BootstrapStateRepositoryContractTests
{
    private string? _databasePath;

    protected override async Task<IServiceProvider> CreateInitializedServiceProviderAsync()
    {
        _databasePath = Path.Combine(Path.GetTempPath(), $"ashlar_sqlite_contract_{Guid.NewGuid():N}.db");
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Pooling = false
        }.ConnectionString;

        var services = new ServiceCollection();
        services.AddAshlarSqlite(connectionString);
        var provider = services.BuildServiceProvider();
        await provider.InitializeAshlarSqliteSchemaAsync();
        return provider;
    }

    protected override Task CleanupInitializedServiceProviderAsync()
    {
        if (_databasePath != null && File.Exists(_databasePath))
        {
            File.Delete(_databasePath);
            _databasePath = null;
        }

        return Task.CompletedTask;
    }
}
