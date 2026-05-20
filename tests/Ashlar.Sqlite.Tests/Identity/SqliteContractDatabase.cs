using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;

namespace Ashlar.Sqlite.Tests.Identity;

internal sealed class SqliteContractDatabase
{
    private SqliteContractDatabase(string databasePath, IServiceProvider serviceProvider)
    {
        DatabasePath = databasePath;
        ServiceProvider = serviceProvider;
    }

    public IServiceProvider ServiceProvider { get; }

    public string ConnectionString { get; private init; } = string.Empty;

    private string DatabasePath { get; }

    public static Task<SqliteContractDatabase> CreateAsync()
    {
        return CreateAsync(_ => { });
    }

    public static async Task<SqliteContractDatabase> CreateAsync(Action<IServiceCollection> configureServices)
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"ashlar_sqlite_contract_{Guid.NewGuid():N}.db");
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Pooling = false
        }.ConnectionString;

        var services = new ServiceCollection();
        services.AddAshlarSqlite(connectionString);
        configureServices(services);
        var provider = services.BuildServiceProvider();
        await provider.InitializeAshlarSqliteSchemaAsync();
        return new SqliteContractDatabase(databasePath, provider)
        {
            ConnectionString = connectionString
        };
    }

    public void Delete()
    {
        if (File.Exists(DatabasePath))
        {
            File.Delete(DatabasePath);
        }
    }
}


