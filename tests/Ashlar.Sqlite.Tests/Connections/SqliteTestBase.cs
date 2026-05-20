using Microsoft.Data.Sqlite;

namespace Ashlar.Sqlite.Tests.Connections;

internal abstract class SqliteTestBase
{
    private string? _databasePath;
    private string? _connectionString;

    [SetUp]
    public void SetUpDatabase()
    {
        _databasePath = Path.Combine(Path.GetTempPath(), $"ashlar_sqlite_test_{Guid.NewGuid():N}.db");
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Pooling = false
        }.ConnectionString;
    }

    [TearDown]
    public void TearDownDatabase()
    {
        if (_databasePath != null && File.Exists(_databasePath))
        {
            File.Delete(_databasePath);
        }
    }

    protected string GetConnectionString()
    {
        return _connectionString ?? throw new InvalidOperationException("SQLite test database has not been initialized.");
    }

    protected async Task<SqliteConnection> OpenConnectionAsync()
    {
        var connection = new SqliteConnection(GetConnectionString());
        await connection.OpenAsync();
        return connection;
    }
}
