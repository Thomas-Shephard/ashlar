using Ashlar.Sqlite.Schema;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace Ashlar.Sqlite.Tests.Schema;

internal sealed class SqliteSchemaManagerTests : SqliteTestBase
{
    [Test]
    public void ConstructorRejectsNullConnectionFactory()
    {
        Assert.Throws<ArgumentNullException>(() => _ = new SqliteSchemaManager(null!));
    }

    [Test]
    public async Task InitializeAsyncCreatesCoreTablesAndJournal()
    {
        await using var provider = CreateProvider();

        await provider.InitializeAshlarSqliteSchemaAsync();

        await using var connection = await OpenConnectionAsync();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(await TableExistsAsync(connection, "ashlar_users"), Is.True);
            Assert.That(await TableExistsAsync(connection, "ashlar_credentials"), Is.True);
            Assert.That(await TableExistsAsync(connection, "ashlar_sessions"), Is.True);
            Assert.That(await TableExistsAsync(connection, "ashlar_schema_versions"), Is.True);
            Assert.That(await CountAsync(connection, "ashlar_schema_versions"), Is.EqualTo(1));
        }
    }

    [Test]
    public async Task InitializeAsyncIsIdempotent()
    {
        await using var provider = CreateProvider();

        await provider.InitializeAshlarSqliteSchemaAsync();
        await provider.InitializeAshlarSqliteSchemaAsync();

        await using var connection = await OpenConnectionAsync();
        Assert.That(await CountAsync(connection, "ashlar_schema_versions"), Is.EqualTo(1));
    }

    [Test]
    public async Task SchemaUsesSQLiteCompatibleTenantEmailUniqueness()
    {
        await using var provider = CreateProvider();
        await provider.InitializeAshlarSqliteSchemaAsync();

        await using var connection = await OpenConnectionAsync();

        await InsertUserAsync(connection, "user-1", "same@example.com", null);
        Assert.ThrowsAsync<SqliteException>(async () => await InsertUserAsync(connection, "user-2", "same@example.com", null));

        await InsertUserAsync(connection, "user-3", "same@example.com", "tenant-1");
        await InsertUserAsync(connection, "user-4", "same@example.com", "tenant-2");
        Assert.ThrowsAsync<SqliteException>(async () => await InsertUserAsync(connection, "user-5", "same@example.com", "tenant-1"));
    }

    [Test]
    public void InitializeAsyncWrapsSchemaFailures()
    {
        var databasePath = Path.Combine(GetConnectionString(), "invalid.db");
        var factory = new SqliteConnectionFactory(new SqliteConnectionStringBuilder { DataSource = databasePath, Pooling = false }.ConnectionString);
        var schemaManager = new SqliteSchemaManager(factory);

        var exception = Assert.ThrowsAsync<InvalidOperationException>(async () => await schemaManager.InitializeAsync());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exception, Is.Not.Null);
            Assert.That(exception.InnerException, Is.TypeOf<SqliteException>());
        }
    }

    [Test]
    public async Task InitializeAsyncAcceptsExplicitLogger()
    {
        var schemaManager = new SqliteSchemaManager(new SqliteConnectionFactory(GetConnectionString()), NullLogger<SqliteSchemaManager>.Instance);

        await schemaManager.InitializeAsync();

        await using var connection = await OpenConnectionAsync();
        Assert.That(await TableExistsAsync(connection, "ashlar_users"), Is.True);
    }

    private ServiceProvider CreateProvider()
    {
        var services = new ServiceCollection();
        services.AddAshlarSqlite(GetConnectionString());
        return services.BuildServiceProvider();
    }

    private static async Task<bool> TableExistsAsync(SqliteConnection connection, string tableName)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = $table_name LIMIT 1;";
        command.Parameters.AddWithValue("$table_name", tableName);
        var result = await command.ExecuteScalarAsync();
        return result != null;
    }

    private static async Task<int> CountAsync(SqliteConnection connection, string tableName)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = $"SELECT COUNT(*) FROM {tableName};";
        var result = await command.ExecuteScalarAsync();
        return Convert.ToInt32(result, System.Globalization.CultureInfo.InvariantCulture);
    }

    private static async Task InsertUserAsync(SqliteConnection connection, string id, string email, string? tenantId)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO ashlar_users (id, email, normalized_email, is_active, tenant_id, created_at)
            VALUES ($id, $email, $normalized_email, 1, $tenant_id, $created_at);
            """;
        command.Parameters.AddWithValue("$id", id);
        command.Parameters.AddWithValue("$email", email);
        command.Parameters.AddWithValue("$normalized_email", email.ToUpperInvariant());
        command.Parameters.AddWithValue("$tenant_id", tenantId == null ? DBNull.Value : tenantId);
        command.Parameters.AddWithValue("$created_at", DateTimeOffset.UtcNow.ToString("O"));
        await command.ExecuteNonQueryAsync();
    }
}


