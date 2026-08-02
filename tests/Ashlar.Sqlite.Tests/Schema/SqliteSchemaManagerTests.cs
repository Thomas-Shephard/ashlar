using Ashlar.Identity.Features.Infrastructure;
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
    public async Task SchemaRejectsSessionAndGrantRowsWhenUserTenantDoesNotMatch()
    {
        await using var provider = CreateProvider();
        await provider.InitializeAshlarSqliteSchemaAsync();

        await using var connection = await OpenConnectionAsync();
        var tenantId = Guid.NewGuid().ToString("D");
        var otherTenantId = Guid.NewGuid().ToString("D");
        var now = DateTimeOffset.UtcNow.ToString("O");
        await InsertUserAsync(connection, "global-user", "global-owner@example.com", null);
        await InsertUserAsync(connection, "tenant-user", "tenant-owner@example.com", tenantId);

        await ExecuteAsync(connection, "INSERT INTO ashlar_sessions (id, user_id, tenant_id, token_hash, created_at, expires_at) VALUES ('matching-session', 'tenant-user', $tenant_id, 'matching-token', $now, $expires);", tenantId, now);
        await ExecuteAsync(connection, "INSERT INTO ashlar_authorization_grants (id, user_id, tenant_id, permission, created_at) VALUES ('matching-grant', 'tenant-user', $tenant_id, 'tenant.read', $now);", tenantId, now);
        await ExecuteAsync(connection, "INSERT INTO ashlar_sessions (id, user_id, token_hash, created_at, expires_at) VALUES ('global-session', 'global-user', 'global-token', $now, $expires);", null, now);
        await ExecuteAsync(connection, "INSERT INTO ashlar_authorization_grants (id, user_id, permission, created_at) VALUES ('global-grant', 'global-user', 'global.read', $now);", null, now);

        Assert.ThrowsAsync<SqliteException>(async () => await ExecuteAsync(connection, "INSERT INTO ashlar_sessions (id, user_id, tenant_id, token_hash, created_at, expires_at) VALUES ('bad-session-other', 'tenant-user', $tenant_id, 'bad-token-other', $now, $expires);", otherTenantId, now));
        Assert.ThrowsAsync<SqliteException>(async () => await ExecuteAsync(connection, "INSERT INTO ashlar_authorization_grants (id, user_id, permission, created_at) VALUES ('bad-global-grant', 'tenant-user', 'bad.global', $now);", null, now));
        Assert.ThrowsAsync<SqliteException>(async () => await ExecuteAsync(connection, "INSERT INTO ashlar_sessions (id, user_id, tenant_id, token_hash, created_at, expires_at) VALUES ('bad-session-tenant', 'global-user', $tenant_id, 'bad-token-tenant', $now, $expires);", tenantId, now));
        Assert.ThrowsAsync<SqliteException>(async () => await ExecuteAsync(connection, "INSERT INTO ashlar_authorization_grants (id, user_id, tenant_id, permission, created_at) VALUES ('bad-tenant-grant', 'global-user', $tenant_id, 'bad.tenant', $now);", tenantId, now));
    }

    [Test]
    public async Task SchemaRejectsUserTenantIdChanges()
    {
        await using var provider = CreateProvider();
        await provider.InitializeAshlarSqliteSchemaAsync();

        await using var connection = await OpenConnectionAsync();
        var tenantId = Guid.NewGuid().ToString("D");
        await InsertUserAsync(connection, "immutable-global", "immutable-global@example.com", null);
        await InsertUserAsync(connection, "immutable-tenant", "immutable-tenant@example.com", tenantId);

        Assert.ThrowsAsync<SqliteException>(async () => await ExecuteAsync(connection, "UPDATE ashlar_users SET tenant_id = $tenant_id WHERE id = 'immutable-global';", tenantId, DateTimeOffset.UtcNow.ToString("O")));
        Assert.ThrowsAsync<SqliteException>(async () => await ExecuteAsync(connection, "UPDATE ashlar_users SET tenant_id = NULL WHERE id = 'immutable-tenant';", null, DateTimeOffset.UtcNow.ToString("O")));
        Assert.That(await ExecuteAsync(connection, "UPDATE ashlar_users SET tenant_id = $tenant_id WHERE id = 'immutable-tenant';", tenantId, DateTimeOffset.UtcNow.ToString("O")), Is.EqualTo(1));
    }

    [TestCase("role")]
    [TestCase("permission")]
    [TestCase("scope_type")]
    [TestCase("scope_id")]
    public async Task AuthorizationGrantTextFieldsRejectWhitespace(string field)
    {
        await using var provider = CreateProvider();
        await provider.InitializeAshlarSqliteSchemaAsync();
        await using var connection = await OpenConnectionAsync();
        await InsertUserAsync(connection, "grant-user", "grant@example.com", null);

        var values = new Dictionary<string, string?>
        {
            ["role"] = field == "permission" ? null : "admin",
            ["permission"] = field == "permission" ? "permission.read" : null,
            ["scope_type"] = field is "scope_type" or "scope_id" ? "resource" : null,
            ["scope_id"] = field is "scope_type" or "scope_id" ? "123" : null
        };
        values[field] = "   ";

        Assert.ThrowsAsync<SqliteException>(async () => await InsertAuthorizationGrantAsync(connection, $"invalid-{field}", values));
    }

    [Test]
    public async Task AuthorizationGrantValidRowsStillInsert()
    {
        await using var provider = CreateProvider();
        await provider.InitializeAshlarSqliteSchemaAsync();
        await using var connection = await OpenConnectionAsync();
        await InsertUserAsync(connection, "grant-user", "grant@example.com", null);

        await InsertAuthorizationGrantAsync(connection, "role-grant", new() { ["role"] = "admin" });
        await InsertAuthorizationGrantAsync(connection, "permission-grant", new() { ["permission"] = "document.read", ["scope_type"] = "document", ["scope_id"] = "123" });
    }

    [TestCase("version")]
    [TestCase("purpose")]
    [TestCase("challenge")]
    [TestCase("relying_party_id")]
    [TestCase("origin")]
    [TestCase("handshake_token_hash")]
    [TestCase("factor_type")]
    [TestCase("registration_proof_type")]
    public async Task PasskeyChallengeTextFieldsRejectWhitespace(string field)
    {
        await using var provider = CreateProvider();
        await provider.InitializeAshlarSqliteSchemaAsync();
        await using var connection = await OpenConnectionAsync();
        await InsertUserAsync(connection, "passkey-user", "passkey@example.com", null);

        Assert.ThrowsAsync<SqliteException>(async () => await InsertPasskeyChallengeAsync(connection, $"invalid-{field}", field));
    }

    [TestCase("   ")]
    [TestCaseSource(nameof(OverlongDisplayNames))]
    public async Task PasskeyChallengeRejectsInvalidDisplayName(string displayName)
    {
        await using var provider = CreateProvider();
        await provider.InitializeAshlarSqliteSchemaAsync();
        await using var connection = await OpenConnectionAsync();

        Assert.ThrowsAsync<SqliteException>(async () => await InsertPasskeyChallengeAsync(connection, "invalid-display-name", displayName: displayName));
    }

    [Test]
    public async Task PasskeyChallengeAllowsOptionalFieldsToBeOmitted()
    {
        await using var provider = CreateProvider();
        await provider.InitializeAshlarSqliteSchemaAsync();
        await using var connection = await OpenConnectionAsync();

        await InsertPasskeyChallengeAsync(connection, "valid-challenge");
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
            INSERT INTO ashlar_users (id, display_email, normalized_email, account_state, tenant_id, created_at)
            VALUES ($id, $displayEmail, $normalizedEmail, 'active', $tenantId, $createdAt);
            """;
        command.Parameters.AddWithValue("$id", id);
        command.Parameters.AddWithValue("$displayEmail", email);
        command.Parameters.AddWithValue("$normalizedEmail", IdentityNormalization.NormalizeEmail(email));
        command.Parameters.AddWithValue("$tenantId", tenantId == null ? DBNull.Value : tenantId);
        command.Parameters.AddWithValue("$createdAt", DateTimeOffset.UtcNow.ToString("O"));
        await command.ExecuteNonQueryAsync();
    }

    private static async Task<int> ExecuteAsync(SqliteConnection connection, string sql, string? tenantId, string now)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.Parameters.AddWithValue("$tenant_id", tenantId == null ? DBNull.Value : tenantId);
        command.Parameters.AddWithValue("$now", now);
        command.Parameters.AddWithValue("$expires", DateTimeOffset.Parse(now, System.Globalization.CultureInfo.InvariantCulture).AddHours(1).ToString("O"));
        return await command.ExecuteNonQueryAsync();
    }

    private static IEnumerable<string> OverlongDisplayNames() => [new string('x', 101)];

    private static async Task InsertAuthorizationGrantAsync(SqliteConnection connection, string id, Dictionary<string, string?> values)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO ashlar_authorization_grants (id, user_id, role, permission, scope_type, scope_id, created_at)
            VALUES ($id, 'grant-user', $role, $permission, $scope_type, $scope_id, $created_at);
            """;
        command.Parameters.AddWithValue("$id", id);
        foreach (var field in new[] { "role", "permission", "scope_type", "scope_id" })
        {
            command.Parameters.AddWithValue($"${field}", values.GetValueOrDefault(field) ?? (object)DBNull.Value);
        }
        command.Parameters.AddWithValue("$created_at", DateTimeOffset.UtcNow.ToString("O"));
        await command.ExecuteNonQueryAsync();
    }

    private static async Task InsertPasskeyChallengeAsync(SqliteConnection connection, string id, string? blankField = null, string? displayName = null)
    {
        var values = new Dictionary<string, object?>
        {
            ["version"] = "v1",
            ["purpose"] = "passkey-authentication",
            ["challenge"] = id,
            ["relying_party_id"] = "example.com",
            ["origin"] = "https://example.com",
            ["user_id"] = null,
            ["handshake_token_hash"] = null,
            ["factor_type"] = null,
            ["registration_proof_type"] = null
        };
        if (blankField is "handshake_token_hash" or "factor_type")
        {
            values["user_id"] = "passkey-user";
            values["handshake_token_hash"] = "token-hash";
            values["factor_type"] = "passkey";
        }
        if (blankField != null)
        {
            values[blankField] = "   ";
        }

        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO ashlar_passkey_challenges
                (id, version, purpose, user_id, handshake_token_hash, factor_type, display_name, registration_proof_type, challenge, options_json, relying_party_id, origin, created_at, expires_at)
            VALUES
                ($id, $version, $purpose, $user_id, $handshake_token_hash, $factor_type, $display_name, $registration_proof_type, $challenge, '{}', $relying_party_id, $origin, $created_at, $expires_at);
            """;
        command.Parameters.AddWithValue("$id", id);
        foreach (var (field, value) in values)
        {
            command.Parameters.AddWithValue($"${field}", value ?? DBNull.Value);
        }
        command.Parameters.AddWithValue("$display_name", displayName ?? (object)DBNull.Value);
        var now = DateTimeOffset.UtcNow;
        command.Parameters.AddWithValue("$created_at", now.ToString("O"));
        command.Parameters.AddWithValue("$expires_at", now.AddMinutes(5).ToString("O"));
        await command.ExecuteNonQueryAsync();
    }
}
