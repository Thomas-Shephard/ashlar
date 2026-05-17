using Dapper;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Ashlar.Postgres.Tests.Schema;

internal sealed class PostgresSchemaIntegrityTests : PostgresTestBase
{
    private static readonly string[] ExpectedQuerySupportingIndexes =
    [
        "ak_ashlar_users_email_tenant",
        "ix_ashlar_credentials_active_user_provider_created",
        "ix_ashlar_credentials_active_provider_key",
        "ix_ashlar_authorization_grants_user_created",
        "ix_ashlar_authorization_grants_active_user_scope",
        "ix_ashlar_invitations_active_email_tenant",
        "ix_ashlar_email_outbox_pending"
    ];

    private IServiceProvider _serviceProvider = null!;

    public override async Task OneTimeSetUp()
    {
        await base.OneTimeSetUp();

        var services = new ServiceCollection();
        services.AddAshlarPostgres(GetConnectionString());
        _serviceProvider = services.BuildServiceProvider();

        await _serviceProvider.InitializeAshlarPostgresSchemaAsync();
    }

    [OneTimeTearDown]
    public async Task OneTimeTearDownAsync()
    {
        if (_serviceProvider is IAsyncDisposable asyncDisposable)
        {
            await asyncDisposable.DisposeAsync();
        }
    }

    [SetUp]
    public async Task SetUpAsync()
    {
        await using var connection = await GetDataSource().OpenConnectionAsync();
        await connection.ExecuteAsync("""
            TRUNCATE ashlar_email_outbox, ashlar_mfa_handshakes, ashlar_security_events,
                     ashlar_invitations, ashlar_rate_limits, ashlar_sessions,
                     ashlar_authorization_grants, ashlar_credentials, ashlar_bootstrap_state,
                     ashlar_users CASCADE;
            """);
    }

    [Test]
    public async Task UserEmailUniquenessShouldBeTenantScopedIncludingNullTenant()
    {
        await using var connection = await GetDataSource().OpenConnectionAsync();
        var tenant1 = Guid.NewGuid();
        var tenant2 = Guid.NewGuid();

        await InsertUserAsync(connection, Guid.NewGuid(), "same@example.com", null);
        await InsertUserAsync(connection, Guid.NewGuid(), "same@example.com", tenant1);
        await InsertUserAsync(connection, Guid.NewGuid(), "same@example.com", tenant2);

        var duplicateNullTenant = Assert.ThrowsAsync<PostgresException>(async () =>
            await InsertUserAsync(connection, Guid.NewGuid(), "same@example.com", null));
        var duplicateTenant = Assert.ThrowsAsync<PostgresException>(async () =>
            await InsertUserAsync(connection, Guid.NewGuid(), "same@example.com", tenant1));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(duplicateNullTenant!.SqlState, Is.EqualTo(PostgresErrorCodes.UniqueViolation));
            Assert.That(duplicateTenant!.SqlState, Is.EqualTo(PostgresErrorCodes.UniqueViolation));
        }
    }

    [Test]
    public async Task CredentialStateConstraintsShouldRequireValidStatusAndRevocationPairing()
    {
        await using var connection = await GetDataSource().OpenConnectionAsync();
        var userId = Guid.NewGuid();
        await InsertUserAsync(connection, userId, "credential-state@example.com", null);

        var invalidStatus = Assert.ThrowsAsync<PostgresException>(async () =>
            await InsertCredentialAsync(connection, userId, status: 7, revokedAt: null));
        var revokedWithoutTimestamp = Assert.ThrowsAsync<PostgresException>(async () =>
            await InsertCredentialAsync(connection, userId, status: 1, revokedAt: null));
        var activeWithTimestamp = Assert.ThrowsAsync<PostgresException>(async () =>
            await InsertCredentialAsync(connection, userId, status: 0, revokedAt: DateTimeOffset.UtcNow));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(invalidStatus!.SqlState, Is.EqualTo(PostgresErrorCodes.CheckViolation));
            Assert.That(revokedWithoutTimestamp!.SqlState, Is.EqualTo(PostgresErrorCodes.CheckViolation));
            Assert.That(activeWithTimestamp!.SqlState, Is.EqualTo(PostgresErrorCodes.CheckViolation));
        }
    }

    [Test]
    public async Task TokenHashBackedTablesShouldRejectDuplicateHashes()
    {
        await using var connection = await GetDataSource().OpenConnectionAsync();
        var userId = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        await InsertUserAsync(connection, userId, "token-hash@example.com", null);

        await connection.ExecuteAsync(
            "INSERT INTO ashlar_sessions (id, user_id, token_hash, created_at, expires_at) VALUES (@id, @userId, 'same-token', @now, @expires)",
            new { id = Guid.NewGuid(), userId, now, expires = now.AddHours(1) });
        await connection.ExecuteAsync(
            "INSERT INTO ashlar_invitations (id, email, normalized_email, token_hash, created_at, expires_at, version) VALUES (@id, 'invite@example.com', 'invite@example.com', 'same-invite', @now, @expires, 'v1')",
            new { id = Guid.NewGuid(), now, expires = now.AddHours(1) });
        await connection.ExecuteAsync(
            "INSERT INTO ashlar_mfa_handshakes (id, user_id, token_hash, created_at, expires_at, required_factors, verified_factors) VALUES (@id, @userId, 'same-handshake', @now, @expires, '[]'::jsonb, '[]'::jsonb)",
            new { id = Guid.NewGuid(), userId, now, expires = now.AddHours(1) });

        var duplicateSession = Assert.ThrowsAsync<PostgresException>(async () =>
            await connection.ExecuteAsync(
                "INSERT INTO ashlar_sessions (id, user_id, token_hash, created_at, expires_at) VALUES (@id, @userId, 'same-token', @now, @expires)",
                new { id = Guid.NewGuid(), userId, now, expires = now.AddHours(1) }));
        var duplicateInvitation = Assert.ThrowsAsync<PostgresException>(async () =>
            await connection.ExecuteAsync(
                "INSERT INTO ashlar_invitations (id, email, normalized_email, token_hash, created_at, expires_at, version) VALUES (@id, 'other@example.com', 'other@example.com', 'same-invite', @now, @expires, 'v1')",
                new { id = Guid.NewGuid(), now, expires = now.AddHours(1) }));
        var duplicateHandshake = Assert.ThrowsAsync<PostgresException>(async () =>
            await connection.ExecuteAsync(
                "INSERT INTO ashlar_mfa_handshakes (id, user_id, token_hash, created_at, expires_at, required_factors, verified_factors) VALUES (@id, @userId, 'same-handshake', @now, @expires, '[]'::jsonb, '[]'::jsonb)",
                new { id = Guid.NewGuid(), userId, now, expires = now.AddHours(1) }));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(duplicateSession!.SqlState, Is.EqualTo(PostgresErrorCodes.UniqueViolation));
            Assert.That(duplicateInvitation!.SqlState, Is.EqualTo(PostgresErrorCodes.UniqueViolation));
            Assert.That(duplicateHandshake!.SqlState, Is.EqualTo(PostgresErrorCodes.UniqueViolation));
        }
    }

    [Test]
    public async Task TerminalStateConstraintsShouldRejectImpossibleInvitationHandshakeAndOutboxRows()
    {
        await using var connection = await GetDataSource().OpenConnectionAsync();
        var userId = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        await InsertUserAsync(connection, userId, "terminal-state@example.com", null);

        var invitationBothAcceptedAndRevoked = Assert.ThrowsAsync<PostgresException>(async () =>
            await connection.ExecuteAsync("""
                INSERT INTO ashlar_invitations (id, email, normalized_email, token_hash, created_at, expires_at, accepted_at, revoked_at, version)
                VALUES (@id, 'invite@example.com', 'invite@example.com', @token, @now, @expires, @now, @now, 'v1')
                """, new { id = Guid.NewGuid(), token = Guid.NewGuid().ToString("N"), now, expires = now.AddHours(1) }));
        var completedHandshakeWithoutTimestamp = Assert.ThrowsAsync<PostgresException>(async () =>
            await connection.ExecuteAsync("""
                INSERT INTO ashlar_mfa_handshakes (id, user_id, token_hash, created_at, expires_at, is_completed, required_factors, verified_factors)
                VALUES (@id, @userId, @token, @now, @expires, TRUE, '[]'::jsonb, '[]'::jsonb)
                """, new { id = Guid.NewGuid(), userId, token = Guid.NewGuid().ToString("N"), now, expires = now.AddHours(1) }));
        var outboxSentAndFailed = Assert.ThrowsAsync<PostgresException>(async () =>
            await connection.ExecuteAsync("""
                INSERT INTO ashlar_email_outbox (id, to_address, subject, text_body, created_at, available_at, sent_at, failed_at)
                VALUES (@id, 'to@example.com', 'Subject', 'Body', @now, @now, @now, @now)
                """, new { id = Guid.NewGuid(), now }));
        var outboxHalfLocked = Assert.ThrowsAsync<PostgresException>(async () =>
            await connection.ExecuteAsync("""
                INSERT INTO ashlar_email_outbox (id, to_address, subject, text_body, created_at, available_at, locked_until)
                VALUES (@id, 'to@example.com', 'Subject', 'Body', @now, @now, @lockedUntil)
                """, new { id = Guid.NewGuid(), now, lockedUntil = now.AddMinutes(5) }));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(invitationBothAcceptedAndRevoked!.SqlState, Is.EqualTo(PostgresErrorCodes.CheckViolation));
            Assert.That(completedHandshakeWithoutTimestamp!.SqlState, Is.EqualTo(PostgresErrorCodes.CheckViolation));
            Assert.That(outboxSentAndFailed!.SqlState, Is.EqualTo(PostgresErrorCodes.CheckViolation));
            Assert.That(outboxHalfLocked!.SqlState, Is.EqualTo(PostgresErrorCodes.CheckViolation));
        }
    }

    [Test]
    public async Task QuerySupportingIndexesShouldExist()
    {
        await using var connection = await GetDataSource().OpenConnectionAsync();
        var indexes = await connection.QueryAsync<string>("""
            SELECT indexname
            FROM pg_indexes
            WHERE schemaname = 'public'
              AND tablename LIKE 'ashlar_%'
            """);

        Assert.That(indexes, Is.SupersetOf(ExpectedQuerySupportingIndexes));
    }

    private static Task<int> InsertUserAsync(NpgsqlConnection connection, Guid id, string email, Guid? tenantId)
    {
        return connection.ExecuteAsync(
            "INSERT INTO ashlar_users (id, email, normalized_email, tenant_id, created_at) VALUES (@id, @email, lower(@email), @tenantId, @now)",
            new { id, email, tenantId, now = DateTimeOffset.UtcNow });
    }

    private static Task<int> InsertCredentialAsync(NpgsqlConnection connection, Guid userId, int status, DateTimeOffset? revokedAt)
    {
        return connection.ExecuteAsync("""
            INSERT INTO ashlar_credentials
                (id, user_id, provider_type, provider_name, provider_key, version, created_at, revoked_at, status)
            VALUES
                (@id, @userId, 'local', 'LOCAL', @providerKey, 'v1', @now, @revokedAt, @status)
            """, new { id = Guid.NewGuid(), userId, providerKey = Guid.NewGuid().ToString("N"), now = DateTimeOffset.UtcNow, revokedAt, status });
    }
}
