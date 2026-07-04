using Dapper;

namespace Ashlar.Postgres.Identity;

internal sealed class PostgresPasskeyChallengeRepository(IPostgresConnectionProvider connectionProvider) : IPasskeyChallengeRepository
{
    private readonly IPostgresConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));

    public async Task CreateAsync(PasskeyChallenge challenge, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(challenge);

        const string sql = """
            INSERT INTO ashlar_passkey_challenges
                (id, version, purpose, user_id, tenant_id, handshake_token_hash, factor_type, display_name, registration_proof_type, registration_proof_session_id, registration_proof_expires_at, challenge, options_json, relying_party_id, origin, created_at, expires_at, consumed_at)
            VALUES
                (@Id, @Version, @Purpose, @UserId, @TenantId, @HandshakeTokenHash, @FactorType, @DisplayName, @RegistrationProofType, @RegistrationProofSessionId, @RegistrationProofExpiresAt, @Challenge, @OptionsJson::jsonb, @RelyingPartyId, @Origin, @CreatedAt, @ExpiresAt, @ConsumedAt)
            """;

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, challenge, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            await connectionHandle.Connection.ExecuteAsync(command);
        }
    }

    public async Task<PasskeyChallenge?> GetAsync(Guid id, CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT id, version, purpose, user_id AS UserId, tenant_id AS TenantId, handshake_token_hash AS HandshakeTokenHash, factor_type AS FactorType, display_name AS DisplayName,
                   registration_proof_type AS RegistrationProofType, registration_proof_session_id AS RegistrationProofSessionId, registration_proof_expires_at AS RegistrationProofExpiresAt,
                   challenge, options_json::text AS OptionsJson,
                   relying_party_id AS RelyingPartyId, origin, created_at AS CreatedAt, expires_at AS ExpiresAt, consumed_at AS ConsumedAt
            FROM ashlar_passkey_challenges
            WHERE id = @Id
            """;

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, new { Id = id }, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            return await connectionHandle.Connection.QueryFirstOrDefaultAsync<PasskeyChallenge>(command);
        }
    }

    public async Task<bool> ConsumeAsync(Guid id, string expectedVersion, DateTimeOffset consumedAt, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedVersion);

        const string sql = """
            UPDATE ashlar_passkey_challenges
            SET consumed_at = clock_timestamp(), version = @NewVersion
            WHERE id = @Id AND version = @ExpectedVersion AND consumed_at IS NULL AND expires_at > clock_timestamp()
            """;

        var parameters = new { Id = id, ExpectedVersion = expectedVersion, NewVersion = Guid.NewGuid().ToString("N") };
        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, parameters, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            return await connectionHandle.Connection.ExecuteAsync(command) == 1;
        }
    }
}
