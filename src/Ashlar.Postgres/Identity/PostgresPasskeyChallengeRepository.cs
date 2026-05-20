using Dapper;

namespace Ashlar.Postgres.Identity;

/// <summary>
/// Provides PostgreSQL persistence for passkey challenges.
/// </summary>
/// <param name="connectionProvider">The connection provider value.</param>
public sealed class PostgresPasskeyChallengeRepository(IPostgresConnectionProvider connectionProvider) : IPasskeyChallengeRepository
{
    private readonly IPostgresConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));

    /// <summary>
    /// Stores a passkey challenge.
    /// </summary>
    /// <param name="challenge">The challenge to store.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    public async Task CreateAsync(PasskeyChallenge challenge, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(challenge);

        const string sql = """
            INSERT INTO ashlar_passkey_challenges
                (id, version, purpose, user_id, handshake_token_hash, factor_type, display_name, challenge, options_json, relying_party_id, origin, created_at, expires_at, consumed_at)
            VALUES
                (@Id, @Version, @Purpose, @UserId, @HandshakeTokenHash, @FactorType, @DisplayName, @Challenge, @OptionsJson::jsonb, @RelyingPartyId, @Origin, @CreatedAt, @ExpiresAt, @ConsumedAt)
            """;

        var connectionHandle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, challenge, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            await connectionHandle.Connection.ExecuteAsync(command);
        }
    }

    /// <summary>
    /// Gets a passkey challenge by id.
    /// </summary>
    /// <param name="id">The challenge id.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The challenge when found; otherwise, <see langword="null" />.</returns>
    public async Task<PasskeyChallenge?> GetAsync(Guid id, CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT id, version, purpose, user_id AS UserId, handshake_token_hash AS HandshakeTokenHash, factor_type AS FactorType, display_name AS DisplayName, challenge, options_json::text AS OptionsJson,
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

    /// <summary>
    /// Atomically consumes a passkey challenge.
    /// </summary>
    /// <param name="id">The challenge id.</param>
    /// <param name="expectedVersion">The expected version.</param>
    /// <param name="consumedAt">The advisory consumption timestamp. This repository uses the database clock for persisted consumption.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns><see langword="true" /> when the challenge was consumed.</returns>
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
