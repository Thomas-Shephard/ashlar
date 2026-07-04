using Microsoft.Data.Sqlite;

namespace Ashlar.Sqlite.Identity;

internal sealed class SqlitePasskeyChallengeRepository(ISqliteConnectionProvider connectionProvider) : IPasskeyChallengeRepository
{
    private readonly ISqliteConnectionProvider _connectionProvider = connectionProvider ?? throw new ArgumentNullException(nameof(connectionProvider));

    public async Task CreateAsync(PasskeyChallenge challenge, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(challenge);

        const string sql = """
            INSERT INTO ashlar_passkey_challenges
                (id, version, purpose, user_id, tenant_id, handshake_token_hash, factor_type, display_name, registration_proof_type, registration_proof_session_id, registration_proof_expires_at, challenge, options_json, relying_party_id, origin, created_at, expires_at, consumed_at)
            VALUES
                ($id, $version, $purpose, $userId, $tenantId, $handshakeTokenHash, $factorType, $displayName, $registrationProofType, $registrationProofSessionId, $registrationProofExpiresAt, $challenge, $optionsJson, $relyingPartyId, $origin, $createdAt, $expiresAt, $consumedAt);
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        AddParameters(command, challenge);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<PasskeyChallenge?> GetAsync(Guid id, CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT id, version, purpose, user_id, tenant_id, handshake_token_hash, factor_type, display_name, registration_proof_type, registration_proof_session_id, registration_proof_expires_at, challenge, options_json,
                   relying_party_id, origin, created_at, expires_at, consumed_at
            FROM ashlar_passkey_challenges
            WHERE id = $id;
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddGuidParameter("$id", id);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadChallenge(reader) : null;
    }

    public async Task<bool> ConsumeAsync(Guid id, string expectedVersion, DateTimeOffset consumedAt, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedVersion);

        const string sql = """
            UPDATE ashlar_passkey_challenges
            SET consumed_at = $consumedAt,
                version = $newVersion
            WHERE id = $id
              AND version = $expectedVersion
              AND consumed_at IS NULL
              AND expires_at > $consumedAt;
            """;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddGuidParameter("$id", id);
        command.AddParameter("$expectedVersion", expectedVersion);
        command.AddDateTimeOffsetParameter("$consumedAt", consumedAt);
        command.AddParameter("$newVersion", Guid.NewGuid().ToString("N"));

        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    private static void AddParameters(SqliteCommand command, PasskeyChallenge challenge)
    {
        command.AddGuidParameter("$id", challenge.Id);
        command.AddParameter("$version", challenge.Version);
        command.AddParameter("$purpose", challenge.Purpose);
        command.AddNullableGuidParameter("$userId", challenge.UserId);
        command.AddNullableGuidParameter("$tenantId", challenge.TenantId);
        command.AddParameter("$handshakeTokenHash", challenge.HandshakeTokenHash);
        command.AddParameter("$factorType", challenge.FactorType);
        command.AddParameter("$displayName", challenge.DisplayName);
        command.AddParameter("$registrationProofType", challenge.RegistrationProofType);
        command.AddNullableGuidParameter("$registrationProofSessionId", challenge.RegistrationProofSessionId);
        command.AddNullableDateTimeOffsetParameter("$registrationProofExpiresAt", challenge.RegistrationProofExpiresAt);
        command.AddParameter("$challenge", challenge.Challenge);
        command.AddParameter("$optionsJson", challenge.OptionsJson);
        command.AddParameter("$relyingPartyId", challenge.RelyingPartyId);
        command.AddParameter("$origin", challenge.Origin);
        command.AddDateTimeOffsetParameter("$createdAt", challenge.CreatedAt);
        command.AddDateTimeOffsetParameter("$expiresAt", challenge.ExpiresAt);
        command.AddNullableDateTimeOffsetParameter("$consumedAt", challenge.ConsumedAt);
    }

    private static PasskeyChallenge ReadChallenge(SqliteDataReader reader)
    {
        return new PasskeyChallenge
        {
            Id = reader.GetGuidFromText("id"),
            Version = reader.GetString(reader.GetOrdinal("version")),
            Purpose = reader.GetString(reader.GetOrdinal("purpose")),
            UserId = reader.GetNullableGuidFromText("user_id"),
            TenantId = reader.GetNullableGuidFromText("tenant_id"),
            HandshakeTokenHash = reader.GetNullableString("handshake_token_hash"),
            FactorType = reader.GetNullableString("factor_type"),
            DisplayName = reader.GetNullableString("display_name"),
            RegistrationProofType = reader.GetNullableString("registration_proof_type"),
            RegistrationProofSessionId = reader.GetNullableGuidFromText("registration_proof_session_id"),
            RegistrationProofExpiresAt = reader.GetNullableDateTimeOffsetFromText("registration_proof_expires_at"),
            Challenge = reader.GetString(reader.GetOrdinal("challenge")),
            OptionsJson = reader.GetString(reader.GetOrdinal("options_json")),
            RelyingPartyId = reader.GetString(reader.GetOrdinal("relying_party_id")),
            Origin = reader.GetString(reader.GetOrdinal("origin")),
            CreatedAt = reader.GetDateTimeOffsetFromText("created_at"),
            ExpiresAt = reader.GetDateTimeOffsetFromText("expires_at"),
            ConsumedAt = reader.GetNullableDateTimeOffsetFromText("consumed_at")
        };
    }
}
