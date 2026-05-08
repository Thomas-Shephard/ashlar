using Ashlar.Operational;
using Dapper;
using Microsoft.Extensions.Options;
using Npgsql;

namespace Ashlar.Postgres;

public sealed class PostgresAshlarCleanupService : IAshlarCleanupService
{
    private readonly NpgsqlDataSource _dataSource;
    private readonly TimeProvider _timeProvider;
    private readonly AshlarCleanupOptions _options;

    public PostgresAshlarCleanupService(
        NpgsqlDataSource dataSource,
        TimeProvider timeProvider,
        IOptions<AshlarCleanupOptions> options)
    {
        ArgumentNullException.ThrowIfNull(dataSource);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(options);

        _dataSource = dataSource;
        _timeProvider = timeProvider;
        _options = options.Value;
        if (!AshlarCleanupOptions.Validate(_options))
        {
            throw new ArgumentException("Cleanup options are invalid.", nameof(options));
        }
    }

    public async Task<AshlarCleanupResult> CleanupAsync(CancellationToken cancellationToken = default)
    {
        var now = _timeProvider.GetUtcNow();
        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        var result = AshlarCleanupResult.Empty;
        var activeCategories = AshlarCleanupCategories.All;

        for (var batchNumber = 0; batchNumber < _options.MaxBatchesPerRun && activeCategories.HasAny; batchNumber++)
        {
            var batchResult = new AshlarCleanupResult(
                await DeleteIfActiveAsync(activeCategories.ExpiredSessions, connection, CleanupDeleteDefinitions.ExpiredSessions, Threshold(now, _options.RemoveExpiredSessionsAfter), cancellationToken),
                await DeleteIfActiveAsync(activeCategories.RevokedSessions, connection, CleanupDeleteDefinitions.RevokedSessions, Threshold(now, _options.RemoveRevokedSessionsAfter), cancellationToken),
                await DeleteIfActiveAsync(activeCategories.ExpiredCredentials, connection, CleanupDeleteDefinitions.ExpiredCredentials, Threshold(now, _options.RemoveExpiredCredentialsAfter), cancellationToken),
                await DeleteIfActiveAsync(activeCategories.RevokedCredentials, connection, CleanupDeleteDefinitions.RevokedCredentials, Threshold(now, _options.RemoveRevokedCredentialsAfter), cancellationToken),
                await DeleteIfActiveAsync(activeCategories.ExpiredInvitations, connection, CleanupDeleteDefinitions.ExpiredInvitations, Threshold(now, _options.RemoveExpiredInvitationsAfter), cancellationToken),
                await DeleteIfActiveAsync(activeCategories.AcceptedInvitations, connection, CleanupDeleteDefinitions.AcceptedInvitations, Threshold(now, _options.RemoveAcceptedInvitationsAfter), cancellationToken),
                await DeleteIfActiveAsync(activeCategories.RevokedInvitations, connection, CleanupDeleteDefinitions.RevokedInvitations, Threshold(now, _options.RemoveRevokedInvitationsAfter), cancellationToken),
                await DeleteIfActiveAsync(activeCategories.ExpiredHandshakes, connection, CleanupDeleteDefinitions.ExpiredHandshakes, Threshold(now, _options.RemoveExpiredHandshakesAfter), cancellationToken),
                await DeleteIfActiveAsync(activeCategories.CompletedHandshakes, connection, CleanupDeleteDefinitions.CompletedHandshakes, Threshold(now, _options.RemoveCompletedHandshakesAfter), cancellationToken),
                await DeleteIfActiveAsync(activeCategories.RevokedHandshakes, connection, CleanupDeleteDefinitions.RevokedHandshakes, Threshold(now, _options.RemoveRevokedHandshakesAfter), cancellationToken),
                await DeleteIfActiveAsync(activeCategories.ExpiredRateLimits, connection, CleanupDeleteDefinitions.ExpiredRateLimits, Threshold(now, _options.RemoveExpiredRateLimitsAfter), cancellationToken),
                await DeleteIfActiveAsync(activeCategories.AuditEvents, connection, CleanupDeleteDefinitions.AuditEvents, Threshold(now, _options.RemoveAuditEventsAfter), cancellationToken));

            result = result.Add(batchResult);
            activeCategories = AshlarCleanupCategories.FromBatchResult(batchResult, _options.BatchSize);
        }

        return result;
    }

    private static DateTimeOffset? Threshold(DateTimeOffset now, TimeSpan? retention) => now - retention;

    private Task<int> DeleteIfActiveAsync(
        bool isActive,
        NpgsqlConnection connection,
        CleanupDeleteDefinition definition,
        DateTimeOffset? cutoff,
        CancellationToken cancellationToken)
    {
        return isActive
            ? DeleteAsync(connection, definition, cutoff, cancellationToken)
            : Task.FromResult(0);
    }

    private async Task<int> DeleteAsync(
        NpgsqlConnection connection,
        CleanupDeleteDefinition definition,
        DateTimeOffset? cutoff,
        CancellationToken cancellationToken)
    {
        if (cutoff == null)
        {
            return 0;
        }

        var sql = $"""
            DELETE FROM {definition.TableName}
            WHERE ctid IN (
                SELECT ctid
                FROM {definition.TableName}
                WHERE {definition.Predicate}
                ORDER BY {definition.OrderColumn}, ctid
                FOR UPDATE SKIP LOCKED
                LIMIT @limit
            );
            """;

        var command = new CommandDefinition(sql, new { cutoff, limit = _options.BatchSize }, cancellationToken: cancellationToken);
        return await connection.ExecuteAsync(command);
    }

    private sealed record CleanupDeleteDefinition(string TableName, string Predicate, string OrderColumn);

    private static class CleanupDeleteDefinitions
    {
        private const string SessionsTable = "ashlar_sessions";
        private const string CredentialsTable = "ashlar_credentials";
        private const string InvitationsTable = "ashlar_invitations";
        private const string HandshakesTable = "ashlar_mfa_handshakes";
        private const string RateLimitsTable = "ashlar_rate_limits";
        private const string SecurityEventsTable = "ashlar_security_events";
        private const string ExpiresAtColumn = "expires_at";
        private const string RevokedAtColumn = "revoked_at";
        private const string AcceptedAtColumn = "accepted_at";
        private const string CompletedAtColumn = "completed_at";
        private const string OccurredAtColumn = "occurred_at";

        public static readonly CleanupDeleteDefinition ExpiredSessions = new(SessionsTable, "expires_at < @cutoff AND revoked_at IS NULL", ExpiresAtColumn);
        public static readonly CleanupDeleteDefinition RevokedSessions = new(SessionsTable, "revoked_at IS NOT NULL AND revoked_at < @cutoff", RevokedAtColumn);
        public static readonly CleanupDeleteDefinition ExpiredCredentials = new(CredentialsTable, "expires_at IS NOT NULL AND expires_at < @cutoff AND revoked_at IS NULL", ExpiresAtColumn);
        public static readonly CleanupDeleteDefinition RevokedCredentials = new(CredentialsTable, "revoked_at IS NOT NULL AND revoked_at < @cutoff", RevokedAtColumn);
        public static readonly CleanupDeleteDefinition ExpiredInvitations = new(InvitationsTable, "expires_at < @cutoff AND accepted_at IS NULL AND revoked_at IS NULL", ExpiresAtColumn);
        public static readonly CleanupDeleteDefinition AcceptedInvitations = new(InvitationsTable, "accepted_at IS NOT NULL AND accepted_at < @cutoff", AcceptedAtColumn);
        public static readonly CleanupDeleteDefinition RevokedInvitations = new(InvitationsTable, "revoked_at IS NOT NULL AND revoked_at < @cutoff", RevokedAtColumn);
        public static readonly CleanupDeleteDefinition ExpiredHandshakes = new(HandshakesTable, "expires_at < @cutoff AND is_revoked = FALSE AND is_completed = FALSE", ExpiresAtColumn);
        public static readonly CleanupDeleteDefinition CompletedHandshakes = new(HandshakesTable, "is_completed = TRUE AND completed_at IS NOT NULL AND completed_at < @cutoff", CompletedAtColumn);
        public static readonly CleanupDeleteDefinition RevokedHandshakes = new(HandshakesTable, "is_revoked = TRUE AND revoked_at IS NOT NULL AND revoked_at < @cutoff", RevokedAtColumn);
        public static readonly CleanupDeleteDefinition ExpiredRateLimits = new(RateLimitsTable, "expires_at < @cutoff", ExpiresAtColumn);
        public static readonly CleanupDeleteDefinition AuditEvents = new(SecurityEventsTable, "occurred_at < @cutoff", OccurredAtColumn);
    }

    private sealed record AshlarCleanupCategories(
        bool ExpiredSessions,
        bool RevokedSessions,
        bool ExpiredCredentials,
        bool RevokedCredentials,
        bool ExpiredInvitations,
        bool AcceptedInvitations,
        bool RevokedInvitations,
        bool ExpiredHandshakes,
        bool CompletedHandshakes,
        bool RevokedHandshakes,
        bool ExpiredRateLimits,
        bool AuditEvents)
    {
        public static AshlarCleanupCategories All { get; } = new(true, true, true, true, true, true, true, true, true, true, true, true);

        public bool HasAny =>
            ExpiredSessions
            || RevokedSessions
            || ExpiredCredentials
            || RevokedCredentials
            || ExpiredInvitations
            || AcceptedInvitations
            || RevokedInvitations
            || ExpiredHandshakes
            || CompletedHandshakes
            || RevokedHandshakes
            || ExpiredRateLimits
            || AuditEvents;

        public static AshlarCleanupCategories FromBatchResult(AshlarCleanupResult result, int batchSize)
        {
            return new AshlarCleanupCategories(
                result.ExpiredSessions == batchSize,
                result.RevokedSessions == batchSize,
                result.ExpiredCredentials == batchSize,
                result.RevokedCredentials == batchSize,
                result.ExpiredInvitations == batchSize,
                result.AcceptedInvitations == batchSize,
                result.RevokedInvitations == batchSize,
                result.ExpiredHandshakes == batchSize,
                result.CompletedHandshakes == batchSize,
                result.RevokedHandshakes == batchSize,
                result.ExpiredRateLimits == batchSize,
                result.AuditEvents == batchSize);
        }
    }
}
