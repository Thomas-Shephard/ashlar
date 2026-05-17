using Ashlar.Operational;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Ashlar.Sqlite;

/// <summary>
/// Provides SQLite cleanup for Ashlar operational tables.
/// </summary>
public sealed partial class SqliteAshlarCleanupService : IAshlarCleanupService
{
    private const string CutoffParameter = "$cutoff";
    private const string LimitParameter = "$limit";

    private readonly ISqliteConnectionProvider _connectionProvider;
    private readonly TimeProvider _timeProvider;
    private readonly AshlarCleanupOptions _options;
    private readonly ILogger<SqliteAshlarCleanupService> _logger;

    /// <summary>
    /// Initializes a configured SQLite cleanup service.
    /// </summary>
    /// <param name="connectionProvider">The SQLite connection provider.</param>
    /// <param name="timeProvider">The time provider.</param>
    /// <param name="options">The cleanup options.</param>
    /// <param name="logger">The logger value.</param>
    public SqliteAshlarCleanupService(
        ISqliteConnectionProvider connectionProvider,
        TimeProvider timeProvider,
        IOptions<AshlarCleanupOptions> options,
        ILogger<SqliteAshlarCleanupService>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(connectionProvider);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(options);

        _connectionProvider = connectionProvider;
        _timeProvider = timeProvider;
        _options = options.Value;
        _logger = logger ?? NullLogger<SqliteAshlarCleanupService>.Instance;
        if (!AshlarCleanupOptions.Validate(_options))
        {
            throw new ArgumentException("Cleanup options are invalid.", nameof(options));
        }
    }

    public async Task<AshlarCleanupResult> CleanupAsync(CancellationToken cancellationToken = default)
    {
        var now = _timeProvider.GetUtcNow();
        var result = AshlarCleanupResult.Empty;
        var activeCategories = AshlarCleanupCategories.All;

        await using var handle = await _connectionProvider.GetConnectionAsync(cancellationToken);
        for (var batchNumber = 0; batchNumber < _options.MaxBatchesPerRun && activeCategories.HasAny; batchNumber++)
        {
            var batchResult = new AshlarCleanupResult(
                await DeleteIfActiveAsync(activeCategories.ExpiredSessions, handle, CleanupDeleteDefinitions.ExpiredSessions, Threshold(now, _options.RemoveExpiredSessionsAfter), cancellationToken),
                await DeleteIfActiveAsync(activeCategories.RevokedSessions, handle, CleanupDeleteDefinitions.RevokedSessions, Threshold(now, _options.RemoveRevokedSessionsAfter), cancellationToken),
                await DeleteIfActiveAsync(activeCategories.ExpiredCredentials, handle, CleanupDeleteDefinitions.ExpiredCredentials, Threshold(now, _options.RemoveExpiredCredentialsAfter), cancellationToken),
                await DeleteIfActiveAsync(activeCategories.RevokedCredentials, handle, CleanupDeleteDefinitions.RevokedCredentials, Threshold(now, _options.RemoveRevokedCredentialsAfter), cancellationToken),
                await DeleteIfActiveAsync(activeCategories.ExpiredInvitations, handle, CleanupDeleteDefinitions.ExpiredInvitations, Threshold(now, _options.RemoveExpiredInvitationsAfter), cancellationToken),
                await DeleteIfActiveAsync(activeCategories.AcceptedInvitations, handle, CleanupDeleteDefinitions.AcceptedInvitations, Threshold(now, _options.RemoveAcceptedInvitationsAfter), cancellationToken),
                await DeleteIfActiveAsync(activeCategories.RevokedInvitations, handle, CleanupDeleteDefinitions.RevokedInvitations, Threshold(now, _options.RemoveRevokedInvitationsAfter), cancellationToken),
                await DeleteIfActiveAsync(activeCategories.ExpiredHandshakes, handle, CleanupDeleteDefinitions.ExpiredHandshakes, Threshold(now, _options.RemoveExpiredHandshakesAfter), cancellationToken),
                await DeleteIfActiveAsync(activeCategories.CompletedHandshakes, handle, CleanupDeleteDefinitions.CompletedHandshakes, Threshold(now, _options.RemoveCompletedHandshakesAfter), cancellationToken),
                await DeleteIfActiveAsync(activeCategories.RevokedHandshakes, handle, CleanupDeleteDefinitions.RevokedHandshakes, Threshold(now, _options.RemoveRevokedHandshakesAfter), cancellationToken),
                await DeleteIfActiveAsync(activeCategories.ExpiredRateLimits, handle, CleanupDeleteDefinitions.ExpiredRateLimits, Threshold(now, _options.RemoveExpiredRateLimitsAfter), cancellationToken),
                await DeleteIfActiveAsync(activeCategories.AuditEvents, handle, CleanupDeleteDefinitions.AuditEvents, Threshold(now, _options.RemoveAuditEventsAfter), cancellationToken),
                await DeleteIfActiveAsync(activeCategories.SentEmails, handle, CleanupDeleteDefinitions.SentEmails, Threshold(now, _options.RemoveSentEmailsAfter), cancellationToken),
                await DeleteIfActiveAsync(activeCategories.FailedEmails, handle, CleanupDeleteDefinitions.FailedEmails, Threshold(now, _options.RemoveFailedEmailsAfter), cancellationToken),
                await DeleteIfActiveAsync(activeCategories.ExpiredAuthorizationGrants, handle, CleanupDeleteDefinitions.ExpiredAuthorizationGrants, Threshold(now, _options.RemoveExpiredAuthorizationGrantsAfter), cancellationToken),
                await DeleteIfActiveAsync(activeCategories.RevokedAuthorizationGrants, handle, CleanupDeleteDefinitions.RevokedAuthorizationGrants, Threshold(now, _options.RemoveRevokedAuthorizationGrantsAfter), cancellationToken),
                await DeleteIfActiveAsync(activeCategories.ExpiredPasskeyChallenges, handle, CleanupDeleteDefinitions.ExpiredPasskeyChallenges, Threshold(now, _options.RemoveExpiredPasskeyChallengesAfter), cancellationToken),
                await DeleteIfActiveAsync(activeCategories.ConsumedPasskeyChallenges, handle, CleanupDeleteDefinitions.ConsumedPasskeyChallenges, Threshold(now, _options.RemoveConsumedPasskeyChallengesAfter), cancellationToken));

            result = result.Add(batchResult);
            activeCategories = AshlarCleanupCategories.FromBatchResult(batchResult, _options.BatchSize);
        }

        return result;
    }

    private static DateTimeOffset? Threshold(DateTimeOffset now, TimeSpan? retention) => now - retention;

    private async Task<int> DeleteIfActiveAsync(
        bool isActive,
        SqliteConnectionHandle handle,
        CleanupDeleteDefinition definition,
        DateTimeOffset? cutoff,
        CancellationToken cancellationToken)
    {
        if (!isActive || cutoff == null)
        {
            return 0;
        }

        try
        {
            return await DeleteAsync(handle, definition, cutoff.Value, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogCleanupCategoryFailed(_logger, definition.Category, definition.TableName, ex);
            throw;
        }
    }

    private async Task<int> DeleteAsync(
        SqliteConnectionHandle handle,
        CleanupDeleteDefinition definition,
        DateTimeOffset cutoff,
        CancellationToken cancellationToken)
    {
        var sql = $"""
            DELETE FROM {definition.TableName}
            WHERE rowid IN (
                SELECT rowid
                FROM {definition.TableName}
                WHERE {definition.Predicate}
                ORDER BY {definition.OrderColumn}, rowid
                LIMIT $limit
            );
            """;

        await using var command = handle.Connection.CreateCommand();
        command.Transaction = handle.Transaction;
        command.CommandText = sql;
        command.AddDateTimeOffsetParameter(CutoffParameter, cutoff);
        command.AddParameter(LimitParameter, _options.BatchSize);
        return await command.ExecuteNonQueryAsync(cancellationToken);
    }

    [LoggerMessage(EventId = 1000, Level = LogLevel.Error, Message = "SQLite cleanup category failed. Category={Category} TableName={TableName}")]
    private static partial void LogCleanupCategoryFailed(ILogger logger, string category, string tableName, Exception exception);

    private sealed record CleanupDeleteDefinition(string Category, string TableName, string Predicate, string OrderColumn);

    private static class CleanupDeleteDefinitions
    {
        private const string SessionsTable = "ashlar_sessions";
        private const string CredentialsTable = "ashlar_credentials";
        private const string AuthorizationGrantsTable = "ashlar_authorization_grants";
        private const string InvitationsTable = "ashlar_invitations";
        private const string HandshakesTable = "ashlar_mfa_handshakes";
        private const string RateLimitsTable = "ashlar_rate_limits";
        private const string PasskeyChallengesTable = "ashlar_passkey_challenges";
        private const string SecurityEventsTable = "ashlar_security_events";
        private const string EmailOutboxTable = "ashlar_email_outbox";
        private const string ExpiresAtColumn = "expires_at";
        private const string RevokedAtColumn = "revoked_at";
        private const string RevokedBeforeCutoffPredicate = "revoked_at IS NOT NULL AND revoked_at < $cutoff";
        private const string AcceptedAtColumn = "accepted_at";
        private const string CompletedAtColumn = "completed_at";
        private const string OccurredAtColumn = "occurred_at";
        private const string ConsumedAtColumn = "consumed_at";
        private const string SentAtColumn = "sent_at";
        private const string FailedAtColumn = "failed_at";

        public static readonly CleanupDeleteDefinition ExpiredSessions = new("expired_sessions", SessionsTable, "expires_at < $cutoff AND revoked_at IS NULL", ExpiresAtColumn);
        public static readonly CleanupDeleteDefinition RevokedSessions = new("revoked_sessions", SessionsTable, RevokedBeforeCutoffPredicate, RevokedAtColumn);
        public static readonly CleanupDeleteDefinition ExpiredCredentials = new("expired_credentials", CredentialsTable, "expires_at IS NOT NULL AND expires_at < $cutoff AND revoked_at IS NULL", ExpiresAtColumn);
        public static readonly CleanupDeleteDefinition RevokedCredentials = new("revoked_credentials", CredentialsTable, RevokedBeforeCutoffPredicate, RevokedAtColumn);
        public static readonly CleanupDeleteDefinition ExpiredAuthorizationGrants = new("expired_authorization_grants", AuthorizationGrantsTable, "expires_at IS NOT NULL AND expires_at < $cutoff AND revoked_at IS NULL", ExpiresAtColumn);
        public static readonly CleanupDeleteDefinition RevokedAuthorizationGrants = new("revoked_authorization_grants", AuthorizationGrantsTable, RevokedBeforeCutoffPredicate, RevokedAtColumn);
        public static readonly CleanupDeleteDefinition ExpiredInvitations = new("expired_invitations", InvitationsTable, "expires_at < $cutoff AND accepted_at IS NULL AND revoked_at IS NULL", ExpiresAtColumn);
        public static readonly CleanupDeleteDefinition AcceptedInvitations = new("accepted_invitations", InvitationsTable, "accepted_at IS NOT NULL AND accepted_at < $cutoff", AcceptedAtColumn);
        public static readonly CleanupDeleteDefinition RevokedInvitations = new("revoked_invitations", InvitationsTable, RevokedBeforeCutoffPredicate, RevokedAtColumn);
        public static readonly CleanupDeleteDefinition ExpiredHandshakes = new("expired_handshakes", HandshakesTable, "expires_at < $cutoff AND is_revoked = 0 AND is_completed = 0", ExpiresAtColumn);
        public static readonly CleanupDeleteDefinition CompletedHandshakes = new("completed_handshakes", HandshakesTable, "is_completed = 1 AND completed_at IS NOT NULL AND completed_at < $cutoff", CompletedAtColumn);
        public static readonly CleanupDeleteDefinition RevokedHandshakes = new("revoked_handshakes", HandshakesTable, "is_revoked = 1 AND revoked_at IS NOT NULL AND revoked_at < $cutoff", RevokedAtColumn);
        public static readonly CleanupDeleteDefinition ExpiredRateLimits = new("expired_rate_limits", RateLimitsTable, "expires_at < $cutoff", ExpiresAtColumn);
        public static readonly CleanupDeleteDefinition ExpiredPasskeyChallenges = new("expired_passkey_challenges", PasskeyChallengesTable, "expires_at < $cutoff AND consumed_at IS NULL", ExpiresAtColumn);
        public static readonly CleanupDeleteDefinition ConsumedPasskeyChallenges = new("consumed_passkey_challenges", PasskeyChallengesTable, "consumed_at IS NOT NULL AND consumed_at < $cutoff", ConsumedAtColumn);
        public static readonly CleanupDeleteDefinition AuditEvents = new("audit_events", SecurityEventsTable, "occurred_at < $cutoff", OccurredAtColumn);
        public static readonly CleanupDeleteDefinition SentEmails = new("sent_emails", EmailOutboxTable, "sent_at IS NOT NULL AND sent_at < $cutoff", SentAtColumn);
        public static readonly CleanupDeleteDefinition FailedEmails = new("failed_emails", EmailOutboxTable, "failed_at IS NOT NULL AND failed_at < $cutoff", FailedAtColumn);
    }

    private sealed record AshlarCleanupCategories(
        bool ExpiredSessions,
        bool RevokedSessions,
        bool ExpiredCredentials,
        bool RevokedCredentials,
        bool ExpiredAuthorizationGrants,
        bool RevokedAuthorizationGrants,
        bool ExpiredInvitations,
        bool AcceptedInvitations,
        bool RevokedInvitations,
        bool ExpiredHandshakes,
        bool CompletedHandshakes,
        bool RevokedHandshakes,
        bool ExpiredRateLimits,
        bool AuditEvents,
        bool SentEmails,
        bool FailedEmails,
        bool ExpiredPasskeyChallenges,
        bool ConsumedPasskeyChallenges)
    {
        public static AshlarCleanupCategories All { get; } = new(true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true);

        public bool HasAny =>
            ExpiredSessions || RevokedSessions || ExpiredCredentials || RevokedCredentials ||
            ExpiredAuthorizationGrants || RevokedAuthorizationGrants || ExpiredInvitations ||
            AcceptedInvitations || RevokedInvitations || ExpiredHandshakes || CompletedHandshakes ||
            RevokedHandshakes || ExpiredRateLimits || AuditEvents || SentEmails || FailedEmails ||
            ExpiredPasskeyChallenges || ConsumedPasskeyChallenges;

        public static AshlarCleanupCategories FromBatchResult(AshlarCleanupResult result, int batchSize)
        {
            return new AshlarCleanupCategories(
                result.ExpiredSessions == batchSize,
                result.RevokedSessions == batchSize,
                result.ExpiredCredentials == batchSize,
                result.RevokedCredentials == batchSize,
                result.ExpiredAuthorizationGrants == batchSize,
                result.RevokedAuthorizationGrants == batchSize,
                result.ExpiredInvitations == batchSize,
                result.AcceptedInvitations == batchSize,
                result.RevokedInvitations == batchSize,
                result.ExpiredHandshakes == batchSize,
                result.CompletedHandshakes == batchSize,
                result.RevokedHandshakes == batchSize,
                result.ExpiredRateLimits == batchSize,
                result.AuditEvents == batchSize,
                result.SentEmails == batchSize,
                result.FailedEmails == batchSize,
                result.ExpiredPasskeyChallenges == batchSize,
                result.ConsumedPasskeyChallenges == batchSize);
        }
    }
}
