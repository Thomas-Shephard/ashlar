using Ashlar.Operational;
using Dapper;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Npgsql;

namespace Ashlar.Postgres;

/// <summary>
/// Provides postgres ashlar cleanup service behavior.
/// </summary>
public sealed class PostgresAshlarCleanupService : IAshlarCleanupService
{
    private static readonly Action<ILogger, string, string, Exception?> CleanupCategoryFailed =
        LoggerMessage.Define<string, string>(
            LogLevel.Error,
            new EventId(1000, nameof(CleanupCategoryFailed)),
            "PostgreSQL cleanup category failed. Category={Category} TableName={TableName}");

    private readonly NpgsqlDataSource _dataSource;
    private readonly TimeProvider _timeProvider;
    private readonly AshlarCleanupOptions _options;
    private readonly ILogger<PostgresAshlarCleanupService> _logger;

    /// <summary>
    /// Initializes a configured PostgreSQL cleanup service.
    /// </summary>
    /// <param name="dataSource">The PostgreSQL data source.</param>
    /// <param name="timeProvider">The time provider.</param>
    /// <param name="options">The cleanup options.</param>
    /// <param name="logger">The logger value.</param>
    public PostgresAshlarCleanupService(
        NpgsqlDataSource dataSource,
        TimeProvider timeProvider,
        IOptions<AshlarCleanupOptions> options,
        ILogger<PostgresAshlarCleanupService>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(dataSource);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(options);

        _dataSource = dataSource;
        _timeProvider = timeProvider;
        _options = options.Value;
        _logger = logger ?? NullLogger<PostgresAshlarCleanupService>.Instance;
        if (!AshlarCleanupOptions.Validate(_options))
        {
            throw new ArgumentException("Cleanup options are invalid.", nameof(options));
        }
    }

    /// <summary>
    /// Performs the cleanup <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
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
                await DeleteIfActiveAsync(activeCategories.AuditEvents, connection, CleanupDeleteDefinitions.AuditEvents, Threshold(now, _options.RemoveAuditEventsAfter), cancellationToken),
                await DeleteIfActiveAsync(activeCategories.SentEmails, connection, CleanupDeleteDefinitions.SentEmails, Threshold(now, _options.RemoveSentEmailsAfter), cancellationToken),
                await DeleteIfActiveAsync(activeCategories.FailedEmails, connection, CleanupDeleteDefinitions.FailedEmails, Threshold(now, _options.RemoveFailedEmailsAfter), cancellationToken),
                await DeleteIfActiveAsync(activeCategories.ExpiredAuthorizationGrants, connection, CleanupDeleteDefinitions.ExpiredAuthorizationGrants, Threshold(now, _options.RemoveExpiredAuthorizationGrantsAfter), cancellationToken),
                await DeleteIfActiveAsync(activeCategories.RevokedAuthorizationGrants, connection, CleanupDeleteDefinitions.RevokedAuthorizationGrants, Threshold(now, _options.RemoveRevokedAuthorizationGrantsAfter), cancellationToken));

            result = result.Add(batchResult);
            activeCategories = AshlarCleanupCategories.FromBatchResult(batchResult, _options.BatchSize);
        }

        return result;
    }

    private static DateTimeOffset? Threshold(DateTimeOffset now, TimeSpan? retention) => now - retention;

    private async Task<int> DeleteIfActiveAsync(
        bool isActive,
        NpgsqlConnection connection,
        CleanupDeleteDefinition definition,
        DateTimeOffset? cutoff,
        CancellationToken cancellationToken)
    {
        if (!isActive)
        {
            return 0;
        }

        try
        {
            return await DeleteAsync(connection, definition, cutoff, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            CleanupCategoryFailed(_logger, definition.Category, definition.TableName, ex);
            throw;
        }
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

    private sealed record CleanupDeleteDefinition(string Category, string TableName, string Predicate, string OrderColumn);

    private static class CleanupDeleteDefinitions
    {
        private const string SessionsTable = "ashlar_sessions";
        private const string CredentialsTable = "ashlar_credentials";
        private const string AuthorizationGrantsTable = "ashlar_authorization_grants";
        private const string InvitationsTable = "ashlar_invitations";
        private const string HandshakesTable = "ashlar_mfa_handshakes";
        private const string RateLimitsTable = "ashlar_rate_limits";
        private const string SecurityEventsTable = "ashlar_security_events";
        private const string EmailOutboxTable = "ashlar_email_outbox";
        private const string ExpiresAtColumn = "expires_at";
        private const string RevokedAtColumn = "revoked_at";
        private const string RevokedBeforeCutoffPredicate = "revoked_at IS NOT NULL AND revoked_at < @cutoff";
        private const string AcceptedAtColumn = "accepted_at";
        private const string CompletedAtColumn = "completed_at";
        private const string OccurredAtColumn = "occurred_at";

        /// <summary>
        /// Performs the new operation and returns the result.
        /// </summary>
        /// <param name="SessionsTable">The sessions table value.</param>
        /// <param name="ExpiresAtColumn">The expires at column value.</param>
        /// <returns>The operation result.</returns>
        public static readonly CleanupDeleteDefinition ExpiredSessions = new("expired_sessions", SessionsTable, "expires_at < @cutoff AND revoked_at IS NULL", ExpiresAtColumn);
        /// <summary>
        /// Performs the new operation and returns the result.
        /// </summary>
        /// <param name="SessionsTable">The sessions table value.</param>
        /// <param name="RevokedBeforeCutoffPredicate">The revoked before cutoff predicate value.</param>
        /// <param name="RevokedAtColumn">The revoked at column value.</param>
        /// <returns>The operation result.</returns>
        public static readonly CleanupDeleteDefinition RevokedSessions = new("revoked_sessions", SessionsTable, RevokedBeforeCutoffPredicate, RevokedAtColumn);
        /// <summary>
        /// Performs the new operation and returns the result.
        /// </summary>
        /// <param name="CredentialsTable">The credentials table value.</param>
        /// <param name="ExpiresAtColumn">The expires at column value.</param>
        /// <returns>The operation result.</returns>
        public static readonly CleanupDeleteDefinition ExpiredCredentials = new("expired_credentials", CredentialsTable, "expires_at IS NOT NULL AND expires_at < @cutoff AND revoked_at IS NULL", ExpiresAtColumn);
        /// <summary>
        /// Performs the new operation and returns the result.
        /// </summary>
        /// <param name="CredentialsTable">The credentials table value.</param>
        /// <param name="RevokedBeforeCutoffPredicate">The revoked before cutoff predicate value.</param>
        /// <param name="RevokedAtColumn">The revoked at column value.</param>
        /// <returns>The operation result.</returns>
        public static readonly CleanupDeleteDefinition RevokedCredentials = new("revoked_credentials", CredentialsTable, RevokedBeforeCutoffPredicate, RevokedAtColumn);
        /// <summary>
        /// Performs the new operation and returns the result.
        /// </summary>
        /// <param name="AuthorizationGrantsTable">The authorization grants table value.</param>
        /// <param name="ExpiresAtColumn">The expires at column value.</param>
        /// <returns>The operation result.</returns>
        public static readonly CleanupDeleteDefinition ExpiredAuthorizationGrants = new("expired_authorization_grants", AuthorizationGrantsTable, "expires_at IS NOT NULL AND expires_at < @cutoff AND revoked_at IS NULL", ExpiresAtColumn);
        /// <summary>
        /// Performs the new operation and returns the result.
        /// </summary>
        /// <param name="AuthorizationGrantsTable">The authorization grants table value.</param>
        /// <param name="RevokedBeforeCutoffPredicate">The revoked before cutoff predicate value.</param>
        /// <param name="RevokedAtColumn">The revoked at column value.</param>
        /// <returns>The operation result.</returns>
        public static readonly CleanupDeleteDefinition RevokedAuthorizationGrants = new("revoked_authorization_grants", AuthorizationGrantsTable, RevokedBeforeCutoffPredicate, RevokedAtColumn);
        /// <summary>
        /// Performs the new operation and returns the result.
        /// </summary>
        /// <param name="InvitationsTable">The invitations table value.</param>
        /// <param name="ExpiresAtColumn">The expires at column value.</param>
        /// <returns>The operation result.</returns>
        public static readonly CleanupDeleteDefinition ExpiredInvitations = new("expired_invitations", InvitationsTable, "expires_at < @cutoff AND accepted_at IS NULL AND revoked_at IS NULL", ExpiresAtColumn);
        /// <summary>
        /// Performs the new operation and returns the result.
        /// </summary>
        /// <param name="InvitationsTable">The invitations table value.</param>
        /// <param name="AcceptedAtColumn">The accepted at column value.</param>
        /// <returns>The operation result.</returns>
        public static readonly CleanupDeleteDefinition AcceptedInvitations = new("accepted_invitations", InvitationsTable, "accepted_at IS NOT NULL AND accepted_at < @cutoff", AcceptedAtColumn);
        /// <summary>
        /// Performs the new operation and returns the result.
        /// </summary>
        /// <param name="InvitationsTable">The invitations table value.</param>
        /// <param name="RevokedBeforeCutoffPredicate">The revoked before cutoff predicate value.</param>
        /// <param name="RevokedAtColumn">The revoked at column value.</param>
        /// <returns>The operation result.</returns>
        public static readonly CleanupDeleteDefinition RevokedInvitations = new("revoked_invitations", InvitationsTable, RevokedBeforeCutoffPredicate, RevokedAtColumn);
        /// <summary>
        /// Performs the new operation and returns the result.
        /// </summary>
        /// <param name="HandshakesTable">The handshakes table value.</param>
        /// <param name="is_revoked">The is revoked value.</param>
        /// <returns>The operation result.</returns>
        public static readonly CleanupDeleteDefinition ExpiredHandshakes = new("expired_handshakes", HandshakesTable, "expires_at < @cutoff AND is_revoked = FALSE AND is_completed = FALSE", ExpiresAtColumn);
        /// <summary>
        /// Performs the new operation and returns the result.
        /// </summary>
        /// <param name="HandshakesTable">The handshakes table value.</param>
        /// <returns>The operation result.</returns>
        public static readonly CleanupDeleteDefinition CompletedHandshakes = new("completed_handshakes", HandshakesTable, "is_completed = TRUE AND completed_at IS NOT NULL AND completed_at < @cutoff", CompletedAtColumn);
        /// <summary>
        /// Performs the new operation and returns the result.
        /// </summary>
        /// <param name="HandshakesTable">The handshakes table value.</param>
        /// <returns>The operation result.</returns>
        public static readonly CleanupDeleteDefinition RevokedHandshakes = new("revoked_handshakes", HandshakesTable, "is_revoked = TRUE AND revoked_at IS NOT NULL AND revoked_at < @cutoff", RevokedAtColumn);
        /// <summary>
        /// Performs the new operation and returns the result.
        /// </summary>
        /// <param name="RateLimitsTable">The rate limits table value.</param>
        /// <param name="ExpiresAtColumn">The expires at column value.</param>
        /// <returns>The operation result.</returns>
        public static readonly CleanupDeleteDefinition ExpiredRateLimits = new("expired_rate_limits", RateLimitsTable, "expires_at < @cutoff", ExpiresAtColumn);
        /// <summary>
        /// Performs the new operation and returns the result.
        /// </summary>
        /// <param name="SecurityEventsTable">The security events table value.</param>
        /// <param name="OccurredAtColumn">The occurred at column value.</param>
        /// <returns>The operation result.</returns>
        public static readonly CleanupDeleteDefinition AuditEvents = new("audit_events", SecurityEventsTable, "occurred_at < @cutoff", OccurredAtColumn);
        /// <summary>
        /// Performs the new operation and returns the result.
        /// </summary>
        /// <param name="EmailOutboxTable">The email outbox table value.</param>
        /// <returns>The operation result.</returns>
        public static readonly CleanupDeleteDefinition SentEmails = new("sent_emails", EmailOutboxTable, "sent_at IS NOT NULL AND sent_at < @cutoff", "sent_at");
        /// <summary>
        /// Performs the new operation and returns the result.
        /// </summary>
        /// <param name="EmailOutboxTable">The email outbox table value.</param>
        /// <returns>The operation result.</returns>
        public static readonly CleanupDeleteDefinition FailedEmails = new("failed_emails", EmailOutboxTable, "failed_at IS NOT NULL AND failed_at < @cutoff", "failed_at");
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
        bool FailedEmails)
    {
        /// <summary>
        /// Executes the new operation.
        /// </summary>
        public static AshlarCleanupCategories All { get; } = new(true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true);

        /// <summary>
        /// Gets or sets the has any value.
        /// </summary>
        public bool HasAny =>
            ExpiredSessions
            || RevokedSessions
            || ExpiredCredentials
            || RevokedCredentials
            || ExpiredAuthorizationGrants
            || RevokedAuthorizationGrants
            || ExpiredInvitations
            || AcceptedInvitations
            || RevokedInvitations
            || ExpiredHandshakes
            || CompletedHandshakes
            || RevokedHandshakes
            || ExpiredRateLimits
            || AuditEvents
            || SentEmails
            || FailedEmails;

        /// <summary>
        /// Performs the from batch result operation and returns the result.
        /// </summary>
        /// <param name="result">The converted result value.</param>
        /// <param name="batchSize">The batch size value.</param>
        /// <returns>The operation result.</returns>
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
                result.FailedEmails == batchSize);
        }
    }
}
